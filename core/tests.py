import json
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from core.models import APIToken, Project, CodeFile, FileRevision, ActivityLog

User = get_user_model()


class CwayProModelsTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='dev@cwaypro.test', password='testpassword123')

    def test_api_token_generation_and_masking(self):
        key = APIToken.generate_key()
        self.assertTrue(key.startswith('cwp_live_'))
        token = APIToken.objects.create(user=self.user, name='My CLI', key=key)
        self.assertIn('...', token.masked_key)
        self.assertEqual(token.masked_key[:8], key[:8])

    def test_project_slug_auto_generation(self):
        proj = Project.objects.create(owner=self.user, name='Awesome Backend Service')
        self.assertEqual(proj.slug, 'awesome-backend-service')

    def test_code_file_language_detection_and_lines(self):
        proj = Project.objects.create(owner=self.user, name='test-repo')
        code_file = CodeFile.objects.create(
            project=proj,
            file_path='src/services/auth.py',
            content='import os\n\ndef login():\n    return True\n'
        )
        self.assertEqual(code_file.filename, 'auth.py')
        self.assertEqual(code_file.language, 'python')
        self.assertEqual(code_file.line_count, 4)
        self.assertGreater(code_file.file_size_bytes, 0)


class CLISyncEndpointTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(email='cli_dev@cwaypro.test', password='password123')
        self.raw_key = APIToken.generate_key()
        self.token = APIToken.objects.create(user=self.user, name='Laptop CLI', key=self.raw_key)
        self.sync_url = reverse('cli_sync')

    def test_unauthorized_without_token(self):
        res = self.client.post(self.sync_url, data={'file_path': 'test.py'}, content_type='application/json')
        self.assertEqual(res.status_code, 401)
        data = res.json()
        self.assertEqual(data['status'], 'error')

    def test_unauthorized_with_invalid_token(self):
        res = self.client.post(
            self.sync_url,
            data={'file_path': 'test.py'},
            content_type='application/json',
            HTTP_AUTHORIZATION='Bearer cwp_live_invalidkey12345'
        )
        self.assertEqual(res.status_code, 401)

    def test_successful_cli_push_new_file(self):
        payload = {
            'project': 'cli-sync-demo',
            'file_path': 'src/app.py',
            'content': 'print("Hello from CwayPro CLI")\n',
            'flags': {'new_file': True, 'branch': 'main'}
        }
        res = self.client.post(
            self.sync_url,
            data=json.dumps(payload),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self.raw_key}'
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['project'], 'cli-sync-demo')
        self.assertEqual(data['file_path'], 'src/app.py')
        self.assertEqual(data['version'], 1)
        self.assertTrue(data['is_new_file'])

        # Verify DB records
        project = Project.objects.get(owner=self.user, name='cli-sync-demo')
        code_file = CodeFile.objects.get(project=project, file_path='src/app.py')
        self.assertEqual(code_file.language, 'python')
        self.assertTrue(code_file.is_new_file)

        # Verify Activity Log
        log = ActivityLog.objects.filter(user=self.user, project=project).first()
        self.assertIsNotNone(log)
        self.assertEqual(log.action_type, 'FILE_CREATE')

    def test_successful_cli_file_update_and_revision(self):
        # Initial push
        payload_v1 = {
            'project': 'cli-repo',
            'file_path': 'config.js',
            'content': 'module.exports = { port: 3000 };',
            'flags': ['--new-file']
        }
        self.client.post(
            self.sync_url,
            data=json.dumps(payload_v1),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self.raw_key}'
        )

        # Second push (update)
        payload_v2 = {
            'project': 'cli-repo',
            'file_path': 'config.js',
            'content': 'module.exports = { port: 8080, env: "prod" };',
            'flags': {'branch': 'develop'}
        }
        res_v2 = self.client.post(
            self.sync_url,
            data=json.dumps(payload_v2),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self.raw_key}'
        )
        self.assertEqual(res_v2.status_code, 200)
        data_v2 = res_v2.json()
        self.assertEqual(data_v2['version'], 2)

        code_file = CodeFile.objects.get(project__name='cli-repo', file_path='config.js')
        self.assertEqual(code_file.version, 2)
        self.assertIn('8080', code_file.content)

        # Check revision was saved
        revisions = FileRevision.objects.filter(code_file=code_file)
        self.assertEqual(revisions.count(), 1)
        self.assertEqual(revisions.first().version, 1)
        self.assertIn('3000', revisions.first().content)


class CwayProViewsTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(email='web_dev@cwaypro.test', password='password123')
        self.client.force_login(self.user)
        self.project = Project.objects.create(owner=self.user, name='Web Workspace')
        self.code_file = CodeFile.objects.create(
            project=self.project,
            file_path='lib/utils.py',
            content='def helper(): pass'
        )

    def test_dashboard_view_authenticated(self):
        res = self.client.get(reverse('dashboard'))
        self.assertEqual(res.status_code, 200)
        self.assertTemplateUsed(res, 'core/dashboard.html')
        self.assertContains(res, 'Developer Workspace')
        self.assertContains(res, 'Web Workspace')
        self.assertContains(res, 'lib/utils.py')

    def test_project_detail_view(self):
        res = self.client.get(reverse('project_detail', kwargs={'project_slug': self.project.slug}))
        self.assertEqual(res.status_code, 200)
        self.assertTemplateUsed(res, 'core/project_detail.html')
        self.assertContains(res, 'Web Workspace')
        self.assertContains(res, 'utils.py')

    def test_file_detail_view(self):
        res = self.client.get(reverse('file_detail', kwargs={'project_slug': self.project.slug, 'file_id': self.code_file.id}))
        self.assertEqual(res.status_code, 200)
        self.assertTemplateUsed(res, 'core/file_detail.html')
        self.assertContains(res, 'lib/utils.py')
        self.assertContains(res, 'def helper(): pass')

    def test_activity_history_view(self):
        ActivityLog.objects.create(
            user=self.user,
            project=self.project,
            action_type='CLI_SYNC',
            description='Test event'
        )
        res = self.client.get(reverse('activity_history'))
        self.assertEqual(res.status_code, 200)
        self.assertTemplateUsed(res, 'core/history.html')
        self.assertContains(res, 'Test event')

    def test_tokens_view_and_generation(self):
        # GET tokens page
        res = self.client.get(reverse('tokens'))
        self.assertEqual(res.status_code, 200)
        self.assertTemplateUsed(res, 'core/tokens.html')

        # POST new token
        post_res = self.client.post(reverse('tokens'), {'name': 'Dev Machine'})
        self.assertEqual(post_res.status_code, 200)
        self.assertEqual(APIToken.objects.filter(user=self.user, name='Dev Machine').count(), 1)

    def test_unauthenticated_redirect(self):
        self.client.logout()
        res = self.client.get(reverse('dashboard'))
        self.assertEqual(res.status_code, 302)
        self.assertIn('/accounts/login/', res.url)


class SecurityTranslationTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(email='security_dev@cwaypro.test', password='password123')
        self.raw_key = APIToken.generate_key()
        self.token = APIToken.objects.create(user=self.user, name='Sec CLI', key=self.raw_key)
        self.sync_url = reverse('cli_sync')

    def test_crypto_engine_round_trip(self):
        from core.security_translator import CryptoEngine
        original = "SUPER_SECRET_PAYLOAD_12345"
        encrypted = CryptoEngine.encrypt(original)
        self.assertNotEqual(original, encrypted)
        decrypted = CryptoEngine.decrypt(encrypted)
        self.assertEqual(original, decrypted)

    def test_secret_scanner_detection_and_masking(self):
        from core.security_translator import SecretScanner
        sample_code = (
            "AWS_KEY = 'AKIA1234567890ABCDEF'\n"
            "DB = 'postgres://user:super_pass_123@localhost:5432/cway'\n"
            "SAFE_VAR = 'normal_value'\n"
        )
        scan = SecretScanner.scan(sample_code)
        self.assertTrue(scan['has_secrets'])
        self.assertGreaterEqual(scan['count'], 2)

        masked_text, secret_lines = SecretScanner.mask_text(sample_code)
        self.assertIn('AKIA************CDEF [REDACTED_AWS_KEY]', masked_text)
        self.assertIn('••••••••••••@', masked_text)
        self.assertNotIn('super_pass_123', masked_text)
        self.assertEqual(secret_lines, [1, 2])

    def test_cli_push_with_encrypt_flag(self):
        from core.models import SecurityAuditLog
        payload = {
            'project': 'vault-project',
            'file_path': 'secrets.py',
            'content': 'DATABASE_PASSWORD = "production_super_secret_password_here"',
            'flags': {'encrypt': True, 'new_file': True}
        }
        res = self.client.post(
            self.sync_url,
            data=json.dumps(payload),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self.raw_key}'
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data['is_encrypted'])

        # Verify DB content is encrypted ciphertext (not cleartext)
        code_file = CodeFile.objects.get(project__name='vault-project', file_path='secrets.py')
        self.assertTrue(code_file.is_encrypted)
        self.assertNotIn('production_super_secret_password_here', code_file.content)

        # Verify audit log was created
        audit = SecurityAuditLog.objects.filter(user=self.user, code_file=code_file, event_type='ENCRYPTED_PUSH').first()
        self.assertIsNotNone(audit)

    def test_outbound_translation_secret_masking_and_reveal_toggle(self):
        from core.models import SecurityAuditLog
        self.client.force_login(self.user)
        project = Project.objects.create(owner=self.user, name='frontend-sec')
        code_file = CodeFile.objects.create(
            project=project,
            file_path='.env.local',
            content='AWS_ACCESS_KEY_ID = "AKIAABCDEFGHIJKLMNOP"\nSECRET_KEY = "cwp_live_9f831234567890123456789012345678"',
            is_encrypted=False,
            security_scan={'has_secrets': True, 'count': 2}
        )

        file_url = reverse('file_detail', kwargs={'project_slug': project.slug, 'file_id': code_file.id})

        # Default GET: secrets must be masked
        res_masked = self.client.get(file_url)
        self.assertEqual(res_masked.status_code, 200)
        self.assertContains(res_masked, '[REDACTED_AWS_KEY]')
        self.assertContains(res_masked, 'Reveal Secrets')
        self.assertNotContains(res_masked, 'AKIAABCDEFGHIJKLMNOP')

        # GET with ?reveal=1: secrets are unmasked
        res_revealed = self.client.get(f"{file_url}?reveal=1")
        self.assertEqual(res_revealed.status_code, 200)
        self.assertContains(res_revealed, 'AKIAABCDEFGHIJKLMNOP')
        self.assertContains(res_revealed, 'Mask Secrets')

        # Check SECRETS_REVEALED log was registered
        reveal_log = SecurityAuditLog.objects.filter(user=self.user, code_file=code_file, event_type='SECRETS_REVEALED').first()
        self.assertIsNotNone(reveal_log)

