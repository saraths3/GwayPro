import os
import secrets
from django.db import models
from django.conf import settings
from django.utils.text import slugify


class APIToken(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='api_tokens'
    )
    name = models.CharField(max_length=128, help_text="e.g. Workstation CLI, Laptop")
    key = models.CharField(max_length=64, unique=True, db_index=True)
    is_active = models.BooleanField(default=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'API Token'
        verbose_name_plural = 'API Tokens'

    @classmethod
    def generate_key(cls):
        return f"cwp_live_{secrets.token_hex(20)}"

    @property
    def masked_key(self):
        if len(self.key) > 16:
            return f"{self.key[:12]}...{self.key[-4:]}"
        return self.key

    def __str__(self):
        return f"{self.name} ({self.masked_key})"


class Project(models.Model):
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='projects'
    )
    name = models.CharField(max_length=128)
    slug = models.SlugField(max_length=140)
    description = models.TextField(blank=True)
    is_private = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('owner', 'slug')
        ordering = ['-updated_at']

    def save(self, *args, **kwargs):
        if not self.slug:
            base_slug = slugify(self.name) or "project"
            slug = base_slug
            counter = 1
            while Project.objects.filter(owner=self.owner, slug=slug).exclude(pk=self.pk).exists():
                slug = f"{base_slug}-{counter}"
                counter += 1
            self.slug = slug
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.owner.email}/{self.name}"


class CodeFile(models.Model):
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name='files'
    )
    file_path = models.CharField(max_length=512, help_text="Relative file path e.g. src/main.py")
    filename = models.CharField(max_length=255, blank=True)
    content = models.TextField()
    language = models.CharField(max_length=64, blank=True)
    file_size_bytes = models.BigIntegerField(default=0)
    is_new_file = models.BooleanField(default=False)
    is_encrypted = models.BooleanField(default=False)
    encryption_algorithm = models.CharField(max_length=32, default="AES-128-CBC-HMAC")
    security_scan = models.JSONField(default=dict, blank=True)
    terminal_flags = models.JSONField(default=dict, blank=True)
    version = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('project', 'file_path')
        ordering = ['-updated_at']

    @staticmethod
    def detect_language(path):
        ext = os.path.splitext(path)[1].lower()
        mapping = {
            '.py': 'python',
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            '.html': 'html',
            '.css': 'css',
            '.json': 'json',
            '.md': 'markdown',
            '.rs': 'rust',
            '.go': 'go',
            '.java': 'java',
            '.c': 'c',
            '.cpp': 'cpp',
            '.h': 'c',
            '.sh': 'bash',
            '.bash': 'bash',
            '.zsh': 'bash',
            '.sql': 'sql',
            '.yaml': 'yaml',
            '.yml': 'yaml',
            '.toml': 'toml',
            '.rb': 'ruby',
            '.php': 'php',
            '.dart': 'dart',
        }
        return mapping.get(ext, 'text')

    def save(self, *args, **kwargs):
        if not self.filename:
            self.filename = os.path.basename(self.file_path) or self.file_path
        if not self.language:
            self.language = self.detect_language(self.file_path)
        if self.content is not None:
            self.file_size_bytes = len(self.content.encode('utf-8'))
        super().save(*args, **kwargs)

    @property
    def line_count(self):
        if not self.content:
            return 0
        return len(self.content.splitlines())

    def __str__(self):
        enc_badge = " [Encrypted]" if self.is_encrypted else ""
        return f"{self.project.name}:{self.file_path} (v{self.version}){enc_badge}"


class FileRevision(models.Model):
    code_file = models.ForeignKey(
        CodeFile,
        on_delete=models.CASCADE,
        related_name='revisions'
    )
    content = models.TextField()
    is_encrypted = models.BooleanField(default=False)
    security_scan = models.JSONField(default=dict, blank=True)
    terminal_flags = models.JSONField(default=dict, blank=True)
    version = models.PositiveIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-version']

    @property
    def line_count(self):
        if not self.content:
            return 0
        return len(self.content.splitlines())

    def __str__(self):
        return f"{self.code_file.file_path} - v{self.version}"


class ActivityLog(models.Model):
    ACTION_CHOICES = [
        ('CLI_SYNC', 'CLI File Sync'),
        ('FILE_CREATE', 'File Created'),
        ('FILE_UPDATE', 'File Updated'),
        ('PROJECT_CREATE', 'Project Created'),
        ('TOKEN_CREATE', 'API Token Created'),
        ('TOKEN_REVOKE', 'API Token Revoked'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='activity_logs'
    )
    project = models.ForeignKey(
        Project,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='activity_logs'
    )
    action_type = models.CharField(max_length=50, choices=ACTION_CHOICES, default='CLI_SYNC')
    description = models.CharField(max_length=255)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.action_type}] {self.description} ({self.created_at:%Y-%m-%d %H:%M})"


class SecurityAuditLog(models.Model):
    EVENT_CHOICES = [
        ('ENCRYPTED_PUSH', 'Encrypted Payload Synced'),
        ('SECRETS_DETECTED', 'Secrets Detected in Payload'),
        ('SECRETS_MASKED', 'Secrets Redacted for Frontend'),
        ('SECRETS_REVEALED', 'Secrets Unmasked by Owner'),
        ('DECRYPTION_FAILED', 'Decryption Failed'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='security_logs'
    )
    code_file = models.ForeignKey(
        CodeFile,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='security_logs'
    )
    event_type = models.CharField(max_length=50, choices=EVENT_CHOICES)
    details = models.CharField(max_length=255)
    metadata = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Security Audit Log'
        verbose_name_plural = 'Security Audit Logs'

    def __str__(self):
        return f"[{self.event_type}] {self.details} ({self.created_at:%Y-%m-%d %H:%M})"
