import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.http import JsonResponse, HttpResponseBadRequest
from django.urls import reverse
from django.utils import timezone
from django.contrib import messages
from .models import APIToken, Project, CodeFile, FileRevision, ActivityLog, SecurityAuditLog
from .forms import APITokenCreateForm, ProjectCreateForm, CLISyncPayloadForm
from .security_translator import SecurityTranslationLayer, CryptoEngine, SecretScanner


@login_required
def dashboard(request):
    """
    Main developer workspace dashboard:
    Renders high-level stats, active projects, recently updated files, and recent sync activity.
    """
    user_projects = Project.objects.filter(owner=request.user)
    recent_files = CodeFile.objects.filter(project__owner=request.user).select_related('project')[:8]
    recent_activities = ActivityLog.objects.filter(user=request.user).select_related('project')[:8]
    
    total_projects = user_projects.count()
    total_files = CodeFile.objects.filter(project__owner=request.user).count()
    total_syncs = ActivityLog.objects.filter(
        user=request.user,
        action_type__in=['CLI_SYNC', 'FILE_CREATE', 'FILE_UPDATE']
    ).count()
    active_tokens = APIToken.objects.filter(user=request.user, is_active=True).count()
    encrypted_files = CodeFile.objects.filter(project__owner=request.user, is_encrypted=True).count()

    context = {
        'projects': user_projects,
        'recent_files': recent_files,
        'recent_activities': recent_activities,
        'stats': {
            'total_projects': total_projects,
            'total_files': total_files,
            'total_syncs': total_syncs,
            'active_tokens': active_tokens,
            'encrypted_files': encrypted_files,
        },
        'project_form': ProjectCreateForm(),
    }
    return render(request, 'core/dashboard.html', context)


@login_required
def project_detail(request, project_slug):
    """
    Project / Repository view: lists all tracked files, recent activity, and repository stats.
    """
    project = get_object_or_404(Project, owner=request.user, slug=project_slug)
    files = project.files.all().order_by('file_path')
    project_activities = ActivityLog.objects.filter(project=project)[:15]

    context = {
        'project': project,
        'files': files,
        'activities': project_activities,
        'file_count': files.count(),
    }
    return render(request, 'core/project_detail.html', context)


@login_required
def file_detail(request, project_slug, file_id):
    """
    File inspection view: displays code content translated through the security layer,
    with masked secrets, line-by-line inspection, lock indicators, and authorized reveal toggles.
    """
    project = get_object_or_404(Project, owner=request.user, slug=project_slug)
    code_file = get_object_or_404(CodeFile, id=file_id, project=project)
    revisions = code_file.revisions.all()

    # Check if developer requested to unmask/reveal secrets
    reveal_secrets = request.GET.get('reveal') == '1'

    # Translate through Security Gateway
    view_dto = SecurityTranslationLayer.translate_outbound_file(
        code_file=code_file,
        user=request.user,
        reveal_secrets=reveal_secrets
    )

    if reveal_secrets and view_dto['has_secrets']:
        SecurityAuditLog.objects.create(
            user=request.user,
            code_file=code_file,
            event_type='SECRETS_REVEALED',
            details=f"User revealed {view_dto['secrets_count']} masked credential(s) in '{code_file.filename}'",
            metadata={'revealed': True}
        )

    context = {
        'project': project,
        'file': code_file,
        'security_dto': view_dto,
        'code_lines': view_dto['code_lines'],
        'revisions': revisions,
    }
    return render(request, 'core/file_detail.html', context)


@login_required
def activity_history(request):
    """
    Global chronological activity log and CLI sync timeline for the authenticated user.
    """
    action_filter = request.GET.get('action')
    logs = ActivityLog.objects.filter(user=request.user).select_related('project')

    if action_filter:
        logs = logs.filter(action_type=action_filter)

    context = {
        'activities': logs[:50],
        'action_filter': action_filter,
        'action_choices': ActivityLog.ACTION_CHOICES,
    }
    return render(request, 'core/history.html', context)


@login_required
def tokens_view(request):
    """
    Manage Personal Access Tokens for CLI authentication.
    """
    newly_created_token = None

    if request.method == 'POST':
        form = APITokenCreateForm(request.POST)
        if form.is_valid():
            raw_key = APIToken.generate_key()
            token = form.save(commit=False)
            token.user = request.user
            token.key = raw_key
            token.save()

            ActivityLog.objects.create(
                user=request.user,
                action_type='TOKEN_CREATE',
                description=f"Generated CLI API token '{token.name}'",
                metadata={'token_id': token.id, 'name': token.name}
            )

            newly_created_token = raw_key
            messages.success(request, f"API Token '{token.name}' generated successfully. Copy it now, it won't be shown again!")
    else:
        form = APITokenCreateForm()

    tokens = APIToken.objects.filter(user=request.user, is_active=True)

    context = {
        'tokens': tokens,
        'form': form,
        'newly_created_token': newly_created_token,
    }
    return render(request, 'core/tokens.html', context)


@login_required
@require_POST
def revoke_token(request, token_id):
    """
    Revoke an active API token.
    """
    token = get_object_or_404(APIToken, id=token_id, user=request.user)
    token_name = token.name
    token.is_active = False
    token.save()

    ActivityLog.objects.create(
        user=request.user,
        action_type='TOKEN_REVOKE',
        description=f"Revoked CLI API token '{token_name}'",
        metadata={'token_id': token.id}
    )
    messages.info(request, f"Token '{token_name}' has been revoked.")
    return redirect('tokens')


@login_required
@require_POST
def create_project(request):
    """
    Create a new project repository via the web UI.
    """
    form = ProjectCreateForm(request.POST)
    if form.is_valid():
        project = form.save(commit=False)
        project.owner = request.user
        project.save()

        ActivityLog.objects.create(
            user=request.user,
            project=project,
            action_type='PROJECT_CREATE',
            description=f"Created repository '{project.name}' via Web Dashboard"
        )
        messages.success(request, f"Project '{project.name}' created.")
        return redirect('project_detail', project_slug=project.slug)

    messages.error(request, "Failed to create project. Please verify inputs.")
    return redirect('dashboard')


@csrf_exempt
def cli_sync_view(request):
    """
    CLI Ingestion Endpoint:
    Accepts code file data pushed by the CwayPro CLI tool.
    Authenticates via Personal Access Token ('Authorization: Bearer cwp_live_...' or 'X-Cway-Token').
    Parses terminal flags (e.g., --new-file, --branch), saves file content, records revisions,
    and logs activity.
    """
    if request.method != 'POST':
        return JsonResponse({
            'status': 'error',
            'error': 'Method not allowed. Only POST is accepted.'
        }, status=405)

    # 1. Authenticate CLI Token
    auth_header = request.headers.get('Authorization', '').strip()
    token_key = None
    if auth_header.lower().startswith('bearer '):
        token_key = auth_header[7:].strip()
    elif auth_header.lower().startswith('token '):
        token_key = auth_header[6:].strip()
    elif 'X-Cway-Token' in request.headers:
        token_key = request.headers['X-Cway-Token'].strip()

    if not token_key:
        return JsonResponse({
            'status': 'error',
            'error': 'Unauthorized: Missing API token in Authorization header (Bearer cwp_live_...) or X-Cway-Token.'
        }, status=401)

    api_token = APIToken.objects.filter(key=token_key, is_active=True).select_related('user').first()
    if not api_token:
        return JsonResponse({
            'status': 'error',
            'error': 'Unauthorized: Invalid or revoked API Token.'
        }, status=401)

    # Touch token last used
    api_token.last_used_at = timezone.now()
    api_token.save(update_fields=['last_used_at'])
    developer = api_token.user

    # 2. Parse Incoming Payload (supports JSON or Form POST)
    data = {}
    content_type = request.content_type or ''
    if content_type.startswith('application/json') or (request.body and request.body.strip().startswith(b'{')):
        try:
            data = json.loads(request.body.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return JsonResponse({'status': 'error', 'error': 'Invalid JSON payload'}, status=400)
    else:
        data = request.POST.dict()

    project_name = data.get('project') or data.get('repository') or 'default'
    file_path = data.get('file_path') or data.get('path')
    content = data.get('content', '')
    raw_flags = data.get('flags', {})

    if not file_path:
        return JsonResponse({'status': 'error', 'error': "'file_path' is required."}, status=400)

    # Clean file path safely without removing leading dot on files like .env
    clean_path = file_path.strip()
    if clean_path.startswith('./'):
        clean_path = clean_path[2:]
    elif clean_path.startswith('/'):
        clean_path = clean_path.lstrip('/')

    # Normalize terminal flags
    normalized_flags = {}
    if isinstance(raw_flags, list):
        for flag in raw_flags:
            flag_clean = flag.lstrip('-')
            normalized_flags[flag_clean] = True
    elif isinstance(raw_flags, dict):
        for k, v in raw_flags.items():
            normalized_flags[k.lstrip('-')] = v
    elif isinstance(raw_flags, str):
        try:
            parsed = json.loads(raw_flags)
            if isinstance(parsed, dict):
                normalized_flags = {k.lstrip('-'): v for k, v in parsed.items()}
            elif isinstance(parsed, list):
                normalized_flags = {f.lstrip('-'): True for f in parsed}
        except json.JSONDecodeError:
            normalized_flags[raw_flags.lstrip('-')] = True

    is_new_file_flag = bool(normalized_flags.get('new_file') or normalized_flags.get('new-file'))

    # 3. Security Translation Layer: Inbound processing (Secret scanning & Encryption at rest)
    security_inbound = SecurityTranslationLayer.translate_inbound(
        content=content,
        flags=normalized_flags,
        file_path=clean_path
    )
    final_content = security_inbound['content']
    is_encrypted = security_inbound['is_encrypted']
    scan_result = security_inbound['security_scan']

    # 4. Resolve or Create Project
    project, proj_created = Project.objects.get_or_create(
        owner=developer,
        name=project_name,
        defaults={'description': f'Repository synced from CLI by {developer.email}'}
    )
    if proj_created:
        ActivityLog.objects.create(
            user=developer,
            project=project,
            action_type='PROJECT_CREATE',
            description=f"Auto-created repository '{project.name}' via CLI sync"
        )

    # 5. Create or Update CodeFile & Preserve Historical Revisions
    code_file = CodeFile.objects.filter(project=project, file_path=clean_path).first()

    if code_file:
        # Save previous state in FileRevision
        FileRevision.objects.create(
            code_file=code_file,
            content=code_file.content,
            is_encrypted=code_file.is_encrypted,
            security_scan=code_file.security_scan,
            terminal_flags=code_file.terminal_flags,
            version=code_file.version
        )
        code_file.content = final_content
        code_file.is_encrypted = is_encrypted
        code_file.security_scan = scan_result
        code_file.terminal_flags = normalized_flags
        code_file.is_new_file = is_new_file_flag
        code_file.version += 1
        code_file.save()

        action_type = 'FILE_UPDATE'
        desc = f"Updated '{code_file.filename}' to v{code_file.version}"
    else:
        code_file = CodeFile.objects.create(
            project=project,
            file_path=clean_path,
            content=final_content,
            is_encrypted=is_encrypted,
            security_scan=scan_result,
            terminal_flags=normalized_flags,
            is_new_file=is_new_file_flag,
            version=1
        )
        action_type = 'FILE_CREATE' if is_new_file_flag else 'CLI_SYNC'
        desc = f"CLI pushed '{code_file.filename}' (v1)"

    # 6. Log Standard Activity & Security Audit Logs
    ActivityLog.objects.create(
        user=developer,
        project=project,
        action_type=action_type,
        description=desc,
        metadata={
            'file_path': code_file.file_path,
            'version': code_file.version,
            'flags': normalized_flags,
            'file_size': code_file.file_size_bytes,
            'is_encrypted': is_encrypted,
        }
    )

    if is_encrypted:
        SecurityAuditLog.objects.create(
            user=developer,
            code_file=code_file,
            event_type='ENCRYPTED_PUSH',
            details=f"Encrypted '{code_file.filename}' at rest using AES-128-CBC-HMAC envelope",
            metadata={'flags': normalized_flags}
        )

    if scan_result['has_secrets']:
        SecurityAuditLog.objects.create(
            user=developer,
            code_file=code_file,
            event_type='SECRETS_DETECTED',
            details=f"Detected {scan_result['count']} sensitive credential(s) in '{code_file.filename}'",
            metadata=scan_result
        )

    dashboard_url = request.build_absolute_uri(
        reverse('file_detail', kwargs={'project_slug': project.slug, 'file_id': code_file.id})
    )

    return JsonResponse({
        'status': 'success',
        'message': 'File synced successfully.',
        'project': project.name,
        'project_slug': project.slug,
        'file_id': code_file.id,
        'file_path': code_file.file_path,
        'filename': code_file.filename,
        'version': code_file.version,
        'language': code_file.language,
        'lines': code_file.line_count,
        'size_bytes': code_file.file_size_bytes,
        'is_new_file': code_file.is_new_file,
        'is_encrypted': code_file.is_encrypted,
        'security_scan': {
            'has_secrets': scan_result['has_secrets'],
            'secrets_detected': scan_result['count'],
            'findings': scan_result['findings'],
        },
        'flags': normalized_flags,
        'dashboard_url': dashboard_url,
    }, status=200)