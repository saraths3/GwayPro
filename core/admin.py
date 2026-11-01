from django.contrib import admin
from .models import APIToken, Project, CodeFile, FileRevision, ActivityLog, SecurityAuditLog

@admin.register(APIToken)
class APITokenAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'masked_key', 'is_active', 'last_used_at', 'created_at')
    list_filter = ('is_active', 'created_at')
    search_fields = ('name', 'key', 'user__email')

@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ('name', 'owner', 'slug', 'is_private', 'created_at', 'updated_at')
    search_fields = ('name', 'slug', 'owner__email')
    prepopulated_fields = {'slug': ('name',)}

@admin.register(CodeFile)
class CodeFileAdmin(admin.ModelAdmin):
    list_display = ('filename', 'project', 'file_path', 'language', 'version', 'is_new_file', 'is_encrypted', 'updated_at')
    list_filter = ('language', 'is_new_file', 'is_encrypted')
    search_fields = ('filename', 'file_path', 'project__name')

@admin.register(FileRevision)
class FileRevisionAdmin(admin.ModelAdmin):
    list_display = ('code_file', 'version', 'is_encrypted', 'created_at')
    search_fields = ('code_file__filename', 'code_file__file_path')

@admin.register(ActivityLog)
class ActivityLogAdmin(admin.ModelAdmin):
    list_display = ('action_type', 'user', 'project', 'description', 'created_at')
    list_filter = ('action_type', 'created_at')
    search_fields = ('description', 'user__email', 'project__name')

@admin.register(SecurityAuditLog)
class SecurityAuditLogAdmin(admin.ModelAdmin):
    list_display = ('event_type', 'user', 'code_file', 'details', 'created_at')
    list_filter = ('event_type', 'created_at')
    search_fields = ('details', 'user__email', 'code_file__filename')
