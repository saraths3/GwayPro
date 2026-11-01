from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('projects/new/', views.create_project, name='create_project'),
    path('projects/<slug:project_slug>/', views.project_detail, name='project_detail'),
    path('projects/<slug:project_slug>/files/<int:file_id>/', views.file_detail, name='file_detail'),
    path('history/', views.activity_history, name='activity_history'),
    path('tokens/', views.tokens_view, name='tokens'),
    path('tokens/revoke/<int:token_id>/', views.revoke_token, name='revoke_token'),
    path('api/v1/sync/', views.cli_sync_view, name='cli_sync'),
]