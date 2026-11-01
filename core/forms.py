from django import forms
from .models import APIToken, Project

class APITokenCreateForm(forms.ModelForm):
    class Meta:
        model = APIToken
        fields = ['name']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'cway-input',
                'placeholder': 'e.g. Workstation M3, Ubuntu Server',
                'required': True,
                'autocomplete': 'off',
            })
        }

class ProjectCreateForm(forms.ModelForm):
    class Meta:
        model = Project
        fields = ['name', 'description', 'is_private']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'cway-input',
                'placeholder': 'e.g. cway-agent-core',
                'required': True,
            }),
            'description': forms.Textarea(attrs={
                'class': 'cway-input',
                'rows': 3,
                'placeholder': 'Brief description of this project or repository...',
            }),
            'is_private': forms.CheckboxInput(attrs={
                'class': 'cway-checkbox',
            }),
        }

class CLISyncPayloadForm(forms.Form):
    project = forms.CharField(max_length=128, required=True)
    file_path = forms.CharField(max_length=512, required=True)
    content = forms.CharField(widget=forms.Textarea, required=True)
    flags = forms.JSONField(required=False, initial=dict)
