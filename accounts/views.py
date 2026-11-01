from django.shortcuts import render, redirect
from django.urls import reverse

def login(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'account/login.html')