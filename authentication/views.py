from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .forms import CustomUserCreationForm
import logging

logger = logging.getLogger(__name__)

def login_view(request):
    try:
        if request.method == 'POST':
            form = AuthenticationForm(request, data=request.POST)
            if form.is_valid():
                username = form.cleaned_data.get('username')
                password = form.cleaned_data.get('password')
                user = authenticate(request, username=username, password=password)
                if user is not None:
                    login(request, user)
                    messages.success(request, f'Welcome back, {username}!')
                    return redirect('main_app:dashboard')
                else:
                    messages.error(request, 'Invalid username or password.')
            else:
                messages.error(request, 'Please correct the errors below.')
        else:
            form = AuthenticationForm()
        return render(request, 'authentication/login.html', {'form': form})
    except Exception as e:
        logger.error(f"Error during login: {str(e)}")
        messages.error(request, 'An error occurred during login. Please try again.')
        return redirect('authentication:login')

def register_view(request):
    try:
        if request.method == 'POST':
            form = CustomUserCreationForm(request.POST)
            if form.is_valid():
                try:
                    user = form.save()
                    logger.info(f"New user registered successfully: {user.username}")
                    messages.success(request, 'Registration successful! Please log in.')
                    return redirect('authentication:login')
                except Exception as e:
                    logger.error(f"Error saving user: {str(e)}")
                    messages.error(request, f'Error saving user: {str(e)}')
            else:
                logger.warning(f"Registration form errors: {form.errors}")
                for field, errors in form.errors.items():
                    for error in errors:
                        messages.error(request, f"{field}: {error}")
        else:
            form = CustomUserCreationForm()
        return render(request, 'authentication/register.html', {'form': form})
    except Exception as e:
        logger.error(f"Unexpected error during registration: {str(e)}")
        messages.error(request, 'An error occurred during registration. Please try again.')
        return redirect('authentication:register')

@login_required
def profile_view(request):
    return render(request, 'authentication/profile.html')

@login_required
def settings_view(request):
    return render(request, 'authentication/settings.html')

def logout_view(request):
    logout(request)
    messages.info(request, 'You have been logged out.')
    return redirect('authentication:login') 