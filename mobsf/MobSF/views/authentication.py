"""User Login and Logout."""
from django.shortcuts import (
    redirect,
    render,
)
from django.contrib.auth import (
    logout,
)
from django.conf import settings
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required as lg
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm

from brake.decorators import ratelimit

from inspect import signature


def login_required(func):
    """Login required decorator."""
    sig = signature(func)

    def wrapper(request, *args, **kwargs):
        arguments = sig.bind(request, *args, **kwargs)
        api = arguments.arguments.get('api')
        # Handle functions that are used by API and Web
        if settings.DISABLE_AUTHENTICATION == '1':
            # Disable authentication for all functions
            return func(request, *args, **kwargs)
        if api:
            # Disable additional authentication
            # for API function calls
            return func(request, *args, **kwargs)
        else:
            # Force authentication for all
            # web function calls
            return lg(func)(request, *args, **kwargs)
    return wrapper


@ratelimit(ip=True,
           method='POST',
           rate=settings.RATELIMIT,
           block=True)
def login_view(request):
    """Login Controller."""
    nextp = request.GET.get('next', '')
    redirect_url = nextp if nextp.startswith('/') else '/'
    if request.user.is_authenticated:
        return redirect(redirect_url)
    if request.method == 'POST':
        form = AuthenticationForm(request, request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect(redirect_url)
    else:
        form = AuthenticationForm()
    context = {
        'title': 'Sign In',
        'version': settings.VERSION,
        'next': redirect_url,
        'form': form,
    }
    return render(request, 'auth/login.html', context)


def logout_view(request):
    """Logout Controller."""
    logout(request)
    response = redirect(settings.LOGIN_URL)
    response['Clear-Site-Data'] = '"*"'
    return response


@login_required
def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(
                request,
                'Your password was successfully updated!')
            return redirect('change_password')
        else:
            messages.error(
                request,
                'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)
    context = {
        'title': 'Change Password',
        'version': settings.VERSION,
        'form': form,
    }
    return render(
        request,
        'auth/change_password.html',
        context)
