"""User Login and Logout."""
from inspect import signature

from django.shortcuts import (
    redirect,
    render,
)
from django.contrib.auth import (
    login,
    logout,
    update_session_auth_hash,
)
from django.contrib.auth.forms import (
    AuthenticationForm,
    PasswordChangeForm,
)
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required as lg

from brake.decorators import ratelimit


def login_required(func):
    """Login required decorator."""
    sig = signature(func)

    def wrapper(request, *args, **kwargs):
        arguments = sig.bind(request, *args, **kwargs)
        api = arguments.arguments.get('api')
        # Handle functions that are used by API and Web
        if settings.DISABLE_AUTHENTICATION == '1' or api:
            # Disable authentication for all functions
            return func(request, *args, **kwargs)
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
    if settings.DISABLE_AUTHENTICATION == '1':
        return redirect('/')
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
    return redirect(settings.LOGIN_URL)


@login_required
def change_password(request):
    if settings.DISABLE_AUTHENTICATION == '1':
        return redirect('/')
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
