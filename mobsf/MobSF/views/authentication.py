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

from inspect import signature


def login_required(func):
    """Login required decorator."""
    sig = signature(func)

    def wrapper(request, *args, **kwargs):
        arguments = sig.bind(request, *args, **kwargs)
        api = arguments.arguments.get('api')
        # # Handle functions that are used by API and Web
        if api:
            return func(request, *args, **kwargs)
        else:
            return lg(func)(request, *args, **kwargs)
    return wrapper


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
    return redirect(settings.LOGIN_URL)
