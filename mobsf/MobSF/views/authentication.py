"""User Login and Logout."""
from inspect import signature

from django.shortcuts import (
    redirect,
    render,
)
from django.contrib.auth import (
    login,
    logout,
    password_validation,
    update_session_auth_hash,
)
from django.contrib.auth.forms import (
    AuthenticationForm,
    PasswordChangeForm,
    PasswordResetForm,
    SetPasswordForm,
)
from django.contrib.auth.views import (
    PasswordResetCompleteView,
    PasswordResetConfirmView,
    PasswordResetDoneView,
    PasswordResetView,
)
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required as lg
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator

from mobsf.MobSF.security import (
    sanitize_redirect,
)

from django_ratelimit.decorators import ratelimit


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


@ratelimit(key='user_or_ip',
           rate=settings.RATELIMIT,
           method='POST',
           block=True)
def login_view(request):
    """Login Controller."""
    if settings.DISABLE_AUTHENTICATION == '1':
        return redirect('/')
    sso = (settings.IDP_METADATA_URL
           or (settings.IDP_SSO_URL
               and settings.IDP_ENTITY_ID
               and settings.IDP_X509CERT))
    if not sso:
        allow_pwd = True
    elif bool(settings.SP_ALLOW_PASSWORD == '1'):
        allow_pwd = True
    else:
        allow_pwd = False
    nextp = request.GET.get('next', '')
    redirect_url = sanitize_redirect(nextp)
    if request.user.is_authenticated:
        return redirect(redirect_url)
    if request.method == 'POST':
        if sso and not allow_pwd:
            return redirect('/')
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
        'sso': sso,
        'allow_pwd': allow_pwd,
        'password_reset_enabled': settings.ENABLE_PASSWORD_RESET,
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
        'password_help_texts': password_validation.password_validators_help_texts(),
    }
    return render(
        request,
        'auth/change_password.html',
        context)


class _AuthEnabledMixin:
    """Ensure password reset endpoints honour MobSF auth settings."""

    page_title = ''

    def dispatch(self, request, *args, **kwargs):
        if settings.DISABLE_AUTHENTICATION == '1' or not settings.ENABLE_PASSWORD_RESET:
            return redirect('/')
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.setdefault('title', self.page_title or 'Password Reset')
        context['version'] = settings.VERSION
        return context


@method_decorator(
    ratelimit(key='user_or_ip', rate=settings.RATELIMIT, method='POST', block=True),
    name='dispatch',
)
class MobSFPasswordResetView(_AuthEnabledMixin, PasswordResetView):
    """Initiate password reset via email."""

    form_class = PasswordResetForm
    template_name = 'auth/password_reset.html'
    email_template_name = 'auth/password_reset_email.txt'
    subject_template_name = 'auth/password_reset_subject.txt'
    success_url = reverse_lazy('password_reset_done')
    page_title = 'Reset Password'
    from_email = settings.DEFAULT_FROM_EMAIL
    extra_email_context = {
        'product_name': 'Mobile Security Framework (MobSF)',
    }

    def get_form(self, form_class=None):
        form = super().get_form(form_class)
        form.fields['email'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Email address',
            'autocomplete': 'email',
            'required': True,
        })
        return form

    def form_valid(self, form):
        try:
            response = super().form_valid(form)
            messages.success(
                self.request,
                'If an account exists for the provided email address, '
                'you will receive password reset instructions shortly.',
            )
            return response
        except Exception:
            messages.error(
                self.request,
                'Unable to send password reset instructions. '
                'Please contact your MobSF administrator.',
            )
            return self.form_invalid(form)


class MobSFPasswordResetDoneView(_AuthEnabledMixin, PasswordResetDoneView):
    template_name = 'auth/password_reset_done.html'
    page_title = 'Reset Email Sent'


class MobSFPasswordResetConfirmView(_AuthEnabledMixin, PasswordResetConfirmView):
    template_name = 'auth/password_reset_confirm.html'
    success_url = reverse_lazy('password_reset_complete')
    form_class = SetPasswordForm
    page_title = 'Choose a New Password'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['password_help_texts'] = (
            password_validation.password_validators_help_texts()
        )
        return context


class MobSFPasswordResetCompleteView(_AuthEnabledMixin, PasswordResetCompleteView):
    template_name = 'auth/password_reset_complete.html'
    page_title = 'Password Reset Complete'
