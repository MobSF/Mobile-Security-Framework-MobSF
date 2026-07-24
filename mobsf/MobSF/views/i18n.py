# -*- coding: utf_8 -*-
"""
i18n helpers for MobSF Chinese localization.

Provides a context processor that injects the current language
and available languages into every template context, plus a view
to switch languages.
"""
from django.utils import translation
from django.shortcuts import redirect
from django.urls import reverse
from django.conf import settings


def language_context(request):
    """Inject language info into template context."""
    current_lang = translation.get_language()
    return {
        'LANGUAGES': settings.LANGUAGES,
        'CURRENT_LANGUAGE': current_lang,
        'LANGUAGES_BIDI': False,
    }


def set_language(request):
    """Switch the active language and redirect back."""
    lang_code = request.GET.get('lang', 'zh-hans')
    supported = [code for code, _ in settings.LANGUAGES]
    if lang_code not in supported:
        lang_code = 'zh-hans'
    translation.activate(lang_code)
    response = redirect(request.META.get('HTTP_REFERER', '/'))
    response.set_cookie(settings.LANGUAGE_COOKIE_NAME, lang_code)
    return response
