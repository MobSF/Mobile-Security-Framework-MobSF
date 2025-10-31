"""Template context processors for MobSF UI customisation."""
from __future__ import annotations

from typing import Dict, Iterable

from django.conf import settings
from django.utils.translation import get_language


def _resolve_localized(values: Dict[str, str], language_code: str) -> str:
    """Return a localised string with graceful fallbacks."""
    if not values:
        return ''
    language_code = (language_code or '').lower()
    if language_code in values:
        return values[language_code]
    base_language = language_code.split('-')[0] if language_code else ''
    if base_language and base_language in values:
        return values[base_language]
    return values.get('default') or next(iter(values.values()))


def branding(request):
    """Expose brand and localisation controls to the templates."""
    language_code = getattr(request, 'LANGUAGE_CODE', None) or get_language()
    language_code = (language_code or settings.LANGUAGE_CODE).lower()
    branding_config = settings.UI_BRANDING

    navigation_labels = {
        key: _resolve_localized(value, language_code)
        for key, value in branding_config.get('navigation_labels', {}).items()
    }

    available_languages: Iterable[str] = settings.UI_LANGUAGES
    language_options = []
    language_display = dict(settings.LANGUAGES)
    for code in available_languages:
        normalized = code.lower()
        label = language_display.get(normalized, language_display.get(normalized.replace('_', '-'), normalized.upper()))
        language_options.append({
            'code': normalized,
            'label': label,
            'selected': normalized == language_code,
        })

    login_heading = _resolve_localized(
        branding_config.get('login_titles', {}),
        language_code,
    )
    login_message = _resolve_localized(
        branding_config.get('login_messages', {}),
        language_code,
    )
    login_support_text = _resolve_localized(
        branding_config.get('login_support_texts', {}),
        language_code,
    )

    return {
        'branding': {
            'product_name': branding_config.get('product_name', 'Mobile Security Framework'),
            'product_short_name': branding_config.get('product_short_name', 'MobSF'),
            'organization_name': branding_config.get('organization_name', ''),
            'accent_color': branding_config.get('accent_color', '#2563eb'),
            'accent_color_dark': branding_config.get('accent_color_dark', '#1e3a8a'),
            'accent_contrast_color': branding_config.get('accent_contrast_color', '#ffffff'),
            'background_color': branding_config.get('background_color', '#0b1220'),
            'login_background_overlay': branding_config.get('login_background_overlay'),
            'login_heading': login_heading,
            'login_message': login_message,
            'login_support_text': login_support_text,
            'login_support_url': branding_config.get('login_support_url', ''),
            'logo_asset': branding_config.get('logo_static_path', ''),
            'security_tips': branding_config.get('security_tips', []),
            'navigation': navigation_labels,
        },
        'available_languages': language_options,
    }
