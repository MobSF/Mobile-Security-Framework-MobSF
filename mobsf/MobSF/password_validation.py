"""Custom password validators used by MobSF."""
import re
from typing import List

from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _


class ConfigurablePasswordValidator:
    """Validate passwords against a configurable policy."""

    def __init__(
        self,
        min_length: int = 12,
        require_uppercase: bool = True,
        require_lowercase: bool = True,
        require_digits: bool = True,
        require_special: bool = True,
        special_characters: str = r"!@#$%^&*()_+\-={}\[\]:\";'<>?,./",
    ) -> None:
        self.min_length = max(int(min_length), 1)
        self.require_uppercase = bool(require_uppercase)
        self.require_lowercase = bool(require_lowercase)
        self.require_digits = bool(require_digits)
        self.require_special = bool(require_special)
        # Escape regex meta characters so the value can be presented safely.
        self.special_characters = special_characters
        self._special_pattern = re.compile(f"[{re.escape(self.special_characters)}]")

    def _requirements(self) -> List[str]:
        requirements = [
            _('Must contain at least %(min_length)d characters.')
            % {'min_length': self.min_length}
        ]
        if self.require_uppercase:
            requirements.append(_('Must contain an uppercase letter.'))
        if self.require_lowercase:
            requirements.append(_('Must contain a lowercase letter.'))
        if self.require_digits:
            requirements.append(_('Must contain a digit.'))
        if self.require_special:
            requirements.append(
                _('Must contain a special character (%(characters)s).')
                % {'characters': self.special_characters}
            )
        return requirements

    def validate(self, password: str, user=None) -> None:
        errors = []
        if len(password or '') < self.min_length:
            errors.append(
                _('This password is too short. It must contain at least %(min_length)d characters.')
                % {'min_length': self.min_length}
            )
        if self.require_uppercase and not re.search(r'[A-Z]', password or ''):
            errors.append(_('This password must contain at least one uppercase letter.'))
        if self.require_lowercase and not re.search(r'[a-z]', password or ''):
            errors.append(_('This password must contain at least one lowercase letter.'))
        if self.require_digits and not re.search(r'\d', password or ''):
            errors.append(_('This password must contain at least one digit.'))
        if self.require_special and not self._special_pattern.search(password or ''):
            errors.append(
                _('This password must contain at least one special character (%(characters)s).')
                % {'characters': self.special_characters}
            )
        if errors:
            raise ValidationError(errors)

    def get_help_text(self) -> str:
        return ' '.join(self._requirements())
