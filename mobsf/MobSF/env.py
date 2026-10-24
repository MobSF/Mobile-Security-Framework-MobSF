"""Boolean environment and config values.

A flag is enabled only when its value is ``1``. A Python ``True`` is kept so
an existing home ``config.py`` can still assign a flag directly.
"""
import os


def flag_from_value(value):
    """Return True when a config or environment value enables a flag."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    text = str(value).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ('"', "'"):
        text = text[1:-1].strip()
    return text == '1'


def env_flag(name, default='0'):
    """Read a boolean environment variable. Only ``1`` enables it."""
    return flag_from_value(os.getenv(name, default))


# Settings that may already be set by an older ~/.MobSF/config.py.
CONFIG_BOOL_FLAGS = (
    ('CVSS_SCORE_ENABLED', 'MOBSF_CVSS_SCORE_ENABLED', '0'),
    ('NIAP_ENABLED', 'MOBSF_NIAP_ENABLED', '0'),
    ('PERM_MAPPING_ENABLED', 'MOBSF_PERM_MAPPING_ENABLED', '1'),
    ('DEX2SMALI_ENABLED', 'MOBSF_DEX2SMALI_ENABLED', '1'),
    ('SO_ANALYSIS_ENABLED', 'MOBSF_SO_ANALYSIS_ENABLED', '1'),
    ('DYLIB_ANALYSIS_ENABLED', 'MOBSF_DYLIB_ANALYSIS_ENABLED', '1'),
    ('DOMAIN_MALWARE_SCAN', 'MOBSF_DOMAIN_MALWARE_SCAN', '1'),
    ('APKID_ENABLED', 'MOBSF_APKID_ENABLED', '1'),
    ('UPSTREAM_PROXY_ENABLED', 'MOBSF_UPSTREAM_PROXY_ENABLED', '0'),
    ('UPSTREAM_PROXY_SSL_VERIFY', 'MOBSF_UPSTREAM_PROXY_SSL_VERIFY', '1'),
    ('VT_ENABLED', 'MOBSF_VT_ENABLED', '0'),
    ('VT_UPLOAD', 'MOBSF_VT_UPLOAD', '0'),
)


def apply_config_flags(namespace, environ=None):
    """Normalize boolean settings without discarding a hand-edited config.

    An environment variable wins when it is set, including ``0``. Otherwise
    the value already loaded from config is coerced. ``True`` stays enabled.
    """
    env = os.environ if environ is None else environ
    for attr, env_name, default in CONFIG_BOOL_FLAGS:
        if env_name in env:
            namespace[attr] = flag_from_value(env[env_name])
        elif attr in namespace:
            namespace[attr] = flag_from_value(namespace[attr])
        else:
            namespace[attr] = default == '1'
