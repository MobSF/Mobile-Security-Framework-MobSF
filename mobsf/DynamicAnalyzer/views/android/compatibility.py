"""Android runtime policy, independent from static APK analysis."""
import re

LEGACY_MAX_API = 30
ANDROID_RELEASES = {
    21: '5.0', 22: '5.1', 23: '6.0', 24: '7.0', 25: '7.1',
    26: '8.0', 27: '8.1', 28: '9', 29: '10', 30: '11',
    31: '12', 32: '12L', 33: '13', 34: '14', 35: '15', 36: '16', 37: '17',
}
FRIDA_ARCHITECTURES = {
    'armeabi-v7a': 'arm', 'armeabi': 'arm', 'arm64-v8a': 'arm64',
    'x86': 'x86', 'x86_64': 'x86_64',
}


def parse_api(value):
    """Reject absent, malformed or unreasonable device SDK properties."""
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{1,3}', value):
        raise ValueError('Cannot determine Android API level')
    api = int(value)
    if not 1 <= api <= 999:
        raise ValueError('Cannot determine Android API level')
    return api


def release_number(release, sdk):
    """Keep legacy float consumers working with preview release codenames."""
    match = re.fullmatch(r'(\d+)(?:\.(\d+))?(?:\.\d+)*', release.strip())
    if match:
        return float(match[1] + ('.' + match[2] if match[2] else ''))
    known = ANDROID_RELEASES.get(parse_api(sdk))
    if known:
        return float(known.removesuffix('L'))
    raise ValueError('Unknown preview release; Android API mapping needs review')


def full_sdk(value, api):
    """Retain minor API levels while keeping major capability checks separate."""
    if api is None:
        return None
    if (re.fullmatch(r'[0-9]{1,3}(?:\.[0-9]{1,3})?', value)
            and int(value.split('.')[0]) == api):
        return value
    return str(api)


def runtime_policy(sdk, modern_enabled=False):
    """Describe eligibility without claiming device-tested compatibility."""
    try:
        api = parse_api(sdk)
    except ValueError as exc:
        return {'api': None, 'mode': 'unknown', 'eligible': False,
                'message': str(exc), 'automatic_system_ca': False}
    modern = api > LEGACY_MAX_API
    enabled = not modern or modern_enabled
    return {
        'api': api,
        'release': ANDROID_RELEASES.get(api, f'API {api} (unmapped release)'),
        'mode': 'modern_experimental' if modern else 'legacy',
        'eligible': enabled,
        'automatic_system_ca': not modern,
        'message': (
            'Experimental modern runtime: root ADB and writable /data/local/tmp '
            'required. System CA installation and automated TLS verdicts '
            'are unavailable; device testing is still required.' if modern and enabled
            else 'Enable MOBSF_ANDROID_MODERN_DYNAMIC=1 for the experimental '
            'rooted modern runtime.' if modern
            else 'Legacy runtime requires root ADB and writable /system.'),
    }
