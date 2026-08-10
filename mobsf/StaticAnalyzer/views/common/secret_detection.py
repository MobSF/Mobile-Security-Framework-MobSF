"""Known secret pattern detection."""
import re

from mobsf.StaticAnalyzer.views.common.entropy import (
    get_entropies,
)

KNOWN_SECRET_PATTERNS = (
    (
        'GitHub token',
        re.compile(
            r'(?<![A-Za-z0-9_])'
            r'gh[pousr]_[A-Za-z0-9]{36,255}'
            r'(?![A-Za-z0-9])'),
    ),
    (
        'GitHub fine-grained token',
        re.compile(
            r'(?<![A-Za-z0-9_])'
            r'github_pat_[A-Za-z0-9_]{20,255}'
            r'(?![A-Za-z0-9_])'),
    ),
    (
        'GitLab personal access token',
        re.compile(
            r'(?<![A-Za-z0-9_-])'
            r'glpat-[A-Za-z0-9_-]{20,255}'
            r'(?![A-Za-z0-9_-])'),
    ),
    (
        'Slack token',
        re.compile(
            r'(?<![A-Za-z0-9-])'
            r'xox[baprs]-[A-Za-z0-9-]{10,255}'
            r'(?![A-Za-z0-9-])'),
    ),
    (
        'Slack webhook',
        re.compile(
            r'https://hooks\.slack\.com/services/'
            r'T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/'
            r'[A-Za-z0-9]{20,64}'
            r'(?![A-Za-z0-9])'),
    ),
    (
        'Stripe live secret key',
        re.compile(
            r'(?<![A-Za-z0-9_])'
            r'(?:sk|rk)_live_[A-Za-z0-9]{16,255}'
            r'(?![A-Za-z0-9])'),
    ),
    (
        'SendGrid API key',
        re.compile(
            r'(?<![A-Za-z0-9_.-])'
            r'SG\.[A-Za-z0-9_-]{16,64}\.'
            r'[A-Za-z0-9_-]{16,128}'
            r'(?![A-Za-z0-9_-])'),
    ),
    (
        'npm access token',
        re.compile(
            r'(?<![A-Za-z0-9_])'
            r'npm_[A-Za-z0-9]{36,64}'
            r'(?![A-Za-z0-9])'),
    ),
    (
        'Mapbox secret token',
        re.compile(
            r'(?<![A-Za-z0-9_.-])'
            r'sk\.[A-Za-z0-9_-]{20,256}\.'
            r'[A-Za-z0-9_-]{20,256}'
            r'(?![A-Za-z0-9_-])'),
    ),
    (
        'Anthropic API key',
        re.compile(
            r'(?<![A-Za-z0-9_-])'
            r'sk-ant-(?:api03|admin01)-'
            r'[A-Za-z0-9_-]{93}AA'
            r'(?![A-Za-z0-9_-])'),
    ),
    (
        'OpenAI API key',
        re.compile(
            r'(?<![A-Za-z0-9_-])'
            r'(?:'
            r'sk-(?:proj|svcacct|admin)-'
            r'(?:[A-Za-z0-9_-]{58}|[A-Za-z0-9_-]{74})'
            r'T3BlbkFJ'
            r'(?:[A-Za-z0-9_-]{58}|[A-Za-z0-9_-]{74})'
            r'|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}'
            r')'
            r'(?![A-Za-z0-9_-])'),
    ),
    (
        'Hugging Face access token',
        re.compile(
            r'(?<![A-Za-z0-9_])'
            r'hf_[A-Za-z]{34}'
            r'(?![A-Za-z0-9])'),
    ),
    (
        'DigitalOcean token',
        re.compile(
            r'(?<![A-Za-z0-9_])'
            r'(?:doo|dop|dor)_v1_[a-f0-9]{64}'
            r'(?![A-Za-z0-9])'),
    ),
    (
        'Doppler API token',
        re.compile(
            r'(?<![A-Za-z0-9_.])'
            r'dp\.pt\.[A-Za-z0-9]{43}'
            r'(?![A-Za-z0-9])'),
    ),
    (
        'Brevo API token',
        re.compile(
            r'(?<![A-Za-z0-9_-])'
            r'xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}'
            r'(?![A-Za-z0-9])'),
    ),
    (
        'Sentry user token',
        re.compile(
            r'(?<![A-Za-z0-9_])'
            r'sntryu_[a-f0-9]{64}'
            r'(?![A-Za-z0-9])'),
    ),
    (
        'Shopify access token',
        re.compile(
            r'(?<![A-Za-z0-9_])'
            r'(?:shpat|shpca|shppa|shpss)_[A-Fa-f0-9]{32}'
            r'(?![A-Fa-f0-9])'),
    ),
    (
        'Square access token',
        re.compile(
            r'(?<![A-Za-z0-9_-])'
            r'sq0atp-[A-Za-z0-9_-]{22,60}'
            r'(?![A-Za-z0-9_-])'),
    ),
    (
        'Private key',
        re.compile(
            r'-----BEGIN '
            r'(?:RSA |EC |DSA |OPENSSH )?'
            r'PRIVATE KEY-----'),
    ),
    (
        'Amazon LWA client secret',
        re.compile(
            r'(?<![A-Za-z0-9_.-])'
            r'amzn1\.oa2-cs\.v[0-9]+\.[0-9A-Fa-f]{32,128}'
            r'(?![0-9A-Fa-f])'),
    ),
    (
        'Amazon LWA access token',
        re.compile(
            r'(?<![A-Za-z0-9_-])'
            r'Atza\|[A-Za-z0-9_-]{20,2043}'
            r'(?![A-Za-z0-9_-])'),
    ),
    (
        'Amazon LWA refresh token',
        re.compile(
            r'(?<![A-Za-z0-9_-])'
            r'Atzr\|[A-Za-z0-9_-]{20,2043}'
            r'(?![A-Za-z0-9_-])'),
    ),
)
KNOWN_SECRET_PREFIXES = tuple(
    f'{name}: ' for name, _pattern in KNOWN_SECRET_PATTERNS)


def _strings(data):
    """Normalize a string or iterable of strings to a tuple."""
    if data is None:
        return ()
    if isinstance(data, str):
        return (data,)
    return tuple(data)


def detect_known_secrets(data):
    """Detect and label secrets with known value formats."""
    secrets = set()
    for value in _strings(data):
        if not isinstance(value, str):
            continue
        for name, pattern in KNOWN_SECRET_PATTERNS:
            for match in pattern.finditer(value):
                secrets.add(f'{name}: {match.group()}')
    return secrets


def get_secrets(data):
    """Detect known-format and high-entropy secrets."""
    secrets = set()
    for value in _strings(data):
        if not isinstance(value, str):
            continue
        scrubbed = value
        for name, pattern in KNOWN_SECRET_PATTERNS:
            for match in pattern.finditer(value):
                secrets.add(f'{name}: {match.group()}')
            scrubbed = pattern.sub('', scrubbed)
        secrets.update(get_entropies((scrubbed,)))
    return secrets


def sort_secrets(secrets):
    """Place labeled known-format secrets before heuristic findings."""
    return sorted(
        set(secrets),
        key=lambda secret: (
            not secret.startswith(KNOWN_SECRET_PREFIXES),
            secret.casefold(),
        ),
    )
