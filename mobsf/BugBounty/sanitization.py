"""Remove credentials and common personal data before storage or export."""
import re

from mobsf.StaticAnalyzer.views.common.secret_detection import (
    KNOWN_SECRET_PATTERNS,
)

REDACTED = '[REDACTED]'
SENSITIVE = re.compile(
    r'password|passwd|secret|token|authorization|cookie|api.?key|'
    r'email|phone|address|session|client.?secret', re.I)


def redact_text(value):
    text = str(value)
    text = re.sub(
        r'-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----.*?'
        r'-----END (?:[A-Z ]+)?PRIVATE KEY-----',
        REDACTED, text, flags=re.S)
    for _name, pattern in KNOWN_SECRET_PATTERNS:
        text = pattern.sub(REDACTED, text)
    text = re.sub(r'(?i)\bBearer\s+[^\s"\x27,;]+', 'Bearer ' + REDACTED, text)
    text = re.sub(
        r'(?im)\b(authorization|cookie|set-cookie)\s*:[^\r\n]*',
        lambda m: m[1] + ': ' + REDACTED, text)
    text = re.sub(
        r'(?i)\b(password|passwd|secret|token|api[_-]?key|session[_-]?id)'
        r'(["\x27]?\s*[:=]\s*["\x27]?)[^\s"\x27&;,<>]+',
        lambda m: m[1] + m[2] + REDACTED, text)
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
                  REDACTED, text)
    text = re.sub(r'(?i)([a-z][a-z0-9+.-]*://)[^\s/@]+:[^\s/@]+@',
                  lambda m: m[1] + REDACTED + '@', text)
    text = re.sub(r'(?<!\w)\+\d[\d ()-]{8,}\d(?!\w)', REDACTED, text)
    text = re.sub(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b',
                  REDACTED, text)
    text = re.sub(r'(?<!\w)[A-Za-z0-9_+/=-]{32,}(?!\w)', REDACTED, text)
    return text


def sanitize(value, depth=0):
    if depth > 12:
        raise ValueError('Evidence nesting limit exceeded')
    if isinstance(value, dict):
        return {redact_text(str(key))[:200]: (
            REDACTED if SENSITIVE.search(str(key))
            else sanitize(item, depth + 1)) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize(item, depth + 1) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_text(value)
