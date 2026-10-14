"""Normalize endpoints from source strings and observed traffic."""
from hashlib import sha256
import re
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

from mobsf.BugBounty.sanitization import redact_text
from mobsf.BugBounty.scope import canonical_host

URL = re.compile(r'(?:https?|wss?)://[^\s<>"\x27`]+')
METHODS = {'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'CONNECT'}


def endpoint_record(url, source, method='', observed=False):
    if len(url) > 4096 or any(ord(c) < 32 for c in url):
        raise ValueError('Invalid URL size or control character')
    parts = urlsplit(url)
    if parts.scheme.lower() not in ('http', 'https', 'ws', 'wss'):
        raise ValueError('Unsupported URL scheme')
    if parts.username is not None or parts.password is not None:
        raise ValueError('URLs with credentials are not imported')
    host = canonical_host(parts.hostname or '')
    port = parts.port
    if port and not 1 <= port <= 65535:
        raise ValueError('Invalid port')
    netloc = '[' + host + ']' if ':' in host else host
    default = 443 if parts.scheme.lower() in ('https', 'wss') else 80
    if port and port != default:
        netloc += ':' + str(port)
    path = parts.path or '/'
    if len(path) > 2048:
        raise ValueError('URL path too long')
    parameters = sorted({k for k, _v in parse_qsl(
        parts.query, keep_blank_values=True, max_num_fields=200)})
    if not isinstance(method, str):
        raise ValueError('Invalid HTTP method')
    method = method if observed and method in METHODS else ''
    # Values and fragments are never retained. Stable identity ignores values.
    identity = '\n'.join((parts.scheme.lower(), netloc, path,
                          ','.join(parameters)))
    safe_path = redact_text(path)
    url = urlunsplit((parts.scheme.lower(), redact_text(netloc), safe_path,
                     '&'.join(quote(redact_text(k), safe='') + '='
                              for k in parameters), ''))
    return {
        'fingerprint': sha256(identity.encode()).hexdigest(),
        'url': url, 'host': redact_text(host), 'path': safe_path, 'method': method,
        'methods': [method] if method else [],
        'parameters': [redact_text(k) for k in parameters],
        'sources': [redact_text(source)[:500]],
        'observed': observed, 'confidence': 0.95 if observed else 0.5,
        'protocol': ('WebSocket' if parts.scheme in ('ws', 'wss') else
                     'GraphQL' if 'graphql' in path.lower() else 'HTTP'),
    }


def discover(text, source):
    for match in URL.finditer(text):
        try:
            yield endpoint_record(match[0].rstrip('),;'), source)
        except ValueError:
            continue
