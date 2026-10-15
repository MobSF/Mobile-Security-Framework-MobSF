"""Conservative host and path matching, without network operations."""
import ipaddress
import re
from urllib.parse import unquote, urlsplit

RULE_FIELDS = ('allowed_domains', 'allowed_subdomains', 'excluded_domains',
               'excluded_paths')


def canonical_host(value):
    host = value.rstrip('.').lower()
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        host = host.encode('idna').decode('ascii')
    if len(host) > 253 or not re.fullmatch(
            r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', host):
        raise ValueError('Invalid domain')
    if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
           for label in host.split('.')):
        raise ValueError('Invalid domain label')
    return host


def validate_rules(rules):
    if not isinstance(rules, dict) or set(rules) - set(RULE_FIELDS):
        raise ValueError('Unknown scope fields')
    result = {}
    for field in RULE_FIELDS:
        items = rules.get(field, [])
        if not isinstance(items, list) or len(items) > 200:
            raise ValueError('Scope rules must be lists of at most 200 items')
        normalized = []
        for item in items:
            if not isinstance(item, str) or len(item) > 2048:
                raise ValueError('Invalid scope rule')
            if field == 'excluded_paths':
                if not item.startswith('/') or '?' in item or '#' in item:
                    raise ValueError('Excluded paths must be absolute paths')
                normalized.append(item)
            else:
                wildcard = item.startswith('*.')
                host = canonical_host(item[2:] if wildcard else item)
                normalized.append(('*.' if wildcard else '') + host)
        result[field] = sorted(set(normalized))
    return result


def domain_match(host, rule):
    if rule.startswith('*.'):
        return host.endswith('.' + rule[2:]) and host != rule[2:]
    return host == rule


def classify(url, program):
    try:
        parts = urlsplit(url)
        if parts.scheme not in ('https', 'http', 'ws', 'wss'):
            return 'UNKNOWN'
        if parts.username is not None or parts.password is not None:
            return 'UNKNOWN'
        host = canonical_host(parts.hostname or '')
        if parts.port is not None and not 1 <= parts.port <= 65535:
            return 'UNKNOWN'
        path = parts.path or '/'
        if '[REDACTED]' in path:
            return 'UNKNOWN'
        decoded = unquote(path)
        # Reject ambiguous encodings rather than assume router semantics.
        if ('%' in decoded or '\\' in decoded or '//' in decoded or ';' in decoded
                or any(p in ('.', '..') for p in decoded.split('/'))):
            return 'UNKNOWN'
        rules = validate_rules(program.rules)
    except ValueError:
        return 'UNKNOWN'
    if any(domain_match(host, d) for d in rules['excluded_domains']):
        return 'OUT_OF_SCOPE'
    for excluded in rules['excluded_paths']:
        prefix = unquote(excluded).rstrip('/')
        if decoded == prefix or decoded.startswith(prefix + '/'):
            return 'OUT_OF_SCOPE'
    if not (program.approved and program.authorization_source
            and program.authorized_at):
        return 'UNKNOWN'
    if any(domain_match(host, d) for d in rules['allowed_domains']):
        return 'IN_SCOPE'
    if any(host.endswith('.' + d.removeprefix('*.'))
           for d in rules['allowed_subdomains']):
        return 'IN_SCOPE'
    return 'UNKNOWN'


def authorize_active(*_args, **_kwargs):
    """There is deliberately no active-test executor in the passive MVP."""
    raise PermissionError('Active tests are disabled in this release')
