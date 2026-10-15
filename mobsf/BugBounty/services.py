"""Import existing analysis, correlate evidence, and preserve review history."""
import ast
from datetime import timedelta
from hashlib import sha256
from html import unescape
import json

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from mobsf.BugBounty.discovery import discover, endpoint_record
from mobsf.BugBounty.models import (
    Analysis, Endpoint, Evidence, Finding, FindingEvent,
)
from mobsf.BugBounty.sanitization import redact_text, sanitize
from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid, StaticAnalyzerIOS


def unpack(value):
    if not value:
        return {}
    if not isinstance(value, str):
        return value
    if len(value.encode()) > settings.BOUNTY_MAX_IMPORT_BYTES:
        raise ValueError('Core result exceeds import size limit')
    try:
        return json.loads(value)
    except (json.JSONDecodeError, ValueError):
        try:
            return ast.literal_eval(value)
        except (ValueError, SyntaxError, RecursionError) as exc:
            raise ValueError('Invalid serialized core result') from exc


def add_evidence(finding, kind, source, content):
    raw = json.dumps(content, sort_keys=True, ensure_ascii=True)
    if len(raw.encode()) > settings.BOUNTY_MAX_IMPORT_BYTES:
        raise ValueError('Evidence exceeds size limit')
    digest = sha256(raw.encode()).hexdigest()
    safe = sanitize(content)
    evidence, _created = Evidence.objects.get_or_create(
        finding=finding, sha256=digest, source=redact_text(source)[:500],
        defaults={
            'kind': kind, 'content': safe,
            'expires_at': timezone.now() + timedelta(
                days=max(1, settings.BOUNTY_RETENTION_DAYS)),
        })
    return evidence


def add_finding(analysis, kind, identity, title, rationale, severity='info'):
    fingerprint = sha256((kind + '\n' + identity).encode()).hexdigest()
    finding, _created = Finding.objects.get_or_create(
        analysis=analysis, fingerprint=fingerprint,
        defaults={
            'kind': kind, 'title': redact_text(title)[:300],
            'rationale': redact_text(rationale), 'severity': severity,
        })
    return finding


def merge_endpoint(analysis, record, content=None):
    defaults = dict(record)
    fingerprint = defaults.pop('fingerprint')
    endpoint, created = Endpoint.objects.get_or_create(
        analysis=analysis, fingerprint=fingerprint, defaults=defaults)
    if not created:
        endpoint.sources = sorted(set(endpoint.sources + record['sources']))
        endpoint.observed = endpoint.observed or record['observed']
        endpoint.confidence = max(endpoint.confidence, record['confidence'])
        endpoint.methods = sorted(set(endpoint.methods + record['methods']))
        endpoint.method = endpoint.methods[0] if len(endpoint.methods) == 1 else ''
        endpoint.last_seen = timezone.now()
        endpoint.save()
    finding = add_finding(
        analysis, 'endpoint', fingerprint, 'Endpoint: ' + endpoint.host,
        'Resource reference; exposure alone does not establish a vulnerability.')
    finding.confidence = endpoint.confidence
    finding.save(update_fields=['confidence'])
    add_evidence(finding, 'http' if record['observed'] else 'source',
                 record['sources'][0], content or {
                     'url': endpoint.url, 'method': record['method'],
                     'observed': record['observed'],
    })
    return endpoint


def source_strings(value, source, depth=0):
    if depth > 12:
        raise ValueError('Core result nesting limit exceeded')
    if isinstance(value, str):
        yield value, source
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from source_strings(item, source + '/' + str(key), depth + 1)
    elif isinstance(value, list):
        for item in value:
            yield from source_strings(item, source, depth + 1)


@transaction.atomic
def import_core(program, checksum):
    core = StaticAnalyzerAndroid.objects.filter(MD5=checksum).first()
    platform = 'android'
    if core is None:
        core = StaticAnalyzerIOS.objects.filter(MD5=checksum).first()
        platform = 'ios'
    if core is None:
        raise ValueError('Complete an Android or iOS static analysis first')
    analysis, _created = Analysis.objects.get_or_create(
        program=program, checksum=checksum, defaults={
            'platform': platform,
            'package': redact_text(getattr(
                core, 'PACKAGE_NAME', getattr(core, 'BUNDLE_ID', '')))[:500],
            'version': redact_text(getattr(
                core, 'VERSION_NAME', getattr(core, 'APP_VERSION', '')))[:100],
        })
    urls = unpack(core.URLS)
    records = []
    if isinstance(urls, list):
        for item in urls:
            if isinstance(item, dict) and isinstance(item.get('urls'), list):
                for url in item['urls']:
                    if isinstance(url, str):
                        records.extend(discover(
                            url, unescape(str(item.get('path', 'core/URLS')))))
            elif isinstance(item, str):
                records.extend(discover(item, 'core/URLS'))
    for field in ('STRINGS', 'FIREBASE_URLS'):
        for text, source in source_strings(unpack(getattr(core, field)), field):
            records.extend(discover(text, source))
            if len(records) > 4000:
                raise ValueError('Endpoint limit exceeded (4000)')
    if len(records) > 4000:
        raise ValueError('Endpoint limit exceeded (4000)')
    for record in records:
        merge_endpoint(analysis, record)
    secrets = unpack(core.SECRETS)
    if isinstance(secrets, list):
        if len(secrets) > 1000:
            raise ValueError('Secret finding limit exceeded (1000)')
        for secret in secrets:
            if not isinstance(secret, str):
                continue
            finding = add_finding(
                analysis, 'potential_secret', secret,
                'Potential credential reference',
                'Core detector match; credential validity has not been tested.',
                'medium')
            # Unknown entropy matches are also fully masked.
            add_evidence(finding, 'secret', 'core/SECRETS',
                         {'classification': redact_text(secret.split(':')[0])
                          if ': ' in secret else 'Entropy heuristic',
                          'value': '[REDACTED]'})
    code = unpack(core.CODE_ANALYSIS)
    if isinstance(code, dict):
        if len(code) > 1000:
            raise ValueError('Static rule limit exceeded (1000)')
        for rule, finding_data in code.items():
            if not isinstance(finding_data, dict):
                continue
            metadata = finding_data.get('metadata', {})
            if not isinstance(metadata, dict):
                metadata = {}
            severity = metadata.get('severity', 'info')
            if severity not in dict(Finding.SEVERITIES):
                severity = 'info'
            finding = add_finding(
                analysis, 'static_rule', str(rule),
                metadata.get('description', str(rule)),
                'Static rule match; manual verification is required.', severity)
            add_evidence(finding, 'source', 'core/CODE_ANALYSIS/' + str(rule),
                         finding_data)
    return analysis


@transaction.atomic
def import_har(analysis, data):
    try:
        entries = data['log']['entries']
    except (TypeError, KeyError) as exc:
        raise ValueError('Expected HAR log.entries') from exc
    if not isinstance(entries, list) or len(entries) > 1000:
        raise ValueError('HAR entry limit exceeded (1000)')
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(
                entry.get('request'), dict):
            raise ValueError('Invalid HAR request')
        req = entry['request']
        if not isinstance(req.get('url'), str):
            raise ValueError('Invalid HAR URL')
        record = endpoint_record(req['url'], 'HAR', req.get('method', ''), True)
        # Parameter values and bodies are deliberately omitted from HAR storage.
        headers = req.get('headers', [])
        if not isinstance(headers, list) or len(headers) > 200:
            raise ValueError('Invalid HAR headers')
        safe_headers = {}
        for header in headers:
            if not isinstance(header, dict) or not isinstance(
                    header.get('name'), str):
                raise ValueError('Invalid HAR header')
            safe_headers[header['name']] = '[REDACTED]'
        response = entry.get('response', {})
        if not isinstance(response, dict):
            raise ValueError('Invalid HAR response')
        merge_endpoint(analysis, record, {
            'url': record['url'], 'method': record['method'],
            'headers': safe_headers, 'status': response.get('status'),
        })
    return len(entries)


@transaction.atomic
def review_finding(finding, actor, status, severity, note):
    finding = Finding.objects.select_for_update().get(pk=finding.pk)
    if status not in dict(Finding.STATES) or severity not in dict(
            Finding.SEVERITIES):
        raise ValueError('Invalid finding classification')
    if not note.strip():
        raise ValueError('A review justification is required')
    if status == 'CONFIRMED' and not finding.evidence.filter(
            expires_at__gt=timezone.now()).exists():
        raise ValueError('Confirmation requires retained evidence')
    FindingEvent.objects.create(
        finding=finding, actor=actor, previous_status=finding.status,
        status=status, note=redact_text(note))
    finding.status, finding.severity = status, severity
    finding.review_note = redact_text(note)
    finding.save()
    return finding
