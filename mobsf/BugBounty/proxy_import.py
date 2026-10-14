"""Bounded, passive import of Burp HTTP items; raw payloads are never retained."""

import base64
import re

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from django.conf import settings


def burp_items(data):
    """Convert Burp Save items XML to the existing sanitized HAR pipeline."""
    if len(data) > settings.BOUNTY_MAX_IMPORT_BYTES:
        raise ValueError('Capture exceeds maximum 2 MiB')
    try:
        root = ElementTree.fromstring(data, forbid_dtd=True)
    except (ElementTree.ParseError, DefusedXmlException) as exc:
        raise ValueError(
            'Invalid Burp items XML; DTDs and entities are forbidden',
        ) from exc
    if root.tag != 'items' or len(root) > 1000:
        raise ValueError('Expected Burp items XML with at most 1000 items')
    entries = []
    for item in root:
        if item.tag != 'item':
            raise ValueError('Invalid Burp item')
        request = item.find('request')
        headers = []
        if request is not None and request.text:
            text = request.text
            if request.get('base64') == 'true':
                try:
                    raw = base64.b64decode(''.join(text.split()), validate=True)
                except ValueError as exc:
                    raise ValueError('Invalid Burp base64 request') from exc
            else:
                raw = text.encode('utf-8')
            header_block = raw.split(b'\r\n\r\n', 1)[0]
            if len(header_block) > 65536:
                raise ValueError('Burp request headers exceed 64 KiB')
            for line in header_block.splitlines()[1:]:
                if not line or b':' not in line:
                    continue
                name = line.split(b':', 1)[0].decode('ascii', errors='strict')
                if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9a-zA-Z-]{1,200}", name):
                    raise ValueError('Invalid Burp HTTP header name')
                headers.append({'name': name, 'value': '[REDACTED]'})
                if len(headers) > 200:
                    raise ValueError('Burp request header limit exceeded')
        status = item.findtext('status', '')
        entries.append(
            {
                'request': {
                    'url': item.findtext('url', ''),
                    'method': item.findtext('method', ''),
                    'headers': headers,
                },
                'response': {'status': int(status) if status.isdigit() else None},
            },
        )
    return {'log': {'entries': entries}}
