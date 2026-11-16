# -*- coding: utf_8 -*-
"""MobSF middleware."""
from django.middleware.gzip import GZipMiddleware

COMPRESSIBLE_TYPES = (
    'text/html',
    'text/plain',
    'text/css',
    'application/json',
    'application/javascript',
    'text/javascript',
)
# Pages that render long-lived secrets are left uncompressed (BREACH).
NO_COMPRESS_URLS = {'api_docs'}


class CompressionMiddleware(GZipMiddleware):
    """Gzip large text responses such as scan reports.

    Streaming responses (logcat, live API, file downloads) and
    binary content are passed through untouched.
    """

    def process_response(self, request, response):
        if response.streaming:
            return response
        ctype = response.get('Content-Type', '').split(';')[0].strip()
        if ctype.lower() not in COMPRESSIBLE_TYPES:
            return response
        match = getattr(request, 'resolver_match', None)
        if match and match.url_name in NO_COMPRESS_URLS:
            return response
        return super().process_response(request, response)
