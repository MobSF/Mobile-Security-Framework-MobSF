# -*- coding: utf_8 -*-
"""Tests for MobSF middleware."""
import gzip

from django.http import HttpResponse, StreamingHttpResponse
from django.test import RequestFactory, SimpleTestCase
from django.urls import ResolverMatch

from mobsf.MobSF.middleware import CompressionMiddleware

BODY = b'<html>' + b'report row\n' * 500 + b'</html>'


class CompressionMiddlewareTests(SimpleTestCase):

    def setUp(self):
        self.factory = RequestFactory()

    def _run(self, response, url_name='static_analyzer'):
        request = self.factory.get('/', HTTP_ACCEPT_ENCODING='gzip')
        request.resolver_match = ResolverMatch(
            lambda r: r, (), {}, url_name=url_name)
        middleware = CompressionMiddleware(lambda r: response)
        return middleware(request)

    def test_html_is_compressed(self):
        resp = self._run(HttpResponse(BODY, content_type='text/html'))
        self.assertEqual(resp['Content-Encoding'], 'gzip')
        self.assertEqual(gzip.decompress(resp.content), BODY)

    def test_json_is_compressed(self):
        resp = self._run(HttpResponse(
            BODY, content_type='application/json; charset=utf-8'))
        self.assertEqual(resp['Content-Encoding'], 'gzip')

    def test_binary_is_not_compressed(self):
        resp = self._run(HttpResponse(
            BODY, content_type='application/octet-stream'))
        self.assertFalse(resp.has_header('Content-Encoding'))
        self.assertEqual(resp.content, BODY)

    def test_streaming_is_not_compressed(self):
        resp = self._run(StreamingHttpResponse(
            iter([BODY]), content_type='text/event-stream'))
        self.assertFalse(resp.has_header('Content-Encoding'))
        self.assertEqual(b''.join(resp.streaming_content), BODY)

    def test_streaming_html_is_not_compressed(self):
        resp = self._run(StreamingHttpResponse(
            iter([BODY]), content_type='text/html'))
        self.assertFalse(resp.has_header('Content-Encoding'))

    def test_api_docs_is_not_compressed(self):
        resp = self._run(
            HttpResponse(BODY, content_type='text/html'),
            url_name='api_docs')
        self.assertFalse(resp.has_header('Content-Encoding'))
