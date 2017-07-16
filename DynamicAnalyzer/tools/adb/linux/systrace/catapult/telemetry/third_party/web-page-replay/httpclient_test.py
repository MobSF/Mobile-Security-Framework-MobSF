#!/usr/bin/env python
# Copyright 2012 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock
import unittest

import datetime
import dnsproxy
import httparchive
import httpclient
import platformsettings
import script_injector
import test_utils


class RealHttpFetchTest(unittest.TestCase):

  # Initialize test data
  CONTENT_TYPE = 'content-type: image/x-icon'
  COOKIE_1 = ('Set-Cookie: GMAIL_IMP=EXPIRED; '
              'Expires=Thu, 12-Jul-2012 22:41:22 GMT; '
              'Path=/mail; Secure')
  COOKIE_2 = ('Set-Cookie: GMAIL_STAT_205a=EXPIRED; '
              'Expires=Thu, 12-Jul-2012 22:42:24 GMT; '
              'Path=/mail; Secure')
  FIRST_LINE = 'fake-header: first line'
  SECOND_LINE = ' second line'
  THIRD_LINE = '\tthird line'
  BAD_HEADER = 'this is a bad header'

  def test__GetHeaderNameValueBasic(self):
    """Test _GetHeaderNameValue with normal header."""

    real_http_fetch = httpclient.RealHttpFetch
    name_value = real_http_fetch._GetHeaderNameValue(self.CONTENT_TYPE)
    self.assertEqual(name_value, ('content-type', 'image/x-icon'))

  def test__GetHeaderNameValueLowercasesName(self):
    """_GetHeaderNameValue lowercases header name."""

    real_http_fetch = httpclient.RealHttpFetch
    header = 'X-Google-Gfe-Backend-Request-Info: eid=1KMAUMeiK4eMiAL52YyMBg'
    expected = ('x-google-gfe-backend-request-info',
                'eid=1KMAUMeiK4eMiAL52YyMBg')
    name_value = real_http_fetch._GetHeaderNameValue(header)
    self.assertEqual(name_value, expected)

  def test__GetHeaderNameValueBadLineGivesNone(self):
    """_GetHeaderNameValue returns None for a header in wrong format."""

    real_http_fetch = httpclient.RealHttpFetch
    name_value = real_http_fetch._GetHeaderNameValue(self.BAD_HEADER)
    self.assertIsNone(name_value)

  def test__ToTuplesBasic(self):
    """Test _ToTuples with normal input."""

    real_http_fetch = httpclient.RealHttpFetch
    headers = [self.CONTENT_TYPE, self.COOKIE_1, self.FIRST_LINE]
    result = real_http_fetch._ToTuples(headers)
    expected = [('content-type', 'image/x-icon'),
                ('set-cookie', self.COOKIE_1[12:]),
                ('fake-header', 'first line')]
    self.assertEqual(result, expected)

  def test__ToTuplesMultipleHeadersWithSameName(self):
    """Test mulitple headers with the same name."""

    real_http_fetch = httpclient.RealHttpFetch
    headers = [self.CONTENT_TYPE, self.COOKIE_1, self.COOKIE_2, self.FIRST_LINE]
    result = real_http_fetch._ToTuples(headers)
    expected = [('content-type', 'image/x-icon'),
                ('set-cookie', self.COOKIE_1[12:]),
                ('set-cookie', self.COOKIE_2[12:]),
                ('fake-header', 'first line')]
    self.assertEqual(result, expected)

  def test__ToTuplesAppendsContinuationLine(self):
    """Test continuation line is handled."""

    real_http_fetch = httpclient.RealHttpFetch
    headers = [self.CONTENT_TYPE, self.COOKIE_1, self.FIRST_LINE,
               self.SECOND_LINE, self.THIRD_LINE]
    result = real_http_fetch._ToTuples(headers)
    expected = [('content-type', 'image/x-icon'),
                ('set-cookie', self.COOKIE_1[12:]),
                ('fake-header', 'first line\n second line\n third line')]
    self.assertEqual(result, expected)

  def test__ToTuplesIgnoresBadHeader(self):
    """Test bad header is ignored."""

    real_http_fetch = httpclient.RealHttpFetch
    bad_headers = [self.CONTENT_TYPE, self.BAD_HEADER, self.COOKIE_1]
    expected = [('content-type', 'image/x-icon'),
                ('set-cookie', self.COOKIE_1[12:])]
    result = real_http_fetch._ToTuples(bad_headers)
    self.assertEqual(result, expected)

  def test__ToTuplesIgnoresMisplacedContinuationLine(self):
    """Test misplaced continuation line is ignored."""

    real_http_fetch = httpclient.RealHttpFetch
    misplaced_headers = [self.THIRD_LINE, self.CONTENT_TYPE,
                         self.COOKIE_1, self.FIRST_LINE, self.SECOND_LINE]
    result = real_http_fetch._ToTuples(misplaced_headers)
    expected = [('content-type', 'image/x-icon'),
                ('set-cookie', self.COOKIE_1[12:]),
                ('fake-header', 'first line\n second line')]
    self.assertEqual(result, expected)


class RealHttpFetchGetConnectionTest(unittest.TestCase):
  """Test that a connection is made with request IP/port or proxy IP/port."""

  def setUp(self):
    def real_dns_lookup(host):
      return {
          'example.com': '127.127.127.127',
          'proxy.com': '2.2.2.2',
          }[host]
    self.fetch = httpclient.RealHttpFetch(real_dns_lookup)
    self.https_proxy = None
    self.http_proxy = None
    def get_proxy(is_ssl):
      return self.https_proxy if is_ssl else self.http_proxy
    self.fetch._get_system_proxy = get_proxy

  def set_http_proxy(self, host, port):
    self.http_proxy = platformsettings.SystemProxy(host, port)

  def set_https_proxy(self, host, port):
    self.https_proxy = platformsettings.SystemProxy(host, port)

  def test_get_connection_without_proxy_connects_to_host_ip(self):
    """HTTP connection with no proxy connects to host IP."""
    self.set_http_proxy(host=None, port=None)
    connection = self.fetch._get_connection('example.com', None, is_ssl=False)
    self.assertEqual('127.127.127.127', connection.host)
    self.assertEqual(80, connection.port)  # default HTTP port

  def test_get_connection_without_proxy_uses_nondefault_request_port(self):
    """HTTP connection with no proxy connects with request port."""
    self.set_https_proxy(host=None, port=None)
    connection = self.fetch._get_connection('example.com', 8888, is_ssl=False)
    self.assertEqual('127.127.127.127', connection.host)
    self.assertEqual(8888, connection.port)  # request HTTP port

  def test_get_connection_with_proxy_uses_proxy_port(self):
    """HTTP connection with proxy connects used proxy port."""
    self.set_http_proxy(host='proxy.com', port=None)
    connection = self.fetch._get_connection('example.com', 8888, is_ssl=False)
    self.assertEqual('2.2.2.2', connection.host)  # proxy IP
    self.assertEqual(80, connection.port)  # proxy port (default HTTP)

  def test_ssl_get_connection_without_proxy_connects_to_host_ip(self):
    """HTTPS (SSL) connection with no proxy connects to host IP."""
    self.set_https_proxy(host=None, port=None)
    connection = self.fetch._get_connection('example.com', None, is_ssl=True)
    self.assertEqual('127.127.127.127', connection.host)
    self.assertEqual(443, connection.port)  # default SSL port

  def test_ssl_get_connection_with_proxy_connects_to_proxy_ip(self):
    """HTTPS (SSL) connection with proxy connects to proxy IP."""
    self.set_https_proxy(host='proxy.com', port=8443)
    connection = self.fetch._get_connection('example.com', None, is_ssl=True)
    self.assertEqual('2.2.2.2', connection.host)  # proxy IP
    self.assertEqual(8443, connection.port)  # SSL proxy port

  def test_ssl_get_connection_with_proxy_tunnels_to_host(self):
    """HTTPS (SSL) connection with proxy tunnels to target host."""
    self.set_https_proxy(host='proxy.com', port=8443)
    connection = self.fetch._get_connection('example.com', 9443, is_ssl=True)
    self.assertEqual('example.com', connection._tunnel_host)  # host name
    self.assertEqual(9443, connection._tunnel_port)  # host port


class ActualNetworkFetchTest(test_utils.RealNetworkFetchTest):

  def testFetchNonSSLRequest(self):
    real_dns_lookup = dnsproxy.RealDnsLookup(
        name_servers=[platformsettings.get_original_primary_nameserver()],
        dns_forwarding=False, proxy_host='127.0.0.1', proxy_port=5353)
    fetch = httpclient.RealHttpFetch(real_dns_lookup)
    request = httparchive.ArchivedHttpRequest(
        command='GET', host='google.com', full_path='/search?q=dogs',
        request_body=None, headers={}, is_ssl=False)
    response = fetch(request)
    self.assertIsNotNone(response)

  def testFetchSSLRequest(self):
    real_dns_lookup = dnsproxy.RealDnsLookup(
        name_servers=[platformsettings.get_original_primary_nameserver()],
        dns_forwarding=False, proxy_host='127.0.0.1', proxy_port=5353)
    fetch = httpclient.RealHttpFetch(real_dns_lookup)
    request = httparchive.ArchivedHttpRequest(
        command='GET', host='google.com', full_path='/search?q=dogs',
        request_body=None, headers={}, is_ssl=True)
    response = fetch(request)
    self.assertIsNotNone(response)


class HttpArchiveFetchTest(unittest.TestCase):

  TEST_REQUEST_TIME = datetime.datetime(2016, 11, 17, 1, 2, 3, 456)

  def createTestResponse(self):
    return httparchive.ArchivedHttpResponse(
        11, 200, 'OK', [('content-type', 'text/html')],
        ['<body>test</body>'],
        request_time=HttpArchiveFetchTest.TEST_REQUEST_TIME)

  def checkTestResponse(self, actual_response, archive, request):
    self.assertEqual(actual_response, archive[request])
    self.assertEqual(['<body>test</body>'], actual_response.response_data)
    self.assertEqual(HttpArchiveFetchTest.TEST_REQUEST_TIME,
                     actual_response.request_time)

  @staticmethod
  def dummy_injector(_):
    return '<body>test</body>'


class RecordHttpArchiveFetchTest(HttpArchiveFetchTest):

  @mock.patch('httpclient.RealHttpFetch')
  def testFetch(self, real_http_fetch):
    http_fetch_instance = real_http_fetch.return_value
    response = self.createTestResponse()
    http_fetch_instance.return_value = response
    archive = httparchive.HttpArchive()
    fetch = httpclient.RecordHttpArchiveFetch(archive, self.dummy_injector)
    request = httparchive.ArchivedHttpRequest(
        'GET', 'www.test.com', '/', None, {})
    self.checkTestResponse(fetch(request), archive, request)


class ReplayHttpArchiveFetchTest(HttpArchiveFetchTest):

  def testFetch(self):
    request = httparchive.ArchivedHttpRequest(
        'GET', 'www.test.com', '/', None, {})
    response = self.createTestResponse()
    archive = httparchive.HttpArchive()
    archive[request] = response
    fetch = httpclient.ReplayHttpArchiveFetch(
        archive, None, self.dummy_injector)
    self.checkTestResponse(fetch(request), archive, request)

  @mock.patch('script_injector.util.resource_string')
  @mock.patch('script_injector.util.resource_exists')
  @mock.patch('script_injector.os.path.exists')
  def testInjectedDate(self, os_path, util_exists, util_resource_string):
    os_path.return_value = False
    util_exists.return_value = True
    util_resource_string.return_value = \
        ["""var time_seed={}""".format(script_injector.TIME_SEED_MARKER)]
    request = httparchive.ArchivedHttpRequest(
        'GET', 'www.test.com', '/', None, {})
    response = self.createTestResponse()
    archive = httparchive.HttpArchive()
    archive[request] = response

    fetch = httpclient.ReplayHttpArchiveFetch(
        archive, None, script_injector.GetScriptInjector("time_script.js"))
    self.assertEqual(
        ['<script>var time_seed=1479344523000</script><body>test</body>'],
        fetch(request).response_data)


if __name__ == '__main__':
  unittest.main()
