#!/usr/bin/env python
# Copyright 2015 Google Inc. All Rights Reserved.
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


import httparchive
import httplib
import httpproxy
import threading
import unittest
import util


class MockCustomResponseHandler(object):
  def __init__(self, response):
    """
    Args:
      response: An instance of ArchivedHttpResponse that is returned for each
      request.
    """
    self._response = response

  def handle(self, request):
    del request
    return self._response


class MockHttpArchiveFetch(object):
  def __init__(self, response):
    """
    Args:
      response: An instance of ArchivedHttpResponse that is returned for each
      request.
    """
    self.is_record_mode = False
    self._response = response

  def __call__(self, request):
    del request # unused
    return self._response


class MockHttpArchiveHandler(httpproxy.HttpArchiveHandler):
  def handle_one_request(self):
    httpproxy.HttpArchiveHandler.handle_one_request(self)
    HttpProxyTest.HANDLED_REQUEST_COUNT += 1


class MockRules(object):
  def Find(self, unused_rule_type_name):  # pylint: disable=unused-argument
    return lambda unused_request, unused_response: None


class HttpProxyTest(unittest.TestCase):
  def setUp(self):
    self.has_proxy_server_bound_port = False
    self.has_proxy_server_started = False
    self.allow_generate_304 = False
    self.serve_response_by_http_archive = False

  def set_up_proxy_server(self, response):
    """
    Args:
      response: An instance of ArchivedHttpResponse that is returned for each
      request.
    """
    HttpProxyTest.HANDLED_REQUEST_COUNT = 0
    self.host = 'localhost'
    self.port = 8889
    custom_handlers = MockCustomResponseHandler(
        response if not self.serve_response_by_http_archive else None)
    rules = MockRules()
    http_archive_fetch = MockHttpArchiveFetch(
        response if self.serve_response_by_http_archive else None)
    self.proxy_server = httpproxy.HttpProxyServer(
        http_archive_fetch, custom_handlers, rules,
        host=self.host, port=self.port,
        allow_generate_304=self.allow_generate_304)
    self.proxy_server.RequestHandlerClass = MockHttpArchiveHandler
    self.has_proxy_server_bound_port = True

  def tear_down_proxy_server(self):
    if self.has_proxy_server_started:
      self.proxy_server.shutdown()
    if self.has_proxy_server_bound_port:
      self.proxy_server.server_close()

  def tearDown(self):
    self.tear_down_proxy_server()

  def serve_requests_forever(self):
    self.has_proxy_server_started = True
    self.proxy_server.serve_forever(poll_interval=0.01)

  # Tests that handle_one_request does not leak threads, and does not try to
  # re-handle connections that are finished.
  def test_handle_one_request_closes_connection(self):
    # By default, BaseHTTPServer.py treats all HTTP 1.1 requests as keep-alive.
    # Intentionally use HTTP 1.0 to prevent this behavior.
    response = httparchive.ArchivedHttpResponse(
        version=10, status=200, reason="OK",
        headers=[], response_data=["bat1"])
    self.set_up_proxy_server(response)
    t = threading.Thread(
        target=HttpProxyTest.serve_requests_forever, args=(self,))
    t.start()

    initial_thread_count = threading.activeCount()

    # Make a bunch of requests.
    request_count = 10
    for _ in range(request_count):
      conn = httplib.HTTPConnection('localhost', 8889, timeout=10)
      conn.request("GET", "/index.html")
      res = conn.getresponse().read()
      self.assertEqual(res, "bat1")
      conn.close()

    # Check to make sure that there is no leaked thread.
    util.WaitFor(lambda: threading.activeCount() == initial_thread_count, 2)

    self.assertEqual(request_count, HttpProxyTest.HANDLED_REQUEST_COUNT)


  # Tests that keep-alive header works.
  def test_keep_alive_header(self):
    response = httparchive.ArchivedHttpResponse(
        version=11, status=200, reason="OK",
        headers=[("Connection", "keep-alive")], response_data=["bat1"])
    self.set_up_proxy_server(response)
    t = threading.Thread(
        target=HttpProxyTest.serve_requests_forever, args=(self,))
    t.start()

    initial_thread_count = threading.activeCount()

    # Make a bunch of requests.
    request_count = 10
    connections = []
    for _ in range(request_count):
      conn = httplib.HTTPConnection('localhost', 8889, timeout=10)
      conn.request("GET", "/index.html", headers={"Connection": "keep-alive"})
      res = conn.getresponse().read()
      self.assertEqual(res, "bat1")
      connections.append(conn)

    # Repeat the same requests.
    for conn in connections:
      conn.request("GET", "/index.html", headers={"Connection": "keep-alive"})
      res = conn.getresponse().read()
      self.assertEqual(res, "bat1")

    # Check that the right number of requests have been handled.
    self.assertEqual(2 * request_count, HttpProxyTest.HANDLED_REQUEST_COUNT)

    # Check to make sure that exactly "request_count" new threads are active.
    self.assertEqual(
        threading.activeCount(), initial_thread_count + request_count)

    for conn in connections:
      conn.close()

    util.WaitFor(lambda: threading.activeCount() == initial_thread_count, 1)

  # Test that opening 400 simultaneous connections does not cause httpproxy to
  # hit a process fd limit. The default limit is 256 fds.
  def test_max_fd(self):
    response = httparchive.ArchivedHttpResponse(
        version=11, status=200, reason="OK",
        headers=[("Connection", "keep-alive")], response_data=["bat1"])
    self.set_up_proxy_server(response)
    t = threading.Thread(
        target=HttpProxyTest.serve_requests_forever, args=(self,))
    t.start()

    # Make a bunch of requests.
    request_count = 400
    connections = []
    for _ in range(request_count):
      conn = httplib.HTTPConnection('localhost', 8889, timeout=10)
      conn.request("GET", "/index.html", headers={"Connection": "keep-alive"})
      res = conn.getresponse().read()
      self.assertEqual(res, "bat1")
      connections.append(conn)

    # Check that the right number of requests have been handled.
    self.assertEqual(request_count, HttpProxyTest.HANDLED_REQUEST_COUNT)

    for conn in connections:
      conn.close()

  # Tests that conditional requests return 304.
  def test_generate_304(self):
    REQUEST_HEADERS = [
        {},
        {'If-Modified-Since': 'whatever'},
        {'If-None-Match': 'whatever yet again'}]
    RESPONSE_STATUSES = [200, 204, 304, 404]
    for allow_generate_304 in [False, True]:
      self.allow_generate_304 = allow_generate_304
      for serve_response_by_http_archive in [False, True]:
        self.serve_response_by_http_archive = serve_response_by_http_archive
        for response_status in RESPONSE_STATUSES:
          response = None
          if response_status != 404:
            response = httparchive.ArchivedHttpResponse(
                version=11, status=response_status, reason="OK", headers=[],
                response_data=["some content"])
          self.set_up_proxy_server(response)
          t = threading.Thread(
              target=HttpProxyTest.serve_requests_forever, args=(self,))
          t.start()
          for method in ['GET', 'HEAD', 'POST']:
            for headers in REQUEST_HEADERS:
              connection = httplib.HTTPConnection('localhost', 8889, timeout=10)
              connection.request(method, "/index.html", headers=headers)
              response = connection.getresponse()
              connection.close()
              if (allow_generate_304 and
                  serve_response_by_http_archive and
                  method in ['GET', 'HEAD'] and
                  headers and
                  response_status == 200):
                self.assertEqual(304, response.status)
                self.assertEqual('', response.read())
              else:
                self.assertEqual(response_status, response.status)
          self.tear_down_proxy_server()


if __name__ == '__main__':
  unittest.main()
