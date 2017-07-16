#!/usr/bin/env python
# Copyright 2010 Google Inc. All Rights Reserved.
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

import BaseHTTPServer
import certutils
import collections
import errno
import logging
import socket
import SocketServer
import ssl
import sys
import time
import urlparse

import daemonserver
import httparchive
import platformsettings
import proxyshaper
import sslproxy

def _HandleSSLCertificateError():
  """
  This method is intended to be called from
  BaseHTTPServer.HTTPServer.handle_error().
  """
  exc_type, exc_value, exc_traceback = sys.exc_info()
  if isinstance(exc_value, ssl.SSLError):
    return

  raise


class HttpProxyError(Exception):
  """Module catch-all error."""
  pass


class HttpProxyServerError(HttpProxyError):
  """Raised for errors like 'Address already in use'."""
  pass


class HttpArchiveHandler(BaseHTTPServer.BaseHTTPRequestHandler):
  protocol_version = 'HTTP/1.1'  # override BaseHTTPServer setting

  # Since we do lots of small wfile.write() calls, turn on buffering.
  wbufsize = -1  # override StreamRequestHandler (a base class) setting

  def setup(self):
    """Override StreamRequestHandler method."""
    BaseHTTPServer.BaseHTTPRequestHandler.setup(self)
    if self.server.traffic_shaping_up_bps:
      self.rfile = proxyshaper.RateLimitedFile(
          self.server.get_active_request_count, self.rfile,
          self.server.traffic_shaping_up_bps)
    if self.server.traffic_shaping_down_bps:
      self.wfile = proxyshaper.RateLimitedFile(
          self.server.get_active_request_count, self.wfile,
          self.server.traffic_shaping_down_bps)

  # Make request handler logging match our logging format.
  def log_request(self, code='-', size='-'):
    pass

  def log_error(self, format, *args):  # pylint:disable=redefined-builtin
    logging.error(format, *args)

  def log_message(self, format, *args):  # pylint:disable=redefined-builtin
    logging.info(format, *args)

  def read_request_body(self):
    request_body = None
    length = int(self.headers.get('content-length', 0)) or None
    if length:
      request_body = self.rfile.read(length)
    return request_body

  def get_header_dict(self):
    return dict(self.headers.items())

  def get_archived_http_request(self):
    host = self.headers.get('host')
    if host is None:
      logging.error('Request without host header')
      return None

    parsed = urlparse.urlparse(self.path)
    params = ';%s' % parsed.params if parsed.params else ''
    query = '?%s' % parsed.query if parsed.query else ''
    fragment = '#%s' % parsed.fragment if parsed.fragment else ''
    full_path = '%s%s%s%s' % (parsed.path, params, query, fragment)

    StubRequest = collections.namedtuple('StubRequest', ('host', 'full_path'))
    request, response = StubRequest(host, full_path), None

    self.server.log_url(request, response)

    return httparchive.ArchivedHttpRequest(
        self.command,
        host,
        full_path,
        self.read_request_body(),
        self.get_header_dict(),
        self.server.is_ssl)

  def send_archived_http_response(self, response):
    try:
      # We need to set the server name before we start the response.
      is_chunked = response.is_chunked()
      has_content_length = response.get_header('content-length') is not None
      self.server_version = response.get_header('server', 'WebPageReplay')
      self.sys_version = ''

      if response.version == 10:
        self.protocol_version = 'HTTP/1.0'

      # If we don't have chunked encoding and there is no content length,
      # we need to manually compute the content-length.
      if not is_chunked and not has_content_length:
        content_length = sum(len(c) for c in response.response_data)
        response.headers.append(('content-length', str(content_length)))

      is_replay = not self.server.http_archive_fetch.is_record_mode
      if is_replay and self.server.traffic_shaping_delay_ms:
        logging.debug('Using round trip delay: %sms',
                      self.server.traffic_shaping_delay_ms)
        time.sleep(self.server.traffic_shaping_delay_ms / 1000.0)
      if is_replay and self.server.use_delays:
        logging.debug('Using delays (ms): %s', response.delays)
        time.sleep(response.delays['headers'] / 1000.0)
        delays = response.delays['data']
      else:
        delays = [0] * len(response.response_data)
      self.send_response(response.status, response.reason)
      # TODO(mbelshe): This is lame - each write is a packet!
      for header, value in response.headers:
        if header in ('last-modified', 'expires'):
          self.send_header(header, response.update_date(value))
        elif header not in ('date', 'server'):
          self.send_header(header, value)
      self.end_headers()

      for chunk, delay in zip(response.response_data, delays):
        if delay:
          self.wfile.flush()
          time.sleep(delay / 1000.0)
        if is_chunked:
          # Write chunk length (hex) and data (e.g. "A\r\nTESSELATED\r\n").
          self.wfile.write('%x\r\n%s\r\n' % (len(chunk), chunk))
        else:
          self.wfile.write(chunk)
      if is_chunked:
        self.wfile.write('0\r\n\r\n')  # write final, zero-length chunk.
      self.wfile.flush()

      # TODO(mbelshe): This connection close doesn't seem to work.
      if response.version == 10:
        self.close_connection = 1

    except Exception, e:
      logging.error('Error sending response for %s%s: %s',
                    self.headers['host'], self.path, e)

  def handle_one_request(self):
    """Handle a single HTTP request.

    This method overrides a method from BaseHTTPRequestHandler. When this
    method returns, it must leave self.close_connection in the correct state.
    If this method raises an exception, the state of self.close_connection
    doesn't matter.
    """
    try:
      self.raw_requestline = self.rfile.readline(65537)
      self.do_parse_and_handle_one_request()
    except socket.timeout, e:
      # A read or a write timed out.  Discard this connection
      self.log_error('Request timed out: %r', e)
      self.close_connection = 1
      return
    except ssl.SSLError:
      # There is insufficient information passed up the stack from OpenSSL to
      # determine the true cause of the SSL error. This almost always happens
      # because the client refuses to accept the self-signed certs of
      # WebPageReplay.
      self.close_connection = 1
      return
    except socket.error, e:
      # Connection reset errors happen all the time due to the browser closing
      # without terminating the connection properly.  They can be safely
      # ignored.
      if e[0] == errno.ECONNRESET:
        self.close_connection = 1
        return
      raise


  def do_parse_and_handle_one_request(self):
    start_time = time.time()
    self.server.num_active_requests += 1
    request = None
    try:
      if len(self.raw_requestline) > 65536:
        self.requestline = ''
        self.request_version = ''
        self.command = ''
        self.send_error(414)
        self.close_connection = 0
        return
      if not self.raw_requestline:
        # This indicates that the socket has been closed by the client.
        self.close_connection = 1
        return

      # self.parse_request() sets self.close_connection. There is no need to
      # set the property after the method is executed, unless custom behavior
      # is desired.
      if not self.parse_request():
        # An error code has been sent, just exit.
        return

      try:
        response = None
        request = self.get_archived_http_request()

        if request is None:
          self.send_error(500)
          return
        response = self.server.custom_handlers.handle(request)
        if not response:
          response = self.server.http_archive_fetch(request)
          if (response and response.status == 200 and
              self.server.allow_generate_304 and
              request.command in set(['GET', 'HEAD']) and
              (request.headers.get('if-modified-since', None) or
               request.headers.get('if-none-match', None))):
            # The WPR archive never get modified since it is not being recorded.
            response = httparchive.create_response(
                status=304, headers=response.headers)
        if response:
          self.send_archived_http_response(response)
        else:
          self.send_error(404)
      finally:
        self.wfile.flush()  # Actually send the response if not already done.
    finally:
      request_time_ms = (time.time() - start_time) * 1000.0
      self.server.total_request_time += request_time_ms
      if request:
        if response:
          logging.debug('Served: %s (%dms)', request, request_time_ms)
        else:
          logging.warning('Failed to find response for: %s (%dms)',
                          request, request_time_ms)
      self.server.num_active_requests -= 1

  def send_error(self, status, body=None):
    """Override the default send error with a version that doesn't unnecessarily
    close the connection.
    """
    response = httparchive.create_response(status, body=body)
    self.send_archived_http_response(response)


class HttpProxyServer(SocketServer.ThreadingMixIn,
                      BaseHTTPServer.HTTPServer,
                      daemonserver.DaemonServer):
  HANDLER = HttpArchiveHandler

  # Increase the request queue size. The default value, 5, is set in
  # SocketServer.TCPServer (the parent of BaseHTTPServer.HTTPServer).
  # Since we're intercepting many domains through this single server,
  # it is quite possible to get more than 5 concurrent requests.
  request_queue_size = 256

  # The number of simultaneous connections that the HTTP server supports. This
  # is primarily limited by system limits such as RLIMIT_NOFILE.
  connection_limit = 500

  # Allow sockets to be reused. See
  # http://svn.python.org/projects/python/trunk/Lib/SocketServer.py for more
  # details.
  allow_reuse_address = True

  # Don't prevent python from exiting when there is thread activity.
  daemon_threads = True

  def __init__(self, http_archive_fetch, custom_handlers, rules,
               host='localhost', port=80, use_delays=False, is_ssl=False,
               protocol='HTTP', allow_generate_304=False,
               down_bandwidth='0', up_bandwidth='0', delay_ms='0'):
    """Start HTTP server.

    Args:
      rules: a rule_parser Rules.
      host: a host string (name or IP) for the web proxy.
      port: a port string (e.g. '80') for the web proxy.
      use_delays: if True, add response data delays during replay.
      is_ssl: True iff proxy is using SSL.
      up_bandwidth: Upload bandwidth
      down_bandwidth: Download bandwidth
           Bandwidths measured in [K|M]{bit/s|Byte/s}. '0' means unlimited.
      delay_ms: Propagation delay in milliseconds. '0' means no delay.
    """
    if platformsettings.SupportsFdLimitControl():
      # BaseHTTPServer opens a new thread and two fds for each connection.
      # Check that the process can open at least 1000 fds.
      soft_limit, hard_limit = platformsettings.GetFdLimit()
      # Add some wiggle room since there are probably fds not associated with
      # connections.
      wiggle_room = 100
      desired_limit = 2 * HttpProxyServer.connection_limit + wiggle_room
      if soft_limit < desired_limit:
        assert desired_limit <= hard_limit, (
            'The hard limit for number of open files per process is %s which '
            'is lower than the desired limit of %s.' %
            (hard_limit, desired_limit))
        platformsettings.AdjustFdLimit(desired_limit, hard_limit)

    try:
      BaseHTTPServer.HTTPServer.__init__(self, (host, port), self.HANDLER)
    except Exception, e:
      raise HttpProxyServerError('Could not start HTTPServer on port %d: %s' %
                                 (port, e))
    self.http_archive_fetch = http_archive_fetch
    self.custom_handlers = custom_handlers
    self.use_delays = use_delays
    self.is_ssl = is_ssl
    self.traffic_shaping_down_bps = proxyshaper.GetBitsPerSecond(down_bandwidth)
    self.traffic_shaping_up_bps = proxyshaper.GetBitsPerSecond(up_bandwidth)
    self.traffic_shaping_delay_ms = int(delay_ms)
    self.num_active_requests = 0
    self.num_active_connections = 0
    self.total_request_time = 0
    self.protocol = protocol
    self.allow_generate_304 = allow_generate_304
    self.log_url = rules.Find('log_url')

    # Note: This message may be scraped. Do not change it.
    logging.warning(
        '%s server started on %s:%d' % (self.protocol, self.server_address[0],
                                        self.server_address[1]))

  def cleanup(self):
    try:
      self.shutdown()
      self.server_close()
    except KeyboardInterrupt:
      pass
    logging.info('Stopped %s server. Total time processing requests: %dms',
                 self.protocol, self.total_request_time)

  def get_active_request_count(self):
    return self.num_active_requests

  def get_request(self):
    self.num_active_connections += 1
    if self.num_active_connections >= HttpProxyServer.connection_limit:
      logging.error(
          'Number of active connections (%s) surpasses the '
          'supported limit of %s.' %
          (self.num_active_connections, HttpProxyServer.connection_limit))
    return BaseHTTPServer.HTTPServer.get_request(self)

  def close_request(self, request):
    BaseHTTPServer.HTTPServer.close_request(self, request)
    self.num_active_connections -= 1


class HttpsProxyServer(HttpProxyServer):
  """SSL server that generates certs for each host."""

  def __init__(self, http_archive_fetch, custom_handlers, rules,
               https_root_ca_cert_path, **kwargs):
    self.ca_cert_path = https_root_ca_cert_path
    self.HANDLER = sslproxy.wrap_handler(HttpArchiveHandler)
    HttpProxyServer.__init__(self, http_archive_fetch, custom_handlers, rules,
                             is_ssl=True, protocol='HTTPS', **kwargs)
    with open(self.ca_cert_path, 'r') as cert_file:
      self._ca_cert_str = cert_file.read()
    self._host_to_cert_map = {}
    self._server_cert_to_cert_map = {}

  def cleanup(self):
    try:
      self.shutdown()
      self.server_close()
    except KeyboardInterrupt:
      pass

  def get_certificate(self, host):
    if host in self._host_to_cert_map:
      return self._host_to_cert_map[host]

    server_cert = self.http_archive_fetch.http_archive.get_server_cert(host)
    if server_cert in self._server_cert_to_cert_map:
      cert = self._server_cert_to_cert_map[server_cert]
      self._host_to_cert_map[host] = cert
      return cert

    cert = certutils.generate_cert(self._ca_cert_str, server_cert, host)
    self._server_cert_to_cert_map[server_cert] = cert
    self._host_to_cert_map[host] = cert
    return cert

  def handle_error(self, request, client_address):
    _HandleSSLCertificateError()


class SingleCertHttpsProxyServer(HttpProxyServer):
  """SSL server."""

  def __init__(self, http_archive_fetch, custom_handlers, rules,
               https_root_ca_cert_path, **kwargs):
    HttpProxyServer.__init__(self, http_archive_fetch, custom_handlers, rules,
                             is_ssl=True, protocol='HTTPS', **kwargs)
    self.socket = ssl.wrap_socket(
        self.socket, certfile=https_root_ca_cert_path, server_side=True,
        do_handshake_on_connect=False)
    # Ancestor class, DaemonServer, calls serve_forever() during its __init__.

  def handle_error(self, request, client_address):
    _HandleSSLCertificateError()


class HttpToHttpsProxyServer(HttpProxyServer):
  """Listens for HTTP requests but sends them to the target as HTTPS requests"""

  def __init__(self, http_archive_fetch, custom_handlers, rules, **kwargs):
    HttpProxyServer.__init__(self, http_archive_fetch, custom_handlers, rules,
                             is_ssl=True, protocol='HTTP-to-HTTPS', **kwargs)

  def handle_error(self, request, client_address):
    _HandleSSLCertificateError()
