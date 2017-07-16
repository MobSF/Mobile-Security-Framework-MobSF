# Copyright 2014 Google Inc. All Rights Reserved.
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

"""Test routines to generate dummy certificates."""

import BaseHTTPServer
import shutil
import signal
import socket
import tempfile
import threading
import time
import unittest

import certutils
import sslproxy


class Client(object):

  def __init__(self, ca_cert_path, verify_cb, port, host_name='foo.com',
               host='localhost'):
    self.host_name = host_name
    self.verify_cb = verify_cb
    self.ca_cert_path = ca_cert_path
    self.port = port
    self.host_name = host_name
    self.host = host
    self.connection = None

  def run_request(self):
    context = certutils.get_ssl_context()
    context.set_verify(certutils.VERIFY_PEER, self.verify_cb)  # Demand a cert
    context.use_certificate_file(self.ca_cert_path)
    context.load_verify_locations(self.ca_cert_path)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.connection = certutils.get_ssl_connection(context, s)
    self.connection.connect((self.host, self.port))
    self.connection.set_tlsext_host_name(self.host_name)

    try:
      self.connection.send('\r\n\r\n')
    finally:
      self.connection.shutdown()
      self.connection.close()


class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
  protocol_version = 'HTTP/1.1'  # override BaseHTTPServer setting

  def handle_one_request(self):
    """Handle a single HTTP request."""
    self.raw_requestline = self.rfile.readline(65537)


class WrappedErrorHandler(Handler):
  """Wraps handler to verify expected sslproxy errors are being raised."""

  def setup(self):
    Handler.setup(self)
    try:
      sslproxy._SetUpUsingDummyCert(self)
    except certutils.Error:
      self.server.error_function = certutils.Error

  def finish(self):
    Handler.finish(self)
    self.connection.shutdown()
    self.connection.close()


class DummyArchive(object):

  def __init__(self):
    pass


class DummyFetch(object):

  def __init__(self):
    self.http_archive = DummyArchive()


class Server(BaseHTTPServer.HTTPServer):
  """SSL server."""

  def __init__(self, ca_cert_path, use_error_handler=False, port=0,
               host='localhost'):
    self.ca_cert_path = ca_cert_path
    with open(ca_cert_path, 'r') as ca_file:
      self.ca_cert_str = ca_file.read()
    self.http_archive_fetch = DummyFetch()
    if use_error_handler:
      self.HANDLER = WrappedErrorHandler
    else:
      self.HANDLER = sslproxy.wrap_handler(Handler)
    try:
      BaseHTTPServer.HTTPServer.__init__(self, (host, port), self.HANDLER)
    except Exception, e:
      raise RuntimeError('Could not start HTTPSServer on port %d: %s'
                         % (port, e))

  def __enter__(self):
    thread = threading.Thread(target=self.serve_forever)
    thread.daemon = True
    thread.start()
    return self

  def cleanup(self):
    try:
      self.shutdown()
    except KeyboardInterrupt:
      pass

  def __exit__(self, type_, value_, traceback_):
    self.cleanup()

  def get_certificate(self, host):
    return certutils.generate_cert(self.ca_cert_str, '', host)


class TestClient(unittest.TestCase):
  _temp_dir = None

  def setUp(self):
    self._temp_dir = tempfile.mkdtemp(prefix='sslproxy_', dir='/tmp')
    self.ca_cert_path = self._temp_dir + 'testCA.pem'
    self.cert_path = self._temp_dir + 'testCA-cert.cer'
    self.wrong_ca_cert_path = self._temp_dir + 'wrong.pem'
    self.wrong_cert_path = self._temp_dir + 'wrong-cert.cer'

    # Write both pem and cer files for certificates
    certutils.write_dummy_ca_cert(*certutils.generate_dummy_ca_cert(),
                                  cert_path=self.ca_cert_path)
    certutils.write_dummy_ca_cert(*certutils.generate_dummy_ca_cert(),
                                  cert_path=self.ca_cert_path)

  def tearDown(self):
    if self._temp_dir:
      shutil.rmtree(self._temp_dir)

  def verify_cb(self, conn, cert, errnum, depth, ok):
    """A callback that verifies the certificate authentication worked.

    Args:
      conn: Connection object
      cert: x509 object
      errnum: possible error number
      depth: error depth
      ok: 1 if the authentication worked 0 if it didnt.
    Returns:
      1 or 0 depending on if the verification worked
    """
    self.assertFalse(cert.has_expired())
    self.assertGreater(time.strftime('%Y%m%d%H%M%SZ', time.gmtime()),
                       cert.get_notBefore())
    return ok

  def test_no_host(self):
    with Server(self.ca_cert_path) as server:
      c = Client(self.cert_path, self.verify_cb, server.server_port, '')
      self.assertRaises(certutils.Error, c.run_request)

  def test_client_connection(self):
    with Server(self.ca_cert_path) as server:
      c = Client(self.cert_path, self.verify_cb, server.server_port, 'foo.com')
      c.run_request()

      c = Client(self.cert_path, self.verify_cb, server.server_port,
                 'random.host')
      c.run_request()

  def test_wrong_cert(self):
    with Server(self.ca_cert_path, True) as server:
      c = Client(self.wrong_cert_path, self.verify_cb, server.server_port,
                 'foo.com')
      self.assertRaises(certutils.Error, c.run_request)


if __name__ == '__main__':
  signal.signal(signal.SIGINT, signal.SIG_DFL)  # Exit on Ctrl-C
  unittest.main()
