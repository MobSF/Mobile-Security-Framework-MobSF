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

"""Extends BaseHTTPRequestHandler with SSL certificate generation."""

import logging
import socket

import certutils



def _SetUpUsingDummyCert(handler):
  """Sets up connection providing the certificate to the client.

  This method handles Server Name Indication (SNI) using dummy certs.

  Args:
    handler: an instance of BaseHTTPServer.BaseHTTPRequestHandler that is used
      by some instance of  BaseHTTPServer.HTTPServer.
  """
  # One of: One of SSLv2_METHOD, SSLv3_METHOD, SSLv23_METHOD, or TLSv1_METHOD
  context = certutils.get_ssl_context()
  def handle_servername(connection):
    """A SNI callback that happens during do_handshake()."""
    try:
      host = connection.get_servername()
      if host:
        cert_str = (
            handler.server.get_certificate(host))
        new_context = certutils.get_ssl_context()
        cert = certutils.load_cert(cert_str)
        new_context.use_certificate(cert)
        new_context.use_privatekey_file(handler.server.ca_cert_path)
        connection.set_context(new_context)
        return new_context
      # else: fail with 'no shared cipher'
    except Exception, e:
      # Do not leak any exceptions or else openssl crashes.
      logging.error('Exception in SNI handler: %s', e)

  context.set_tlsext_servername_callback(handle_servername)
  handler.connection = certutils.get_ssl_connection(context, handler.connection)
  handler.connection.set_accept_state()
  try:
    handler.connection.do_handshake()
  except certutils.Error, v:
    host = handler.connection.get_servername()
    if not host:
      logging.error('Dropping request without SNI')
      return ''
    raise certutils.Error('SSL handshake error %s: %s' % (host, str(v)))

  # Re-wrap the read/write streams with our new connection.
  handler.rfile = socket._fileobject(handler.connection, 'rb', handler.rbufsize,
                                  close=False)
  handler.wfile = socket._fileobject(handler.connection, 'wb', handler.wbufsize,
                                  close=False)


def wrap_handler(handler_class):
  """Wraps a BaseHTTPHandler with SSL MITM certificates."""
  if certutils.openssl_import_error:
    # pylint: disable=raising-bad-type
    raise certutils.openssl_import_error

  class WrappedHandler(handler_class):

    def setup(self):
      handler_class.setup(self)
      _SetUpUsingDummyCert(self)

    def finish(self):
      handler_class.finish(self)
      self.connection.shutdown()
      self.connection.close()

  return WrappedHandler
