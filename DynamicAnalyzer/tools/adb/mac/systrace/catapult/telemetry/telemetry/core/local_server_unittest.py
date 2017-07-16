# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import BaseHTTPServer
import SimpleHTTPServer

from telemetry import decorators
from telemetry.core import local_server
from telemetry.testing import tab_test_case


class SimpleLocalServerBackendRequestHandler(
    SimpleHTTPServer.SimpleHTTPRequestHandler):

  def do_GET(self):
    msg = """<!DOCTYPE html>
<html>
<body>
hello world
</body>
"""

    self.send_response(200)
    self.send_header('Content-Type', 'text/html')
    self.send_header('Content-Length', len(msg))
    self.end_headers()
    self.wfile.write(msg)

  def log_request(self, code='-', size='-'):
    pass


class SimpleLocalServerBackend(BaseHTTPServer.HTTPServer,
                               local_server.LocalServerBackend):

  def __init__(self):
    BaseHTTPServer.HTTPServer.__init__(self, ('127.0.0.1', 0),
                                       SimpleLocalServerBackendRequestHandler)
    local_server.LocalServerBackend.__init__(self)

  def StartAndGetNamedPorts(self, args):
    assert 'hello' in args
    assert args['hello'] == 'world'
    return [local_server.NamedPort('http', self.server_address[1])]

  def ServeForever(self):
    self.serve_forever()


class SimpleLocalServer(local_server.LocalServer):

  def __init__(self):
    super(SimpleLocalServer, self).__init__(SimpleLocalServerBackend)

  def GetBackendStartupArgs(self):
    return {'hello': 'world'}

  @property
  def url(self):
    return self.forwarder.url + '/'


class LocalServerUnittest(tab_test_case.TabTestCase):

  @classmethod
  def setUpClass(cls):
    super(LocalServerUnittest, cls).setUpClass()
    cls._server = SimpleLocalServer()
    cls._platform.StartLocalServer(cls._server)

  @decorators.Disabled('all') # https://crbug.com/570955
  def testLocalServer(self):
    self.assertTrue(self._server in self._platform.local_servers)
    self._tab.Navigate(self._server.url)
    self._tab.WaitForDocumentReadyStateToBeComplete()
    body_text = self._tab.EvaluateJavaScript('document.body.textContent')
    body_text = body_text.strip()
    self.assertEquals('hello world', body_text)

  @decorators.Disabled('all') # https://crbug.com/570955
  def testStartingAndRestarting(self):
    server2 = SimpleLocalServer()
    self.assertRaises(Exception,
                      lambda: self._platform.StartLocalServer(server2))

    self._server.Close()
    self.assertTrue(self._server not in self._platform.local_servers)

    self._platform.StartLocalServer(server2)
