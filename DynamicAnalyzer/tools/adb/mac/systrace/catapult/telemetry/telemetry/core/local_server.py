# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# TODO(aiolos): this should be moved to catapult/base after the repo move.
# It is used by tracing in tvcm/browser_controller.
import collections
import json
import os
import re
import subprocess
import sys

from telemetry.core import util

NamedPort = collections.namedtuple('NamedPort', ['name', 'port'])


class LocalServerBackend(object):

  def __init__(self):
    pass

  def StartAndGetNamedPorts(self, args):
    """Starts the actual server and obtains any sockets on which it
    should listen.

    Returns a list of NamedPort on which this backend is listening.
    """
    raise NotImplementedError()

  def ServeForever(self):
    raise NotImplementedError()


class LocalServer(object):

  def __init__(self, server_backend_class):
    assert LocalServerBackend in server_backend_class.__bases__
    server_module_name = server_backend_class.__module__
    assert server_module_name in sys.modules, \
        'The server class\' module must be findable via sys.modules'
    assert getattr(sys.modules[server_module_name],
                   server_backend_class.__name__), \
        'The server class must getattrable from its __module__ by its __name__'

    self._server_backend_class = server_backend_class
    self._subprocess = None
    self._devnull = None
    self._local_server_controller = None
    self.host_ip = None
    self.port = None

  def Start(self, local_server_controller):
    assert self._subprocess == None
    self._local_server_controller = local_server_controller

    self.host_ip = local_server_controller.host_ip

    server_args = self.GetBackendStartupArgs()
    server_args_as_json = json.dumps(server_args)
    server_module_name = self._server_backend_class.__module__

    self._devnull = open(os.devnull, 'w')
    cmd = [
        sys.executable,
        '-m',
        __name__,
        'run_backend',
        server_module_name,
        self._server_backend_class.__name__,
        server_args_as_json,
    ]

    env = os.environ.copy()
    env['PYTHONPATH'] = os.pathsep.join(sys.path)

    self._subprocess = subprocess.Popen(cmd,
                                        cwd=util.GetTelemetryDir(),
                                        env=env,
                                        stdout=subprocess.PIPE)

    named_ports = self._GetNamedPortsFromBackend()
    http_port = None
    for p in named_ports:
      if p.name == 'http':
        http_port = p.port
    assert http_port and len(named_ports) == 1, (
        'Only http port is supported: %s' % named_ports)
    self.port = http_port

  def _GetNamedPortsFromBackend(self):
    named_ports_json = None
    named_ports_re = re.compile('LocalServerBackend started: (?P<port>.+)')
    # TODO: This will hang if the subprocess doesn't print the correct output.
    while self._subprocess.poll() == None:
      m = named_ports_re.match(self._subprocess.stdout.readline())
      if m:
        named_ports_json = m.group('port')
        break

    if not named_ports_json:
      raise Exception('Server process died prematurely ' +
                      'without giving us port pairs.')
    return [NamedPort(**pair) for pair in json.loads(named_ports_json.lower())]

  @property
  def is_running(self):
    return self._subprocess != None

  def __enter__(self):
    return self

  def __exit__(self, *args):
    self.Close()

  def __del__(self):
    self.Close()

  def Close(self):
    if self._subprocess:
      # TODO(tonyg): Should this block until it goes away?
      self._subprocess.kill()
      self._subprocess = None
    if self._devnull:
      self._devnull.close()
      self._devnull = None
    if self._local_server_controller:
      self._local_server_controller.ServerDidClose(self)
      self._local_server_controller = None

  def GetBackendStartupArgs(self):
    """Returns whatever arguments are required to start up the backend"""
    raise NotImplementedError()


class LocalServerController(object):
  """Manages the list of running servers

  This class manages the running servers, but also provides an isolation layer
  to prevent LocalServer subclasses from accessing the browser backend directly.

  """

  def __init__(self, platform_backend):
    self._platform_backend = platform_backend
    self._local_servers_by_class = {}
    self.host_ip = self._platform_backend.forwarder_factory.host_ip

  def StartServer(self, server):
    assert not server.is_running, 'Server already started'
    assert self._platform_backend.network_controller_backend.is_initialized
    assert isinstance(server, LocalServer)
    if server.__class__ in self._local_servers_by_class:
      raise Exception(
          'Cannot have two servers of the same class running at once. ' +
          'Locate the existing one and use it, or call Close() on it.')

    server.Start(self)
    self._local_servers_by_class[server.__class__] = server

  def GetRunningServer(self, server_class, default_value):
    return self._local_servers_by_class.get(server_class, default_value)

  @property
  def local_servers(self):
    return self._local_servers_by_class.values()

  def Close(self):
    while len(self._local_servers_by_class):
      server = self._local_servers_by_class.itervalues().next()
      try:
        server.Close()
      except Exception:
        import traceback
        traceback.print_exc()

  def GetRemotePort(self, port):
    return self._platform_backend.GetRemotePort(port)

  def ServerDidClose(self, server):
    del self._local_servers_by_class[server.__class__]


def _LocalServerBackendMain(args):
  assert len(args) == 4
  (cmd, server_module_name, server_backend_class_name,
   server_args_as_json) = args[:4]
  assert cmd == 'run_backend'
  server_module = __import__(server_module_name, fromlist=[True])
  server_backend_class = getattr(server_module, server_backend_class_name)
  server = server_backend_class()

  server_args = json.loads(server_args_as_json)

  named_ports = server.StartAndGetNamedPorts(server_args)
  assert isinstance(named_ports, list)
  for named_port in named_ports:
    assert isinstance(named_port, NamedPort)

  # Note: This message is scraped by the parent process'
  # _GetNamedPortsFromBackend(). Do **not** change it.
  # pylint: disable=protected-access
  print 'LocalServerBackend started: %s' % json.dumps([pair._asdict()
                                                       for pair in named_ports])
  sys.stdout.flush()

  return server.ServeForever()


if __name__ == '__main__':
  # This trick is needed because local_server.NamedPort is not the
  # same as sys.modules['__main__'].NamedPort. The module itself is loaded
  # twice, basically.
  from telemetry.core import local_server  # pylint: disable=import-self
  sys.exit(
      local_server._LocalServerBackendMain(  # pylint: disable=protected-access
          sys.argv[1:]))
