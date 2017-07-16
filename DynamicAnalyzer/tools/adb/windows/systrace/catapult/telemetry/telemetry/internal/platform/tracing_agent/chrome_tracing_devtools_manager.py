# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# A singleton map from platform backends to maps of uniquely-identifying
# remote port (which may be the same as local port) to DevToolsClientBackend.
# There is no guarantee that the devtools agent is still alive.
_platform_backends_to_devtools_clients_maps = {}


def _RemoveStaleDevToolsClient(platform_backend):
  """Removes DevTools clients that are no longer connectable."""
  devtools_clients_map = _platform_backends_to_devtools_clients_maps.get(
      platform_backend, {})
  devtools_clients_map = {
      port: client
      for port, client in devtools_clients_map.iteritems()
      if client.IsAlive()
      }
  _platform_backends_to_devtools_clients_maps[platform_backend] = (
      devtools_clients_map)


def RegisterDevToolsClient(devtools_client_backend, platform_backend):
  """Register DevTools client

  This should only be called from DevToolsClientBackend when it is initialized.
  """
  remote_port = str(devtools_client_backend.remote_port)
  if platform_backend not in _platform_backends_to_devtools_clients_maps:
    _platform_backends_to_devtools_clients_maps[platform_backend] = {}
  devtools_clients_map = (
    _platform_backends_to_devtools_clients_maps[platform_backend])
  devtools_clients_map[remote_port] = devtools_client_backend


def IsSupported(platform_backend):
  _RemoveStaleDevToolsClient(platform_backend)
  devtools_clients_map = _platform_backends_to_devtools_clients_maps.get(
      platform_backend, {})
  for _, devtools_client in devtools_clients_map.iteritems():
    if devtools_client.IsChromeTracingSupported():
      return True
  return False


def GetDevToolsClients(platform_backend):
  """Get DevTools clients including the ones that are no longer connectable."""
  devtools_clients_map = _platform_backends_to_devtools_clients_maps.get(
      platform_backend, {})
  if not devtools_clients_map:
    return []
  return devtools_clients_map.values()

def GetActiveDevToolsClients(platform_backend):
  """Get DevTools clients that are still connectable."""
  _RemoveStaleDevToolsClient(platform_backend)
  return GetDevToolsClients(platform_backend)
