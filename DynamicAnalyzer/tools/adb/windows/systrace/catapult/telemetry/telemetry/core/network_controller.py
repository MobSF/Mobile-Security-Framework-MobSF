# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from py_trace_event import trace_event


class NetworkController(object):
  """Control network settings and servers to simulate the Web.

  Network changes include forwarding device ports to host platform ports.
  Web Page Replay is used to record and replay HTTP/HTTPS responses.
  """

  __metaclass__ = trace_event.TracedMetaClass

  def __init__(self, network_controller_backend):
    self._network_controller_backend = network_controller_backend

  def InitializeIfNeeded(self, use_live_traffic=False):
    self._network_controller_backend.InitializeIfNeeded(use_live_traffic)

  def Open(self, wpr_mode, extra_wpr_args):
    self._network_controller_backend.Open(wpr_mode, extra_wpr_args)

  def UpdateTrafficSettings(self, round_trip_latency_ms=None,
      download_bandwidth_kbps=None, upload_bandwidth_kbps=None):
    self._network_controller_backend.ts_proxy_server.UpdateTrafficSettings(
      round_trip_latency_ms, download_bandwidth_kbps, upload_bandwidth_kbps)

  @property
  def is_open(self):
    return self._network_controller_backend.is_open

  def Close(self):
    self._network_controller_backend.Close()

  def StartReplay(self, archive_path, make_javascript_deterministic=False):
    self._network_controller_backend.StartReplay(
        archive_path, make_javascript_deterministic)

  def StopReplay(self):
    self._network_controller_backend.StopReplay()
