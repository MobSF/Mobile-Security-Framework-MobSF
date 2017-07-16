# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import logging
import socket
import time
import traceback

from telemetry import decorators
from telemetry.internal.backends.chrome_inspector import inspector_websocket
from telemetry.internal.backends.chrome_inspector import websocket
from tracing.trace_data import trace_data as trace_data_module


class TracingUnsupportedException(Exception):
  pass


class TracingTimeoutException(Exception):
  pass


class TracingUnrecoverableException(Exception):
  pass


class TracingHasNotRunException(Exception):
  pass


class TracingUnexpectedResponseException(Exception):
  pass


class ClockSyncResponseException(Exception):
  pass


class _DevToolsStreamReader(object):
  def __init__(self, inspector_socket, stream_handle):
    self._inspector_websocket = inspector_socket
    self._handle = stream_handle
    self._trace_file_handle = None
    self._callback = None

  def Read(self, callback):
    # Do not allow the instance of this class to be reused, as
    # we only read data sequentially at the moment, so a stream
    # can only be read once.
    assert not self._callback
    self._trace_file_handle = trace_data_module.TraceFileHandle()
    self._trace_file_handle.Open()
    self._callback = callback
    self._ReadChunkFromStream()
    # The below is not a typo -- queue one extra read ahead to avoid latency.
    self._ReadChunkFromStream()

  def _ReadChunkFromStream(self):
    # Limit max block size to avoid fragmenting memory in sock.recv(),
    # (see https://github.com/liris/websocket-client/issues/163 for details)
    req = {'method': 'IO.read', 'params': {
        'handle': self._handle, 'size': 32768}}
    self._inspector_websocket.AsyncRequest(req, self._GotChunkFromStream)

  def _GotChunkFromStream(self, response):
    # Quietly discard responses from reads queued ahead after EOF.
    if self._trace_file_handle is None:
      return
    if 'error' in response:
      raise TracingUnrecoverableException(
          'Reading trace failed: %s' % response['error']['message'])
    result = response['result']
    # Convert the trace data that's receive as UTF32 to its native encoding of
    # UTF8 in order to reduce its size.
    self._trace_file_handle.AppendTraceData(result['data'].encode('utf8'))
    if not result.get('eof', False):
      self._ReadChunkFromStream()
      return
    req = {'method': 'IO.close', 'params': {'handle': self._handle}}
    self._inspector_websocket.SendAndIgnoreResponse(req)
    self._trace_file_handle.Close()
    self._callback(self._trace_file_handle)
    self._trace_file_handle = None


class TracingBackend(object):

  _TRACING_DOMAIN = 'Tracing'

  def __init__(self, inspector_socket, is_tracing_running=False,
               support_modern_devtools_tracing_start_api=False):
    self._inspector_websocket = inspector_socket
    self._inspector_websocket.RegisterDomain(
        self._TRACING_DOMAIN, self._NotificationHandler)
    self._is_tracing_running = is_tracing_running
    self._start_issued = False
    self._can_collect_data = False
    self._has_received_all_tracing_data = False
    self._support_modern_devtools_tracing_start_api = (
        support_modern_devtools_tracing_start_api)
    self._trace_data_builder = None

  @property
  def is_tracing_running(self):
    return self._is_tracing_running

  def StartTracing(self, chrome_trace_config, timeout=10):
    """When first called, starts tracing, and returns True.

    If called during tracing, tracing is unchanged, and it returns False.
    """
    if self.is_tracing_running:
      return False
    assert not self._can_collect_data, 'Data not collected from last trace.'
    # Reset collected tracing data from previous tracing calls.

    if not self.IsTracingSupported():
      raise TracingUnsupportedException(
          'Chrome tracing not supported for this app.')

    params = {'transferMode': 'ReturnAsStream'}
    if self._support_modern_devtools_tracing_start_api:
      params['traceConfig'] = (
          chrome_trace_config.GetChromeTraceConfigForDevTools())
    else:
      if chrome_trace_config.requires_modern_devtools_tracing_start_api:
        raise TracingUnsupportedException(
            'Trace options require modern Tracing.start DevTools API, '
            'which is NOT supported by the browser')
      params['categories'], params['options'] = (
          chrome_trace_config.GetChromeTraceCategoriesAndOptionsForDevTools())

    req = {'method': 'Tracing.start', 'params': params}
    logging.info('Start Tracing Request: %r', req)
    response = self._inspector_websocket.SyncRequest(req, timeout)

    if 'error' in response:
      raise TracingUnexpectedResponseException(
          'Inspector returned unexpected response for '
          'Tracing.start:\n' + json.dumps(response, indent=2))

    self._is_tracing_running = True
    self._start_issued = True
    return True

  def RecordClockSyncMarker(self, sync_id):
    assert self.is_tracing_running, 'Tracing must be running to clock sync.'
    req = {
      'method': 'Tracing.recordClockSyncMarker',
      'params': {
        'syncId': sync_id
      }
    }
    rc = self._inspector_websocket.SyncRequest(req, timeout=2)
    if 'error' in rc:
      raise ClockSyncResponseException(rc['error']['message'])

  def StopTracing(self):
    """Stops tracing and pushes results to the supplied TraceDataBuilder.

    If this is called after tracing has been stopped, trace data from the last
    tracing run is pushed.
    """
    if not self.is_tracing_running:
      raise TracingHasNotRunException()
    else:
      if not self._start_issued:
        # Tracing is running but start was not issued so, startup tracing must
        # be in effect. Issue another Tracing.start to update the transfer mode.
        # TODO(caseq): get rid of it when streaming is the default.
        params = {
          'transferMode': 'ReturnAsStream',
          'traceConfig': {}
        }
        req = {'method': 'Tracing.start', 'params': params}
        self._inspector_websocket.SendAndIgnoreResponse(req)

      req = {'method': 'Tracing.end'}
      self._inspector_websocket.SendAndIgnoreResponse(req)

    self._is_tracing_running = False
    self._start_issued = False
    self._can_collect_data = True

  def DumpMemory(self, timeout=30):
    """Dumps memory.

    Returns:
      GUID of the generated dump if successful, None otherwise.

    Raises:
      TracingTimeoutException: If more than |timeout| seconds has passed
      since the last time any data is received.
      TracingUnrecoverableException: If there is a websocket error.
      TracingUnexpectedResponseException: If the response contains an error
      or does not contain the expected result.
    """
    request = {
      'method': 'Tracing.requestMemoryDump'
    }
    try:
      response = self._inspector_websocket.SyncRequest(request, timeout)
    except websocket.WebSocketTimeoutException:
      raise TracingTimeoutException(
          'Exception raised while sending a Tracing.requestMemoryDump '
          'request:\n' + traceback.format_exc())
    except (socket.error, websocket.WebSocketException,
            inspector_websocket.WebSocketDisconnected):
      raise TracingUnrecoverableException(
          'Exception raised while sending a Tracing.requestMemoryDump '
          'request:\n' + traceback.format_exc())


    if ('error' in response or
        'result' not in response or
        'success' not in response['result'] or
        'dumpGuid' not in response['result']):
      raise TracingUnexpectedResponseException(
          'Inspector returned unexpected response for '
          'Tracing.requestMemoryDump:\n' + json.dumps(response, indent=2))

    result = response['result']
    return result['dumpGuid'] if result['success'] else None

  def CollectTraceData(self, trace_data_builder, timeout=60):
    if not self._can_collect_data:
      raise Exception('Cannot collect before tracing is finished.')
    self._CollectTracingData(trace_data_builder, timeout)
    self._can_collect_data = False

  def _CollectTracingData(self, trace_data_builder, timeout):
    """Collects tracing data. Assumes that Tracing.end has already been sent.

    Args:
      trace_data_builder: An instance of TraceDataBuilder to put results into.
      timeout: The timeout in seconds.

    Raises:
      TracingTimeoutException: If more than |timeout| seconds has passed
      since the last time any data is received.
      TracingUnrecoverableException: If there is a websocket error.
    """
    self._has_received_all_tracing_data = False
    start_time = time.time()
    self._trace_data_builder = trace_data_builder
    try:
      while True:
        try:
          self._inspector_websocket.DispatchNotifications(timeout)
          start_time = time.time()
        except websocket.WebSocketTimeoutException:
          pass
        except (socket.error, websocket.WebSocketException):
          raise TracingUnrecoverableException(
              'Exception raised while collecting tracing data:\n' +
                  traceback.format_exc())

        if self._has_received_all_tracing_data:
          break

        elapsed_time = time.time() - start_time
        if elapsed_time > timeout:
          raise TracingTimeoutException(
              'Only received partial trace data due to timeout after %s '
              'seconds. If the trace data is big, you may want to increase '
              'the timeout amount.' % elapsed_time)
    finally:
      self._trace_data_builder = None

  def _NotificationHandler(self, res):
    if 'Tracing.dataCollected' == res.get('method'):
      value = res.get('params', {}).get('value')
      self._trace_data_builder.AddTraceFor(
        trace_data_module.CHROME_TRACE_PART, value)
    elif 'Tracing.tracingComplete' == res.get('method'):
      stream_handle = res.get('params', {}).get('stream')
      if not stream_handle:
        self._has_received_all_tracing_data = True
        return
      reader = _DevToolsStreamReader(self._inspector_websocket, stream_handle)
      reader.Read(self._ReceivedAllTraceDataFromStream)

  def _ReceivedAllTraceDataFromStream(self, trace_handle):
    self._trace_data_builder.AddTraceFor(
        trace_data_module.CHROME_TRACE_PART, trace_handle)
    self._has_received_all_tracing_data = True

  def Close(self):
    self._inspector_websocket.UnregisterDomain(self._TRACING_DOMAIN)
    self._inspector_websocket = None

  @decorators.Cache
  def IsTracingSupported(self):
    req = {'method': 'Tracing.hasCompleted'}
    res = self._inspector_websocket.SyncRequest(req, timeout=10)
    return not res.get('response')
