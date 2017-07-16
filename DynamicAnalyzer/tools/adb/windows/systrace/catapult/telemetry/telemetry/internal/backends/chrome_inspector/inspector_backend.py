# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import functools
import logging
import os
import socket
import sys

from py_trace_event import trace_event

from telemetry.core import exceptions
from telemetry import decorators
from telemetry.internal.backends.chrome_inspector import devtools_http
from telemetry.internal.backends.chrome_inspector import inspector_console
from telemetry.internal.backends.chrome_inspector import inspector_memory
from telemetry.internal.backends.chrome_inspector import inspector_page
from telemetry.internal.backends.chrome_inspector import inspector_runtime
from telemetry.internal.backends.chrome_inspector import inspector_websocket
from telemetry.internal.backends.chrome_inspector import websocket
from telemetry.util import js_template

import py_utils


def _HandleInspectorWebSocketExceptions(func):
  """Decorator for converting inspector_websocket exceptions.

  When an inspector_websocket exception is thrown in the original function,
  this decorator converts it into a telemetry exception and adds debugging
  information.
  """
  @functools.wraps(func)
  def inner(inspector_backend, *args, **kwargs):
    try:
      return func(inspector_backend, *args, **kwargs)
    except (socket.error, websocket.WebSocketException,
            inspector_websocket.WebSocketDisconnected) as e:
      inspector_backend._ConvertExceptionFromInspectorWebsocket(e)

  return inner


class InspectorBackend(object):
  """Class for communicating with a devtools client.

  The owner of an instance of this class is responsible for calling
  Disconnect() before disposing of the instance.
  """

  __metaclass__ = trace_event.TracedMetaClass

  def __init__(self, app, devtools_client, context, timeout=120):
    self._websocket = inspector_websocket.InspectorWebsocket()
    self._websocket.RegisterDomain(
        'Inspector', self._HandleInspectorDomainNotification)

    self._app = app
    self._devtools_client = devtools_client
    # Be careful when using the context object, since the data may be
    # outdated since this is never updated once InspectorBackend is
    # created. Consider an updating strategy for this. (For an example
    # of the subtlety, see the logic for self.url property.)
    self._context = context

    logging.debug('InspectorBackend._Connect() to %s', self.debugger_url)
    try:
      self._websocket.Connect(self.debugger_url, timeout)
      self._console = inspector_console.InspectorConsole(self._websocket)
      self._memory = inspector_memory.InspectorMemory(self._websocket)
      self._page = inspector_page.InspectorPage(
          self._websocket, timeout=timeout)
      self._runtime = inspector_runtime.InspectorRuntime(self._websocket)
    except (websocket.WebSocketException, exceptions.TimeoutException,
            py_utils.TimeoutException) as e:
      self._ConvertExceptionFromInspectorWebsocket(e)

  def Disconnect(self):
    """Disconnects the inspector websocket.

    This method intentionally leaves the self._websocket object around, so that
    future calls it to it will fail with a relevant error.
    """
    if self._websocket:
      self._websocket.Disconnect()

  def __del__(self):
    self.Disconnect()

  @property
  def app(self):
    return self._app

  @property
  def url(self):
    """Returns the URL of the tab, as reported by devtools.

    Raises:
      devtools_http.DevToolsClientConnectionError
    """
    return self._devtools_client.GetUrl(self.id)

  @property
  def id(self):
    return self._context['id']

  @property
  def debugger_url(self):
    return self._context['webSocketDebuggerUrl']

  def GetWebviewInspectorBackends(self):
    """Returns a list of InspectorBackend instances associated with webviews.

    Raises:
      devtools_http.DevToolsClientConnectionError
    """
    inspector_backends = []
    devtools_context_map = self._devtools_client.GetUpdatedInspectableContexts()
    for context in devtools_context_map.contexts:
      if context['type'] == 'webview':
        inspector_backends.append(
            devtools_context_map.GetInspectorBackend(context['id']))
    return inspector_backends

  def IsInspectable(self):
    """Whether the tab is inspectable, as reported by devtools."""
    try:
      return self._devtools_client.IsInspectable(self.id)
    except devtools_http.DevToolsClientConnectionError:
      return False

  # Public methods implemented in JavaScript.

  @property
  @decorators.Cache
  def screenshot_supported(self):
    if (self.app.platform.GetOSName() == 'linux' and (
        os.getenv('DISPLAY') not in [':0', ':0.0'])):
      # Displays other than 0 mean we are likely running in something like
      # xvfb where screenshotting doesn't work.
      return False
    return True

  @_HandleInspectorWebSocketExceptions
  def Screenshot(self, timeout):
    assert self.screenshot_supported, 'Browser does not support screenshotting'
    return self._page.CaptureScreenshot(timeout)

  # Memory public methods.

  @_HandleInspectorWebSocketExceptions
  def GetDOMStats(self, timeout):
    """Gets memory stats from the DOM.

    Raises:
      inspector_memory.InspectorMemoryException
      exceptions.TimeoutException
      exceptions.DevtoolsTargetCrashException
    """
    dom_counters = self._memory.GetDOMCounters(timeout)
    return {
      'document_count': dom_counters['documents'],
      'node_count': dom_counters['nodes'],
      'event_listener_count': dom_counters['jsEventListeners']
    }

  # Page public methods.

  @_HandleInspectorWebSocketExceptions
  def WaitForNavigate(self, timeout):
    self._page.WaitForNavigate(timeout)

  @_HandleInspectorWebSocketExceptions
  def Navigate(self, url, script_to_evaluate_on_commit, timeout):
    self._page.Navigate(url, script_to_evaluate_on_commit, timeout)

  @_HandleInspectorWebSocketExceptions
  def GetCookieByName(self, name, timeout):
    return self._page.GetCookieByName(name, timeout)

  # Console public methods.

  @_HandleInspectorWebSocketExceptions
  def GetCurrentConsoleOutputBuffer(self, timeout=10):
    return self._console.GetCurrentConsoleOutputBuffer(timeout)

  # Runtime public methods.

  @_HandleInspectorWebSocketExceptions
  def ExecuteJavaScript(self, statement, **kwargs):
    """Executes a given JavaScript statement. Does not return the result.

    Example: runner.ExecuteJavaScript('var foo = {{ value }};', value='hi');

    Args:
      statement: The statement to execute (provided as a string).

    Optional keyword args:
      timeout: The number of seconds to wait for the statement to execute.
      context_id: The id of an iframe where to execute the code; the main page
          has context_id=1, the first iframe context_id=2, etc.
      Additional keyword arguments provide values to be interpolated within
          the statement. See telemetry.util.js_template for details.

    Raises:
      py_utils.TimeoutException
      exceptions.EvaluationException
      exceptions.WebSocketException
      exceptions.DevtoolsTargetCrashException
    """
    # Use the default both when timeout=None or the option is ommited.
    timeout = kwargs.pop('timeout', None) or 60
    context_id = kwargs.pop('context_id', None)
    statement = js_template.Render(statement, **kwargs)
    self._runtime.Execute(statement, context_id, timeout)

  @_HandleInspectorWebSocketExceptions
  def EvaluateJavaScript(self, expression, **kwargs):
    """Returns the result of evaluating a given JavaScript expression.

    Example: runner.ExecuteJavaScript('document.location.href');

    Args:
      expression: The expression to execute (provided as a string).

    Optional keyword args:
      timeout: The number of seconds to wait for the expression to evaluate.
      context_id: The id of an iframe where to execute the code; the main page
          has context_id=1, the first iframe context_id=2, etc.
      Additional keyword arguments provide values to be interpolated within
          the expression. See telemetry.util.js_template for details.

    Raises:
      py_utils.TimeoutException
      exceptions.EvaluationException
      exceptions.WebSocketException
      exceptions.DevtoolsTargetCrashException
    """
    # Use the default both when timeout=None or the option is ommited.
    timeout = kwargs.pop('timeout', None) or 60
    context_id = kwargs.pop('context_id', None)
    expression = js_template.Render(expression, **kwargs)
    return self._runtime.Evaluate(expression, context_id, timeout)

  def WaitForJavaScriptCondition(self, condition, **kwargs):
    """Wait for a JavaScript condition to become truthy.

    Example: runner.WaitForJavaScriptCondition('window.foo == 10');

    Args:
      condition: The JavaScript condition (provided as string).

    Optional keyword args:
      timeout: The number in seconds to wait for the condition to become
          True (default to 60).
      context_id: The id of an iframe where to execute the code; the main page
          has context_id=1, the first iframe context_id=2, etc.
      Additional keyword arguments provide values to be interpolated within
          the expression. See telemetry.util.js_template for details.

    Returns:
      The value returned by the JavaScript condition that got interpreted as
      true.

    Raises:
      py_utils.TimeoutException
      exceptions.EvaluationException
      exceptions.WebSocketException
      exceptions.DevtoolsTargetCrashException
    """
    # Use the default both when timeout=None or the option is ommited.
    timeout = kwargs.pop('timeout', None) or 60
    context_id = kwargs.pop('context_id', None)
    condition = js_template.Render(condition, **kwargs)

    def IsJavaScriptExpressionTrue():
      return self._runtime.Evaluate(condition, context_id, timeout)

    try:
      return py_utils.WaitFor(IsJavaScriptExpressionTrue, timeout)
    except py_utils.TimeoutException as e:
      # Try to make timeouts a little more actionable by dumping console output.
      debug_message = None
      try:
        debug_message = (
            'Console output:\n%s' %
            self.GetCurrentConsoleOutputBuffer())
      except Exception as e:
        debug_message = (
            'Exception thrown when trying to capture console output: %s' %
            repr(e))
      raise py_utils.TimeoutException(
          e.message + '\n' + debug_message)

  @_HandleInspectorWebSocketExceptions
  def EnableAllContexts(self):
    """Allows access to iframes.

    Raises:
      exceptions.WebSocketDisconnected
      exceptions.TimeoutException
      exceptions.DevtoolsTargetCrashException
    """
    return self._runtime.EnableAllContexts()

  @_HandleInspectorWebSocketExceptions
  def SynthesizeScrollGesture(self, x=100, y=800, xDistance=0, yDistance=-500,
                              xOverscroll=None, yOverscroll=None,
                              preventFling=None, speed=None,
                              gestureSourceType=None, repeatCount=None,
                              repeatDelayMs=None, interactionMarkerName=None,
                              timeout=60):
    """Runs an inspector command that causes a repeatable browser driven scroll.

    Args:
      x: X coordinate of the start of the gesture in CSS pixels.
      y: Y coordinate of the start of the gesture in CSS pixels.
      xDistance: Distance to scroll along the X axis (positive to scroll left).
      yDistance: Distance to scroll along the Y axis (positive to scroll up).
      xOverscroll: Number of additional pixels to scroll back along the X axis.
      xOverscroll: Number of additional pixels to scroll back along the Y axis.
      preventFling: Prevents a fling gesture.
      speed: Swipe speed in pixels per second.
      gestureSourceType: Which type of input events to be generated.
      repeatCount: Number of additional repeats beyond the first scroll.
      repeatDelayMs: Number of milliseconds delay between each repeat.
      interactionMarkerName: The name of the interaction markers to generate.

    Raises:
      exceptions.TimeoutException
      exceptions.DevtoolsTargetCrashException
    """
    params = {
        'x': x,
        'y': y,
        'xDistance': xDistance,
        'yDistance': yDistance
    }

    if preventFling is not None:
      params['preventFling'] = preventFling

    if xOverscroll is not None:
      params['xOverscroll'] = xOverscroll

    if yOverscroll is not None:
      params['yOverscroll'] = yOverscroll

    if speed is not None:
      params['speed'] = speed

    if repeatCount is not None:
      params['repeatCount'] = repeatCount

    if gestureSourceType is not None:
      params['gestureSourceType'] = gestureSourceType

    if repeatDelayMs is not None:
      params['repeatDelayMs'] = repeatDelayMs

    if interactionMarkerName is not None:
      params['interactionMarkerName'] = interactionMarkerName

    scroll_command = {
      'method': 'Input.synthesizeScrollGesture',
      'params': params
    }
    return self._runtime.RunInspectorCommand(scroll_command, timeout)

  @_HandleInspectorWebSocketExceptions
  def DispatchKeyEvent(self, keyEventType='char', modifiers=None,
                       timestamp=None, text=None, unmodifiedText=None,
                       keyIdentifier=None, domCode=None, domKey=None,
                       windowsVirtualKeyCode=None, nativeVirtualKeyCode=None,
                       autoRepeat=None, isKeypad=None, isSystemKey=None,
                       timeout=60):
    """Dispatches a key event to the page.

    Args:
      type: Type of the key event. Allowed values: 'keyDown', 'keyUp',
          'rawKeyDown', 'char'.
      modifiers: Bit field representing pressed modifier keys. Alt=1, Ctrl=2,
          Meta/Command=4, Shift=8 (default: 0).
      timestamp: Time at which the event occurred. Measured in UTC time in
          seconds since January 1, 1970 (default: current time).
      text: Text as generated by processing a virtual key code with a keyboard
          layout. Not needed for for keyUp and rawKeyDown events (default: '').
      unmodifiedText: Text that would have been generated by the keyboard if no
          modifiers were pressed (except for shift). Useful for shortcut
          (accelerator) key handling (default: "").
      keyIdentifier: Unique key identifier (e.g., 'U+0041') (default: '').
      windowsVirtualKeyCode: Windows virtual key code (default: 0).
      nativeVirtualKeyCode: Native virtual key code (default: 0).
      autoRepeat: Whether the event was generated from auto repeat (default:
          False).
      isKeypad: Whether the event was generated from the keypad (default:
          False).
      isSystemKey: Whether the event was a system key event (default: False).

    Raises:
      exceptions.TimeoutException
      exceptions.DevtoolsTargetCrashException
    """
    params = {
      'type': keyEventType,
    }

    if modifiers is not None:
      params['modifiers'] = modifiers
    if timestamp is not None:
      params['timestamp'] = timestamp
    if text is not None:
      params['text'] = text
    if unmodifiedText is not None:
      params['unmodifiedText'] = unmodifiedText
    if keyIdentifier is not None:
      params['keyIdentifier'] = keyIdentifier
    if domCode is not None:
      params['code'] = domCode
    if domKey is not None:
      params['key'] = domKey
    if windowsVirtualKeyCode is not None:
      params['windowsVirtualKeyCode'] = windowsVirtualKeyCode
    if nativeVirtualKeyCode is not None:
      params['nativeVirtualKeyCode'] = nativeVirtualKeyCode
    if autoRepeat is not None:
      params['autoRepeat'] = autoRepeat
    if isKeypad is not None:
      params['isKeypad'] = isKeypad
    if isSystemKey is not None:
      params['isSystemKey'] = isSystemKey

    key_command = {
      'method': 'Input.dispatchKeyEvent',
      'params': params
    }
    return self._runtime.RunInspectorCommand(key_command, timeout)

  # Methods used internally by other backends.

  def _HandleInspectorDomainNotification(self, res):
    if (res['method'] == 'Inspector.detached' and
        res.get('params', {}).get('reason', '') == 'replaced_with_devtools'):
      self._WaitForInspectorToGoAway()
      return
    if res['method'] == 'Inspector.targetCrashed':
      exception = exceptions.DevtoolsTargetCrashException(self.app)
      self._AddDebuggingInformation(exception)
      raise exception

  def _WaitForInspectorToGoAway(self):
    self._websocket.Disconnect()
    raw_input('The connection to Chrome was lost to the inspector ui.\n'
              'Please close the inspector and press enter to resume '
              'Telemetry run...')
    raise exceptions.DevtoolsTargetCrashException(
        self.app, 'Devtool connection with the browser was interrupted due to '
        'the opening of an inspector.')

  def _ConvertExceptionFromInspectorWebsocket(self, error):
    """Converts an Exception from inspector_websocket.

    This method always raises a Telemetry exception. It appends debugging
    information. The exact exception raised depends on |error|.

    Args:
      error: An instance of socket.error or websocket.WebSocketException.
    Raises:
      exceptions.TimeoutException: A timeout occurred.
      exceptions.DevtoolsTargetCrashException: On any other error, the most
        likely explanation is that the devtool's target crashed.
    """
    if isinstance(error, websocket.WebSocketTimeoutException):
      new_error = exceptions.TimeoutException()
      new_error.AddDebuggingMessage(exceptions.AppCrashException(
          self.app, 'The app is probably crashed:\n'))
    else:
      new_error = exceptions.DevtoolsTargetCrashException(self.app)

    original_error_msg = 'Original exception:\n' + str(error)
    new_error.AddDebuggingMessage(original_error_msg)
    self._AddDebuggingInformation(new_error)

    raise new_error, None, sys.exc_info()[2]

  def _AddDebuggingInformation(self, error):
    """Adds debugging information to error.

    Args:
      error: An instance of exceptions.Error.
    """
    if self.IsInspectable():
      msg = (
          'Received a socket error in the browser connection and the tab '
          'still exists. The operation probably timed out.'
      )
    else:
      msg = (
          'Received a socket error in the browser connection and the tab no '
          'longer exists. The tab probably crashed.'
      )
    error.AddDebuggingMessage(msg)
    error.AddDebuggingMessage('Debugger url: %s' % self.debugger_url)

  @_HandleInspectorWebSocketExceptions
  def CollectGarbage(self):
    self._page.CollectGarbage()
