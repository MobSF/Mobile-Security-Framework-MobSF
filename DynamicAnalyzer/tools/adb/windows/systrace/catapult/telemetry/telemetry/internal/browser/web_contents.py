# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os

from telemetry.core import exceptions

from py_trace_event import trace_event

DEFAULT_WEB_CONTENTS_TIMEOUT = 90

# TODO(achuith, dtu, nduca): Add unit tests specifically for WebContents,
# independent of Tab.
class WebContents(object):

  __metaclass__ = trace_event.TracedMetaClass

  """Represents web contents in the browser"""
  def __init__(self, inspector_backend):
    self._inspector_backend = inspector_backend

    with open(os.path.join(os.path.dirname(__file__),
        'network_quiescence.js')) as f:
      self._quiescence_js = f.read()

    with open(os.path.join(os.path.dirname(__file__),
        'wait_for_frame.js')) as f:
      self._wait_for_frame_js = f.read()

    # An incrementing ID used to query frame timing javascript. Using a new id
    # with each request ensures that previously timed-out wait for frame
    # requests don't impact new requests.
    self._wait_for_frame_id = 0

  @property
  def id(self):
    """Return the unique id string for this tab object."""
    return self._inspector_backend.id

  def GetUrl(self):
    """Returns the URL to which the WebContents is connected.

    Raises:
      exceptions.Error: If there is an error in inspector backend connection.
    """
    return self._inspector_backend.url

  def GetWebviewContexts(self):
    """Returns a list of webview contexts within the current inspector backend.

    Returns:
      A list of WebContents objects representing the webview contexts.

    Raises:
      exceptions.Error: If there is an error in inspector backend connection.
    """
    webviews = []
    inspector_backends = self._inspector_backend.GetWebviewInspectorBackends()
    for inspector_backend in inspector_backends:
      webviews.append(WebContents(inspector_backend))
    return webviews

  def WaitForDocumentReadyStateToBeComplete(self,
      timeout=DEFAULT_WEB_CONTENTS_TIMEOUT):
    """Waits for the document to finish loading.

    Raises:
      exceptions.Error: See WaitForJavaScriptCondition() for a detailed list
      of possible exceptions.
    """

    self.WaitForJavaScriptCondition(
        'document.readyState == "complete"', timeout=timeout)

  def WaitForDocumentReadyStateToBeInteractiveOrBetter(self,
      timeout=DEFAULT_WEB_CONTENTS_TIMEOUT):
    """Waits for the document to be interactive.

    Raises:
      exceptions.Error: See WaitForJavaScriptCondition() for a detailed list
      of possible exceptions.
    """
    self.WaitForJavaScriptCondition(
        'document.readyState == "interactive" || '
        'document.readyState == "complete"', timeout=timeout)

  def WaitForFrameToBeDisplayed(self,
          timeout=DEFAULT_WEB_CONTENTS_TIMEOUT):
    """Waits for a frame to be displayed before returning.

    Raises:
      exceptions.Error: See WaitForJavaScriptCondition() for a detailed list
      of possible exceptions.
    """
    # Generate a new id for each call of this function to ensure that we track
    # each request to wait seperately.
    self._wait_for_frame_id += 1
    self.WaitForJavaScriptCondition(
        '{{ @script }}; window.__telemetry_testHasFramePassed({{ frame_id }})',
        script=self._wait_for_frame_js,
        frame_id=str(self._wait_for_frame_id),  # Place id as a str.
        timeout=timeout)

  def HasReachedQuiescence(self):
    """Determine whether the page has reached quiescence after loading.

    Returns:
      True if 2 seconds have passed since last resource received, false
      otherwise.
    Raises:
      exceptions.Error: See EvaluateJavaScript() for a detailed list of
      possible exceptions.
    """
    # Inclusion of the script that provides
    # window.__telemetry_testHasReachedNetworkQuiescence()
    # is idempotent, it's run on every call because WebContents doesn't track
    # page loads and we need to execute anew for every newly loaded page.
    return self.EvaluateJavaScript(
        '{{ @script }}; window.__telemetry_testHasReachedNetworkQuiescence()',
        script=self._quiescence_js)

  def ExecuteJavaScript(self, *args, **kwargs):
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
    return self._inspector_backend.ExecuteJavaScript(*args, **kwargs)

  def EvaluateJavaScript(self, *args, **kwargs):
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
    return self._inspector_backend.EvaluateJavaScript(*args, **kwargs)

  def WaitForJavaScriptCondition(self, *args, **kwargs):
    """Wait for a JavaScript condition to become true.

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

    Raises:
      py_utils.TimeoutException
      exceptions.EvaluationException
      exceptions.WebSocketException
      exceptions.DevtoolsTargetCrashException
    """
    return self._inspector_backend.WaitForJavaScriptCondition(*args, **kwargs)

  def EnableAllContexts(self):
    """Enable all contexts in a page. Returns the number of available contexts.

    Raises:
      exceptions.WebSocketDisconnected
      py_utils.TimeoutException
      exceptions.DevtoolsTargetCrashException
    """
    return self._inspector_backend.EnableAllContexts()

  def WaitForNavigate(self, timeout=DEFAULT_WEB_CONTENTS_TIMEOUT):
    """Waits for the navigation to complete.

    The current page is expect to be in a navigation.
    This function returns when the navigation is complete or when
    the timeout has been exceeded.

    Raises:
      py_utils.TimeoutException
      exceptions.DevtoolsTargetCrashException
    """
    self._inspector_backend.WaitForNavigate(timeout)

  def Navigate(self, url, script_to_evaluate_on_commit=None,
               timeout=DEFAULT_WEB_CONTENTS_TIMEOUT):
    """Navigates to url.

    If |script_to_evaluate_on_commit| is given, the script source string will be
    evaluated when the navigation is committed. This is after the context of
    the page exists, but before any script on the page itself has executed.

    Raises:
      py_utils.TimeoutException
      exceptions.DevtoolsTargetCrashException
    """
    self._inspector_backend.Navigate(url, script_to_evaluate_on_commit, timeout)

  def IsAlive(self):
    """Whether the WebContents is still operating normally.

    Since WebContents function asynchronously, this method does not guarantee
    that the WebContents will still be alive at any point in the future.

    Returns:
      A boolean indicating whether the WebContents is opearting normally.
    """
    return self._inspector_backend.IsInspectable()

  def CloseConnections(self):
    """Closes all TCP sockets held open by the browser.

    Raises:
      exceptions.DevtoolsTargetCrashException if the tab is not alive.
    """
    if not self.IsAlive():
      raise exceptions.DevtoolsTargetCrashException
    self.ExecuteJavaScript('window.chrome && chrome.benchmarking &&'
                           'chrome.benchmarking.closeConnections()')

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
      yDistance: Ddistance to scroll along the Y axis (positive to scroll up).
      xOverscroll: Number of additional pixels to scroll back along the X axis.
      xOverscroll: Number of additional pixels to scroll back along the Y axis.
      preventFling: Prevents a fling gesture.
      speed: Swipe speed in pixels per second.
      gestureSourceType: Which type of input events to be generated.
      repeatCount: Number of additional repeats beyond the first scroll.
      repeatDelayMs: Number of milliseconds delay between each repeat.
      interactionMarkerName: The name of the interaction markers to generate.

    Raises:
      py_utils.TimeoutException
      exceptions.DevtoolsTargetCrashException
    """
    return self._inspector_backend.SynthesizeScrollGesture(
        x=x, y=y, xDistance=xDistance, yDistance=yDistance,
        xOverscroll=xOverscroll, yOverscroll=yOverscroll,
        preventFling=preventFling, speed=speed,
        gestureSourceType=gestureSourceType, repeatCount=repeatCount,
        repeatDelayMs=repeatDelayMs,
        interactionMarkerName=interactionMarkerName,
        timeout=timeout)

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
      py_utils.TimeoutException
      exceptions.DevtoolsTargetCrashException
    """
    return self._inspector_backend.DispatchKeyEvent(
        keyEventType=keyEventType, modifiers=modifiers, timestamp=timestamp,
        text=text, unmodifiedText=unmodifiedText, keyIdentifier=keyIdentifier,
        domCode=domCode, domKey=domKey,
        windowsVirtualKeyCode=windowsVirtualKeyCode,
        nativeVirtualKeyCode=nativeVirtualKeyCode, autoRepeat=autoRepeat,
        isKeypad=isKeypad, isSystemKey=isSystemKey, timeout=timeout)
