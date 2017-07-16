# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Provides fakes for several of Telemetry's internal objects.

These allow code like story_runner and Benchmark to be run and tested
without compiling or starting a browser. Class names prepended with an
underscore are intended to be implementation details, and should not
be subclassed; however, some, like _FakeBrowser, have public APIs that
may need to be called in tests.
"""
from telemetry.internal.backends.chrome_inspector import websocket
from telemetry.internal.browser import browser_options
from telemetry.internal.platform import system_info
from telemetry.page import shared_page_state
from telemetry.util import image_util
from telemetry.testing.internal import fake_gpu_info
from types import ModuleType


# Classes and functions which are intended to be part of the public
# fakes API.

class FakePlatform(object):
  def __init__(self):
    self._network_controller = None
    self._tracing_controller = None

  @property
  def is_host_platform(self):
    raise NotImplementedError

  @property
  def network_controller(self):
    if self._network_controller is None:
      self._network_controller = _FakeNetworkController()
    return  self._network_controller

  @property
  def tracing_controller(self):
    if self._tracing_controller is None:
      self._tracing_controller = _FakeTracingController()
    return  self._tracing_controller

  def Initialize(self):
    pass

  def CanMonitorThermalThrottling(self):
    return False

  def IsThermallyThrottled(self):
    return False

  def HasBeenThermallyThrottled(self):
    return False

  def GetDeviceTypeName(self):
    return 'FakeDevice'

  def GetArchName(self):
    raise NotImplementedError

  def GetOSName(self):
    return 'FakeOS'

  def GetOSVersionName(self):
    raise NotImplementedError

  def StopAllLocalServers(self):
    pass

  def WaitForTemperature(self, _):
    pass


class FakeLinuxPlatform(FakePlatform):
  def __init__(self):
    super(FakeLinuxPlatform, self).__init__()
    self.screenshot_png_data = None
    self.http_server_directories = []
    self.http_server = FakeHTTPServer()

  @property
  def is_host_platform(self):
    return True

  def GetDeviceTypeName(self):
    return 'Desktop'

  def GetArchName(self):
    return 'x86_64'

  def GetOSName(self):
    return 'linux'

  def GetOSVersionName(self):
    return 'trusty'

  def CanTakeScreenshot(self):
    return bool(self.screenshot_png_data)

  def TakeScreenshot(self, file_path):
    if not self.CanTakeScreenshot():
      raise NotImplementedError
    img = image_util.FromBase64Png(self.screenshot_png_data)
    image_util.WritePngFile(img, file_path)
    return True

  def SetHTTPServerDirectories(self, paths):
    self.http_server_directories.append(paths)


class FakeHTTPServer(object):
  def UrlOf(self, url):
    del url  # unused
    return 'file:///foo'


class FakePossibleBrowser(object):
  def __init__(self, execute_on_startup=None,
               execute_after_browser_creation=None):
    self._returned_browser = _FakeBrowser(FakeLinuxPlatform())
    self.browser_type = 'linux'
    self.supports_tab_control = False
    self.is_remote = False
    self.execute_on_startup = execute_on_startup
    self.execute_after_browser_creation = execute_after_browser_creation

  @property
  def returned_browser(self):
    """The browser object that will be returned through later API calls."""
    return self._returned_browser

  def Create(self, finder_options):
    if self.execute_on_startup is not None:
      self.execute_on_startup()
    del finder_options  # unused
    if self.execute_after_browser_creation is not None:
      self.execute_after_browser_creation(self._returned_browser)
    return self.returned_browser

  @property
  def platform(self):
    """The platform object from the returned browser.

    To change this or set it up, change the returned browser's
    platform.
    """
    return self.returned_browser.platform

  def IsRemote(self):
    return self.is_remote

  def SetCredentialsPath(self, _):
    pass


class FakeSharedPageState(shared_page_state.SharedPageState):
  def __init__(self, test, finder_options, story_set):
    super(FakeSharedPageState, self).__init__(test, finder_options, story_set)

  def _GetPossibleBrowser(self, test, finder_options):
    p = FakePossibleBrowser()
    self.ConfigurePossibleBrowser(p)
    return p

  def ConfigurePossibleBrowser(self, possible_browser):
    """Override this to configure the PossibleBrowser.

    Can make changes to the browser's configuration here via e.g.:
       possible_browser.returned_browser.returned_system_info = ...
    """
    pass


  def DidRunStory(self, results):
    # TODO(kbr): add a test which throws an exception from DidRunStory
    # to verify the fix from https://crrev.com/86984d5fc56ce00e7b37ebe .
    super(FakeSharedPageState, self).DidRunStory(results)


class FakeSystemInfo(system_info.SystemInfo):
  def __init__(self, model_name='', gpu_dict=None):
    if gpu_dict == None:
      gpu_dict = fake_gpu_info.FAKE_GPU_INFO
    super(FakeSystemInfo, self).__init__(model_name, gpu_dict)


class _FakeBrowserFinderOptions(browser_options.BrowserFinderOptions):
  def __init__(self, execute_on_startup=None,
               execute_after_browser_creation=None, *args, **kwargs):
    browser_options.BrowserFinderOptions.__init__(self, *args, **kwargs)
    self.fake_possible_browser = \
      FakePossibleBrowser(
        execute_on_startup=execute_on_startup,
        execute_after_browser_creation=execute_after_browser_creation)

def CreateBrowserFinderOptions(browser_type=None, execute_on_startup=None,
                               execute_after_browser_creation=None):
  """Creates fake browser finder options for discovering a browser."""
  return _FakeBrowserFinderOptions(
    browser_type=browser_type,
    execute_on_startup=execute_on_startup,
    execute_after_browser_creation=execute_after_browser_creation)


# Internal classes. Note that end users may still need to both call
# and mock out methods of these classes, but they should not be
# subclassed.

class _FakeBrowser(object):
  def __init__(self, platform):
    self._tabs = _FakeTabList(self)
    # Fake the creation of the first tab.
    self._tabs.New()
    self._returned_system_info = FakeSystemInfo()
    self._platform = platform
    self._browser_type = 'release'
    self._is_crashed = False

  @property
  def platform(self):
    return self._platform

  @platform.setter
  def platform(self, incoming):
    """Allows overriding of the fake browser's platform object."""
    assert isinstance(incoming, FakePlatform)
    self._platform = incoming

  @property
  def returned_system_info(self):
    """The object which will be returned from calls to GetSystemInfo."""
    return self._returned_system_info

  @returned_system_info.setter
  def returned_system_info(self, incoming):
    """Allows overriding of the returned SystemInfo object.

    Incoming argument must be an instance of FakeSystemInfo."""
    assert isinstance(incoming, FakeSystemInfo)
    self._returned_system_info = incoming

  @property
  def browser_type(self):
    """The browser_type this browser claims to be ('debug', 'release', etc.)"""
    return self._browser_type

  @browser_type.setter
  def browser_type(self, incoming):
    """Allows setting of the browser_type."""
    self._browser_type = incoming

  @property
  def credentials(self):
    return _FakeCredentials()

  def Close(self):
    self._is_crashed = False

  @property
  def supports_system_info(self):
    return True

  def GetSystemInfo(self):
    return self.returned_system_info

  @property
  def supports_tab_control(self):
    return True

  @property
  def tabs(self):
    return self._tabs

  def DumpStateUponFailure(self):
    pass


class _FakeCredentials(object):
  def WarnIfMissingCredentials(self, _):
    pass


class _FakeTracingController(object):
  def __init__(self):
    self._is_tracing = False

  def StartTracing(self, tracing_config, timeout=10):
    self._is_tracing = True
    del tracing_config
    del timeout

  def StopTracing(self):
    self._is_tracing = False

  @property
  def is_tracing_running(self):
    return self._is_tracing

  def ClearStateIfNeeded(self):
    pass

  def IsChromeTracingSupported(self):
    return True


class _FakeNetworkController(object):
  def __init__(self):
    self.wpr_mode = None
    self.extra_wpr_args = None
    self.is_initialized = False
    self.is_open = False
    self.use_live_traffic = None

  def InitializeIfNeeded(self, use_live_traffic=False):
    self.use_live_traffic = use_live_traffic

  def UpdateTrafficSettings(self, round_trip_latency_ms=None,
      download_bandwidth_kbps=None, upload_bandwidth_kbps=None):
    pass

  def Open(self, wpr_mode, extra_wpr_args):
    self.wpr_mode = wpr_mode
    self.extra_wpr_args = extra_wpr_args
    self.is_open = True

  def Close(self):
    self.wpr_mode = None
    self.extra_wpr_args = None
    self.is_initialized = False
    self.is_open = False

  def StartReplay(self, archive_path, make_javascript_deterministic=False):
    del make_javascript_deterministic  # Unused.
    assert self.is_open
    self.is_initialized = archive_path is not None

  def StopReplay(self):
    self.is_initialized = False


class _FakeTab(object):
  def __init__(self, browser, tab_id):
    self._browser = browser
    self._tab_id = str(tab_id)
    self._collect_garbage_count = 0
    self.test_png = None

  @property
  def collect_garbage_count(self):
    return self._collect_garbage_count

  @property
  def id(self):
    return self._tab_id

  @property
  def browser(self):
    return self._browser

  def WaitForDocumentReadyStateToBeComplete(self, timeout=0):
    pass

  def Navigate(self, url, script_to_evaluate_on_commit=None,
               timeout=0):
    del script_to_evaluate_on_commit, timeout # unused
    if url == 'chrome://crash':
      self.browser._is_crashed = True
      raise Exception

  def WaitForDocumentReadyStateToBeInteractiveOrBetter(self, timeout=0):
    pass

  def WaitForFrameToBeDisplayed(self, timeout=0):
    pass

  def IsAlive(self):
    return True

  def CloseConnections(self):
    pass

  def CollectGarbage(self):
    self._collect_garbage_count += 1

  def Close(self):
    pass

  @property
  def screenshot_supported(self):
    return self.test_png is not None

  def Screenshot(self):
    assert self.screenshot_supported, 'Screenshot is not supported'
    return image_util.FromBase64Png(self.test_png)


class _FakeTabList(object):
  _current_tab_id = 0

  def __init__(self, browser):
    self._tabs = []
    self._browser = browser

  def New(self, timeout=300):
    del timeout  # unused
    type(self)._current_tab_id += 1
    t = _FakeTab(self._browser, type(self)._current_tab_id)
    self._tabs.append(t)
    return t

  def __iter__(self):
    return self._tabs.__iter__()

  def __len__(self):
    return len(self._tabs)

  def __getitem__(self, index):
    if self._tabs[index].browser._is_crashed:
      raise Exception
    else:
      return self._tabs[index]

  def GetTabById(self, identifier):
    """The identifier of a tab can be accessed with tab.id."""
    for tab in self._tabs:
      if tab.id == identifier:
        return tab
    return None


class FakeInspectorWebsocket(object):
  _NOTIFICATION_EVENT = 1
  _NOTIFICATION_CALLBACK = 2

  """A fake InspectorWebsocket.

  A fake that allows tests to send pregenerated data. Normal
  InspectorWebsockets allow for any number of domain handlers. This fake only
  allows up to 1 domain handler, and assumes that the domain of the response
  always matches that of the handler.
  """
  def __init__(self, mock_timer):
    self._mock_timer = mock_timer
    self._notifications = []
    self._response_handlers = {}
    self._pending_callbacks = {}
    self._handler = None

  def RegisterDomain(self, _, handler):
    self._handler = handler

  def AddEvent(self, method, params, time):
    if self._notifications:
      assert self._notifications[-1][1] < time, (
          'Current response is scheduled earlier than previous response.')
    response = {'method': method, 'params': params}
    self._notifications.append((response, time, self._NOTIFICATION_EVENT))

  def AddAsyncResponse(self, method, result, time):
    if self._notifications:
      assert self._notifications[-1][1] < time, (
          'Current response is scheduled earlier than previous response.')
    response = {'method': method, 'result': result}
    self._notifications.append((response, time, self._NOTIFICATION_CALLBACK))

  def AddResponseHandler(self, method, handler):
    self._response_handlers[method] = handler

  def SyncRequest(self, request, *args, **kwargs):
    del args, kwargs  # unused
    handler = self._response_handlers[request['method']]
    return handler(request) if handler else None

  def AsyncRequest(self, request, callback):
    self._pending_callbacks.setdefault(request['method'], []).append(callback)

  def SendAndIgnoreResponse(self, request):
    pass

  def Connect(self, _):
    pass

  def DispatchNotifications(self, timeout):
    current_time = self._mock_timer.time()
    if not self._notifications:
      self._mock_timer.SetTime(current_time + timeout + 1)
      raise websocket.WebSocketTimeoutException()

    response, time, kind = self._notifications[0]
    if time - current_time > timeout:
      self._mock_timer.SetTime(current_time + timeout + 1)
      raise websocket.WebSocketTimeoutException()

    self._notifications.pop(0)
    self._mock_timer.SetTime(time + 1)
    if kind == self._NOTIFICATION_EVENT:
      self._handler(response)
    elif kind == self._NOTIFICATION_CALLBACK:
      callback = self._pending_callbacks.get(response['method']).pop(0)
      callback(response)
    else:
      raise Exception('Unexpected response type')


class FakeTimer(object):
  """ A fake timer to fake out the timing for a module.
    Args:
      module: module to fake out the time
  """
  def __init__(self, module=None):
    self._elapsed_time = 0
    self._module = module
    self._actual_time = None
    if module:
      assert isinstance(module, ModuleType)
      self._actual_time = module.time
      self._module.time = self

  def sleep(self, time):
    self._elapsed_time += time

  def time(self):
    return self._elapsed_time

  def SetTime(self, time):
    self._elapsed_time = time

  def __del__(self):
    self.Restore()

  def Restore(self):
    if self._module:
      self._module.time = self._actual_time
      self._module = None
      self._actual_time = None

