# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import pprint
import shlex
import sys

from telemetry.core import exceptions
from telemetry.core import util
from telemetry import decorators
from telemetry.internal.backends import browser_backend
from telemetry.internal.backends.chrome import extension_backend
from telemetry.internal.backends.chrome import system_info_backend
from telemetry.internal.backends.chrome import tab_list_backend
from telemetry.internal.backends.chrome_inspector import devtools_client_backend
from telemetry.internal.browser import user_agent
from telemetry.internal.browser import web_contents
from telemetry.testing import options_for_unittests

import py_utils


class ChromeBrowserBackend(browser_backend.BrowserBackend):
  """An abstract class for chrome browser backends. Provides basic functionality
  once a remote-debugger port has been established."""
  # It is OK to have abstract methods. pylint: disable=abstract-method

  def __init__(self, platform_backend, supports_tab_control,
               supports_extensions, browser_options):
    super(ChromeBrowserBackend, self).__init__(
        platform_backend=platform_backend,
        supports_extensions=supports_extensions,
        browser_options=browser_options,
        tab_list_backend=tab_list_backend.TabListBackend)
    self._port = None

    self._supports_tab_control = supports_tab_control
    self._devtools_client = None
    self._system_info_backend = None

    self._output_profile_path = browser_options.output_profile_path
    self._extensions_to_load = browser_options.extensions_to_load

    if (self.browser_options.dont_override_profile and
        not options_for_unittests.AreSet()):
      sys.stderr.write('Warning: Not overriding profile. This can cause '
                       'unexpected effects due to profile-specific settings, '
                       'such as about:flags settings, cookies, and '
                       'extensions.\n')

  @property
  def devtools_client(self):
    return self._devtools_client

  @property
  @decorators.Cache
  def extension_backend(self):
    if not self.supports_extensions:
      return None
    return extension_backend.ExtensionBackendDict(self)

  def _ArgsNeedProxyServer(self, args):
    """Returns True if args for Chrome indicate the need for proxy server."""
    if '--enable-spdy-proxy-auth' in args:
      return True
    return [arg for arg in args if arg.startswith('--proxy-server=')]

  def GetBrowserStartupArgs(self):
    assert not '--no-proxy-server' in self.browser_options.extra_browser_args, (
        '--no-proxy-server flag is disallowed as Chrome needs to be route to '
        'ts_proxy_server')
    args = []
    args.extend(self.browser_options.extra_browser_args)
    args.append('--enable-net-benchmarking')
    args.append('--metrics-recording-only')
    args.append('--no-default-browser-check')
    args.append('--no-first-run')

    # Turn on GPU benchmarking extension for all runs. The only side effect of
    # the extension being on is that render stats are tracked. This is believed
    # to be effectively free. And, by doing so here, it avoids us having to
    # programmatically inspect a pageset's actions in order to determine if it
    # might eventually scroll.
    args.append('--enable-gpu-benchmarking')

    if self.browser_options.disable_background_networking:
      args.append('--disable-background-networking')
    args.extend(self.GetReplayBrowserStartupArgs())
    args.extend(user_agent.GetChromeUserAgentArgumentFromType(
        self.browser_options.browser_user_agent_type))

    extensions = [extension.local_path
                  for extension in self._extensions_to_load]
    extension_str = ','.join(extensions)
    if len(extensions) > 0:
      args.append('--load-extension=%s' % extension_str)

    if self.browser_options.disable_component_extensions_with_background_pages:
      args.append('--disable-component-extensions-with-background-pages')

    # Disables the start page, as well as other external apps that can
    # steal focus or make measurements inconsistent.
    if self.browser_options.disable_default_apps:
      args.append('--disable-default-apps')

    # Disable the search geolocation disclosure infobar, as it is only shown a
    # small number of times to users and should not be part of perf comparisons.
    args.append('--disable-search-geolocation-disclosure')

    if (self.browser_options.logging_verbosity ==
        self.browser_options.NON_VERBOSE_LOGGING):
      args.extend(['--enable-logging', '--v=0'])
    elif (self.browser_options.logging_verbosity ==
          self.browser_options.VERBOSE_LOGGING):
      args.extend(['--enable-logging', '--v=1'])

    return args

  def GetReplayBrowserStartupArgs(self):
    replay_args = []
    network_backend = self.platform_backend.network_controller_backend
    if not network_backend.is_initialized:
      return []
    proxy_port = network_backend.forwarder.port_pair.remote_port
    replay_args.append('--proxy-server=socks://localhost:%s' % proxy_port)
    if not network_backend.is_test_ca_installed:
      # Ignore certificate errors if the platform backend has not created
      # and installed a root certificate.
      replay_args.append('--ignore-certificate-errors')
    return replay_args

  def HasBrowserFinishedLaunching(self):
    assert self._port, 'No DevTools port info available.'
    return devtools_client_backend.IsDevToolsAgentAvailable(self._port, self)

  def _InitDevtoolsClientBackend(self, remote_devtools_port=None):
    """ Initiate the devtool client backend which allow browser connection
    through browser' devtool.

    Args:
      remote_devtools_port: The remote devtools port, if
          any. Otherwise assumed to be the same as self._port.
    """
    assert not self._devtools_client, (
        'Devtool client backend cannot be init twice')
    self._devtools_client = devtools_client_backend.DevToolsClientBackend(
        self._port, remote_devtools_port or self._port, self)

  def _WaitForBrowserToComeUp(self):
    """ Wait for browser to come up. """
    try:
      timeout = self.browser_options.browser_startup_timeout
      py_utils.WaitFor(self.HasBrowserFinishedLaunching, timeout=timeout)
    except (py_utils.TimeoutException, exceptions.ProcessGoneException) as e:
      if not self.IsBrowserRunning():
        raise exceptions.BrowserGoneException(self.browser, e)
      raise exceptions.BrowserConnectionGoneException(self.browser, e)

  def _WaitForExtensionsToLoad(self):
    """ Wait for all extensions to load.
    Be sure to check whether the browser_backend supports_extensions before
    calling this method.
    """
    assert self._supports_extensions
    assert self._devtools_client, (
        'Waiting for extensions required devtool client to be initiated first')
    try:
      py_utils.WaitFor(self._AllExtensionsLoaded, timeout=60)
    except py_utils.TimeoutException:
      logging.error('ExtensionsToLoad: ' +
          repr([e.extension_id for e in self._extensions_to_load]))
      logging.error('Extension list: ' +
          pprint.pformat(self.extension_backend, indent=4))
      raise

  def _AllExtensionsLoaded(self):
    # Extension pages are loaded from an about:blank page,
    # so we need to check that the document URL is the extension
    # page in addition to the ready state.
    for e in self._extensions_to_load:
      try:
        extension_objects = self.extension_backend[e.extension_id]
      except KeyError:
        return False
      for extension_object in extension_objects:
        try:
          res = extension_object.EvaluateJavaScript("""
              document.URL.lastIndexOf({{ url }}, 0) == 0 &&
              (document.readyState == 'complete' ||
               document.readyState == 'interactive')
              """,
              url='chrome-extension://%s/' % e.extension_id)
        except exceptions.EvaluateException:
          # If the inspected page is not ready, we will get an error
          # when we evaluate a JS expression, but we can just keep polling
          # until the page is ready (crbug.com/251913).
          res = None

        # TODO(tengs): We don't have full support for getting the Chrome
        # version before launch, so for now we use a generic workaround to
        # check for an extension binding bug in old versions of Chrome.
        # See crbug.com/263162 for details.
        if res and extension_object.EvaluateJavaScript(
            'chrome.runtime == null'):
          extension_object.Reload()
        if not res:
          return False
    return True

  @property
  def browser_directory(self):
    raise NotImplementedError()

  @property
  def profile_directory(self):
    raise NotImplementedError()

  @property
  def supports_tab_control(self):
    return self._supports_tab_control

  @property
  def supports_tracing(self):
    return True

  def StartTracing(self, trace_options,
                   timeout=web_contents.DEFAULT_WEB_CONTENTS_TIMEOUT):
    """
    Args:
        trace_options: An tracing_options.TracingOptions instance.
    """
    return self.devtools_client.StartChromeTracing(trace_options, timeout)

  def StopTracing(self):
    self.devtools_client.StopChromeTracing()

  def CollectTracingData(self, trace_data_builder):
    self.devtools_client.CollectChromeTracingData(trace_data_builder)

  def GetProcessName(self, cmd_line):
    """Returns a user-friendly name for the process of the given |cmd_line|."""
    if not cmd_line:
      # TODO(tonyg): Eventually we should make all of these known and add an
      # assertion.
      return 'unknown'
    if 'nacl_helper_bootstrap' in cmd_line:
      return 'nacl_helper_bootstrap'
    if ':sandboxed_process' in cmd_line:
      return 'renderer'
    if ':privileged_process' in cmd_line:
      return 'gpu-process'
    args = shlex.split(cmd_line)
    types = [arg.split('=')[1] for arg in args if arg.startswith('--type=')]
    if not types:
      return 'browser'
    return types[0]

  def Close(self):
    if self._devtools_client:
      self._devtools_client.Close()
      self._devtools_client = None

  @property
  def supports_system_info(self):
    return self.GetSystemInfo() != None

  def GetSystemInfo(self):
    if self._system_info_backend is None:
      self._system_info_backend = system_info_backend.SystemInfoBackend(
          self._port)
    # TODO(crbug.com/706336): Remove this condional branch once crbug.com/704024
    # is fixed.
    if util.IsRunningOnCrosDevice():
      return self._system_info_backend.GetSystemInfo(timeout=30)
    return self._system_info_backend.GetSystemInfo()

  @property
  def supports_memory_dumping(self):
    return True

  def DumpMemory(self, timeout=web_contents.DEFAULT_WEB_CONTENTS_TIMEOUT):
    return self.devtools_client.DumpMemory(timeout)

  @property
  def supports_overriding_memory_pressure_notifications(self):
    return True

  def SetMemoryPressureNotificationsSuppressed(
      self, suppressed, timeout=web_contents.DEFAULT_WEB_CONTENTS_TIMEOUT):
    self.devtools_client.SetMemoryPressureNotificationsSuppressed(
        suppressed, timeout)

  def SimulateMemoryPressureNotification(
      self, pressure_level, timeout=web_contents.DEFAULT_WEB_CONTENTS_TIMEOUT):
    self.devtools_client.SimulateMemoryPressureNotification(
        pressure_level, timeout)

  @property
  def supports_cpu_metrics(self):
    return True

  @property
  def supports_memory_metrics(self):
    return True

  @property
  def supports_power_metrics(self):
    return True
