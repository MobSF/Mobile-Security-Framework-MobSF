# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import os

from telemetry.core import exceptions
from telemetry.core import util
from telemetry import decorators
from telemetry.internal.backends.chrome import chrome_browser_backend
from telemetry.internal.backends.chrome import misc_web_contents_backend
from telemetry.internal import forwarders

import py_utils


class CrOSBrowserBackend(chrome_browser_backend.ChromeBrowserBackend):
  def __init__(self, cros_platform_backend, browser_options, cri, is_guest):
    super(CrOSBrowserBackend, self).__init__(
        cros_platform_backend, supports_tab_control=True,
        supports_extensions=not is_guest,
        browser_options=browser_options)
    assert browser_options.IsCrosBrowserOptions()
    # Initialize fields so that an explosion during init doesn't break in Close.
    self._cri = cri
    self._is_guest = is_guest
    self._forwarder = None
    self._remote_debugging_port = self._cri.GetRemotePort()
    self._port = self._remote_debugging_port

    extensions_to_load = browser_options.extensions_to_load

    # Copy extensions to temp directories on the device.
    # Note that we also perform this copy locally to ensure that
    # the owner of the extensions is set to chronos.
    for e in extensions_to_load:
      extension_dir = cri.RunCmdOnDevice(
          ['mktemp', '-d', '/tmp/extension_XXXXX'])[0].rstrip()
      e.local_path = os.path.join(extension_dir, os.path.basename(e.path))
      cri.PushFile(e.path, extension_dir)
      cri.Chown(extension_dir)

    self._cri.RestartUI(self.browser_options.clear_enterprise_policy)
    py_utils.WaitFor(self.IsBrowserRunning, 20)

    # Delete test user's cryptohome vault (user data directory).
    if not self.browser_options.dont_override_profile:
      self._cri.RunCmdOnDevice(['cryptohome', '--action=remove', '--force',
                                '--user=%s' % self._username])

  @property
  def log_file_path(self):
    return None

  def GetBrowserStartupArgs(self):
    args = super(CrOSBrowserBackend, self).GetBrowserStartupArgs()

    logging_patterns = ['*/chromeos/net/*',
                        '*/chromeos/login/*',
                        'chrome_browser_main_posix']
    vmodule = '--vmodule='
    for pattern in logging_patterns:
      vmodule += '%s=2,' % pattern
    vmodule = vmodule.rstrip(',')

    args.extend([
            '--enable-smooth-scrolling',
            '--enable-threaded-compositing',
            # Allow devtools to connect to chrome.
            '--remote-debugging-port=%i' % self._remote_debugging_port,
            # Open a maximized window.
            '--start-maximized',
            # Disable system startup sound.
            '--ash-disable-system-sounds',
            # Ignore DMServer errors for policy fetches.
            '--allow-failed-policy-fetch-for-test',
            # Skip user image selection screen, and post login screens.
            '--oobe-skip-postlogin',
            # Debug logging.
            vmodule])

    # Disable GAIA services unless we're using GAIA login, or if there's an
    # explicit request for it.
    if (self.browser_options.disable_gaia_services and
        not self.browser_options.gaia_login):
      args.append('--disable-gaia-services')

    trace_config_file = (self.platform_backend.tracing_controller_backend
                         .GetChromeTraceConfigFile())
    if trace_config_file:
      args.append('--trace-config-file=%s' % trace_config_file)

    return args

  @property
  def pid(self):
    return self._cri.GetChromePid()

  @property
  def browser_directory(self):
    result = self._cri.GetChromeProcess()
    if result and 'path' in result:
      return os.path.dirname(result['path'])
    return None

  @property
  def profile_directory(self):
    return '/home/chronos/Default'

  def __del__(self):
    self.Close()

  def Start(self):
    # Escape all commas in the startup arguments we pass to Chrome
    # because dbus-send delimits array elements by commas
    startup_args = [a.replace(',', '\\,') for a in self.GetBrowserStartupArgs()]

    # Restart Chrome with the login extension and remote debugging.
    pid = self.pid
    logging.info('Restarting Chrome (pid=%d) with remote port', pid)
    args = ['dbus-send', '--system', '--type=method_call',
            '--dest=org.chromium.SessionManager',
            '/org/chromium/SessionManager',
            'org.chromium.SessionManagerInterface.EnableChromeTesting',
            'boolean:true',
            'array:string:"%s"' % ','.join(startup_args)]
    logging.info(' '.join(args))
    self._cri.RunCmdOnDevice(args)

    if not self._cri.local:
      # TODO(crbug.com/404771): Move port forwarding to network_controller.
      self._port = util.GetUnreservedAvailableLocalPort()
      self._forwarder = self._platform_backend.forwarder_factory.Create(
          forwarders.PortPair(self._port, self._remote_debugging_port),
          use_remote_port_forwarding=False)

    # Wait for new chrome and oobe.
    py_utils.WaitFor(lambda: pid != self.pid, 15)
    self._WaitForBrowserToComeUp()
    self._InitDevtoolsClientBackend(
        remote_devtools_port=self._remote_debugging_port)
    py_utils.WaitFor(lambda: self.oobe_exists, 30)

    if self.browser_options.auto_login:
      if self._is_guest:
        pid = self.pid
        self.oobe.NavigateGuestLogin()
        # Guest browsing shuts down the current browser and launches an
        # incognito browser in a separate process, which we need to wait for.
        try:
          # TODO(achuith): Reduce this timeout to 15 sec after crbug.com/631640
          # is resolved.
          py_utils.WaitFor(lambda: pid != self.pid, 60)
        except py_utils.TimeoutException:
          self._RaiseOnLoginFailure(
              'Failed to restart browser in guest mode (pid %d).' % pid)

      elif self.browser_options.gaia_login:
        self.oobe.NavigateGaiaLogin(self._username, self._password)
      else:
        self.oobe.NavigateFakeLogin(self._username, self._password,
            self._gaia_id, not self.browser_options.disable_gaia_services)

      try:
        self._WaitForLogin()
      except py_utils.TimeoutException:
        self._RaiseOnLoginFailure('Timed out going through login screen. '
                                  + self._GetLoginStatus())

    logging.info('Browser is up!')

  def Background(self):
    raise NotImplementedError

  def Close(self):
    super(CrOSBrowserBackend, self).Close()

    if self._cri:
      self._cri.RestartUI(False) # Logs out.
      self._cri.CloseConnection()

    py_utils.WaitFor(lambda: not self._IsCryptohomeMounted(), 180)

    if self._forwarder:
      self._forwarder.Close()
      self._forwarder = None

    if self._cri:
      for e in self._extensions_to_load:
        self._cri.RmRF(os.path.dirname(e.local_path))

    self._cri = None

  def IsBrowserRunning(self):
    return bool(self.pid)

  def GetStandardOutput(self):
    return 'Cannot get standard output on CrOS'

  def GetStackTrace(self):
    return (False, 'Cannot get stack trace on CrOS')

  def GetMostRecentMinidumpPath(self):
    return None

  def GetAllMinidumpPaths(self):
    return None

  def GetAllUnsymbolizedMinidumpPaths(self):
    return None

  def SymbolizeMinidump(self, minidump_path):
    return None

  @property
  @decorators.Cache
  def misc_web_contents_backend(self):
    """Access to chrome://oobe/login page."""
    return misc_web_contents_backend.MiscWebContentsBackend(self)

  @property
  def oobe(self):
    return self.misc_web_contents_backend.GetOobe()

  @property
  def oobe_exists(self):
    return self.misc_web_contents_backend.oobe_exists

  @property
  def _username(self):
    return self.browser_options.username

  @property
  def _password(self):
    return self.browser_options.password

  @property
  def _gaia_id(self):
    return self.browser_options.gaia_id

  def _IsCryptohomeMounted(self):
    username = '$guest' if self._is_guest else self._username
    return self._cri.IsCryptohomeMounted(username, self._is_guest)

  def _GetLoginStatus(self):
    """Returns login status. If logged in, empty string is returned."""
    status = ''
    if not self._IsCryptohomeMounted():
      status += 'Cryptohome not mounted. '
    if not self.HasBrowserFinishedLaunching():
      status += 'Browser didn\'t launch. '
    if self.oobe_exists:
      status += 'OOBE not dismissed.'
    return status

  def _IsLoggedIn(self):
    """Returns True if cryptohome has mounted, the browser is
    responsive to devtools requests, and the oobe has been dismissed."""
    return not self._GetLoginStatus()

  def _WaitForLogin(self):
    # Wait for cryptohome to mount.
    py_utils.WaitFor(self._IsLoggedIn, 900)

    # For incognito mode, the session manager actually relaunches chrome with
    # new arguments, so we have to wait for the browser to come up.
    self._WaitForBrowserToComeUp()

    # Wait for extensions to load.
    if self._supports_extensions:
      self._WaitForExtensionsToLoad()

  def _RaiseOnLoginFailure(self, error):
    if self._platform_backend.CanTakeScreenshot():
      self._cri.TakeScreenshotWithPrefix('login-screen')
    raise exceptions.LoginException(error)
