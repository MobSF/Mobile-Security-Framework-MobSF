# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import time


class AndroidBrowserBackendSettings(object):

  def __init__(self, activity, cmdline_file, package, pseudo_exec_name,
               supports_tab_control):
    self._activity = activity
    self._cmdline_file = cmdline_file
    self._package = package
    self._pseudo_exec_name = pseudo_exec_name
    self._supports_tab_control = supports_tab_control

  @property
  def activity(self):
    return self._activity

  @property
  def package(self):
    return self._package

  @property
  def pseudo_exec_name(self):
    return self._pseudo_exec_name

  @property
  def supports_tab_control(self):
    return self._supports_tab_control

  @property
  def command_line_name(self):
    return self._cmdline_file

  def GetDevtoolsRemotePort(self, device):
    raise NotImplementedError()

  @property
  def profile_ignore_list(self):
    # Don't delete lib, since it is created by the installer.
    return ['lib']


class ChromeBackendSettings(AndroidBrowserBackendSettings):
  # Stores a default Preferences file, re-used to speed up "--page-repeat".
  _default_preferences_file = None

  def __init__(self, package):
    super(ChromeBackendSettings, self).__init__(
        activity='com.google.android.apps.chrome.Main',
        cmdline_file='chrome-command-line',
        package=package,
        pseudo_exec_name='chrome',
        supports_tab_control=True)

  def GetDevtoolsRemotePort(self, device):
    return 'localabstract:chrome_devtools_remote'


class ContentShellBackendSettings(AndroidBrowserBackendSettings):
  def __init__(self, package):
    super(ContentShellBackendSettings, self).__init__(
        activity='org.chromium.content_shell_apk.ContentShellActivity',
        cmdline_file='content-shell-command-line',
        package=package,
        pseudo_exec_name='content_shell',
        supports_tab_control=False)

  def GetDevtoolsRemotePort(self, device):
    return 'localabstract:content_shell_devtools_remote'


class WebviewBackendSettings(AndroidBrowserBackendSettings):
  def __init__(self,
               package,
               activity='org.chromium.webview_shell.TelemetryActivity',
               cmdline_file='webview-command-line'):
    super(WebviewBackendSettings, self).__init__(
        activity=activity,
        cmdline_file=cmdline_file,
        package=package,
        pseudo_exec_name='webview',
        supports_tab_control=False)

  def GetDevtoolsRemotePort(self, device):
    # The DevTools socket name for WebView depends on the activity PID's.
    retries = 0
    timeout = 1
    pid = None
    while True:
      pids = device.GetPids(self.package)
      if not pids or self.package not in pids:
        time.sleep(timeout)
        retries += 1
        timeout *= 2
        if retries == 4:
          logging.critical('android_browser_backend: Timeout while waiting for '
                           'activity %s:%s to come up',
                           self.package,
                           self.activity)
          raise Exception('Timeout waiting for PID.')
      if len(pids.get(self.package, [])) > 1:
        raise Exception(
            'At most one instance of process %s expected but found pids: '
            '%s' % (self.package, pids))
      if len(pids.get(self.package, [])) == 1:
        pid = pids[self.package][0]
        break
    return 'localabstract:webview_devtools_remote_%s' % str(pid)


class WebviewShellBackendSettings(WebviewBackendSettings):
  def __init__(self, package):
    super(WebviewShellBackendSettings, self).__init__(
        activity='org.chromium.android_webview.shell.AwShellActivity',
        cmdline_file='android-webview-command-line',
        package=package)
