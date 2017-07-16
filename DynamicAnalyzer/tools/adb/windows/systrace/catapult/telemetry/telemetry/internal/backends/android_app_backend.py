# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import re

from telemetry.internal.app import android_process
from telemetry.internal.backends import android_browser_backend_settings
from telemetry.internal.backends import app_backend

from devil.android import app_ui
from devil.android import flag_changer
from devil.android.sdk import intent

import py_utils


class AndroidAppBackend(app_backend.AppBackend):

  def __init__(self, android_platform_backend, start_intent,
               is_app_ready_predicate=None, app_has_webviews=True):
    super(AndroidAppBackend, self).__init__(
        start_intent.package, android_platform_backend)
    self._default_process_name = start_intent.package
    self._start_intent = start_intent
    self._is_app_ready_predicate = is_app_ready_predicate
    self._is_running = False
    self._app_has_webviews = app_has_webviews
    self._existing_processes_by_pid = {}
    self._app_ui = None

  @property
  def device(self):
    return self.platform_backend.device

  def GetAppUi(self):
    if self._app_ui is None:
      self._app_ui = app_ui.AppUi(self.device, self._start_intent.package)
    return self._app_ui

  def _LaunchAndWaitForApplication(self):
    """Launch the app and wait for it to be ready."""
    def is_app_ready():
      return self._is_app_ready_predicate(self.app)

    # When "is_app_ready_predicate" is provided, we use it to wait for the
    # app to become ready, otherwise "blocking=True" is used as a fall back.
    # TODO(slamm): check if the wait for "ps" check is really needed, or
    # whether the "blocking=True" fall back is sufficient.
    has_ready_predicate = self._is_app_ready_predicate is not None
    self.device.StartActivity(
        self._start_intent,
        blocking=not has_ready_predicate,
        force_stop=True,  # Ensure app was not running.
    )
    if has_ready_predicate:
      py_utils.WaitFor(is_app_ready, timeout=60)

  def Start(self):
    """Start an Android app and wait for it to finish launching.

    If the app has webviews, the app is launched with the suitable
    command line arguments.

    AppStory derivations can customize the wait-for-ready-state to wait
    for a more specific event if needed.
    """
    if self._app_has_webviews:
      webview_startup_args = self.GetWebviewStartupArgs()
      command_line_name = (
          android_browser_backend_settings.WebviewBackendSettings(
              'android-webview')).command_line_name
      with flag_changer.CustomCommandLineFlags(
          self.device, command_line_name, webview_startup_args):
        self._LaunchAndWaitForApplication()
    else:
      self._LaunchAndWaitForApplication()
    self._is_running = True

  def Foreground(self):
    self.device.StartActivity(
        intent.Intent(package=self._start_intent.package,
                      activity=self._start_intent.activity,
                      action=None,
                      flags=[intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED]),
        blocking=True)

  def Background(self):
    package = 'org.chromium.push_apps_to_background'
    activity = package + '.PushAppsToBackgroundActivity'
    self.device.StartActivity(
        intent.Intent(
            package=package,
            activity=activity,
            action=None,
            flags=[intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED]),
        blocking=True)

  def Close(self):
    self._is_running = False
    self.platform_backend.KillApplication(self._start_intent.package)

  def IsAppRunning(self):
    return self._is_running

  def GetStandardOutput(self):
    raise NotImplementedError

  def GetStackTrace(self):
    raise NotImplementedError

  def GetProcesses(self, process_filter=None):
    if process_filter is None:
      # Match process names of the form: 'process_name[:subprocess]'.
      process_filter = re.compile(
          '^%s(:|$)' % re.escape(self._default_process_name)).match

    processes = set()
    ps_output = self.platform_backend.GetPsOutput(['pid', 'name'])
    for pid, name in ps_output:
      if not process_filter(name):
        continue

      if pid not in self._existing_processes_by_pid:
        self._existing_processes_by_pid[pid] = android_process.AndroidProcess(
            self, pid, name)
      processes.add(self._existing_processes_by_pid[pid])
    return processes

  def GetProcess(self, subprocess_name):
    assert subprocess_name.startswith(':')
    process_name = self._default_process_name + subprocess_name
    return self.GetProcesses(lambda n: n == process_name).pop()

  def GetWebViews(self):
    assert self._app_has_webviews
    webviews = set()
    for process in self.GetProcesses():
      webviews.update(process.GetWebViews())
    return webviews

  def GetWebviewStartupArgs(self):
    assert self._app_has_webviews
    args = []

    # Turn on GPU benchmarking extension for all runs. The only side effect of
    # the extension being on is that render stats are tracked. This is believed
    # to be effectively free. And, by doing so here, it avoids us having to
    # programmatically inspect a pageset's actions in order to determine if it
    # might eventually scroll.
    args.append('--enable-gpu-benchmarking')

    return args
