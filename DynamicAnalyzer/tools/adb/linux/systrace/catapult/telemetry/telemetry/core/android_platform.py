# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.core import android_action_runner
from telemetry.core import platform
from telemetry.internal.app import android_app
from telemetry.internal.backends import android_app_backend


class AndroidPlatform(platform.Platform):

  def __init__(self, platform_backend):
    super(AndroidPlatform, self).__init__(platform_backend)
    self._android_action_runner = android_action_runner.AndroidActionRunner(
        platform_backend)

  def Initialize(self):
    self._platform_backend.Initialize()

  @property
  def android_action_runner(self):
    return self._android_action_runner

  @property
  def system_ui(self):
    """Returns an AppUi object to interact with Android's system UI.

    See devil.android.app_ui for the documentation of the API provided.
    """
    return self._platform_backend.GetSystemUi()

  def IsSvelte(self):
    return self._platform_backend.IsSvelte()

  def LaunchAndroidApplication(self,
                               start_intent,
                               is_app_ready_predicate=None,
                               app_has_webviews=True):
    """Launches an Android application given the intent.

    Args:
      start_intent: The intent to use to start the app.
      is_app_ready_predicate: A predicate function to determine
          whether the app is ready. This is a function that takes an
          AndroidApp instance and return a boolean. When it is not passed in,
          the app is ready when the intent to launch it is completed.
      app_has_webviews: A boolean indicating whether the app is expected to
          contain any WebViews. If True, the app will be launched with
          appropriate webview flags, and the GetWebViews method of the returned
          object may be used to access them.

    Returns:
      A reference to the android_app launched.
    """
    self._platform_backend.DismissCrashDialogIfNeeded()
    app_backend = android_app_backend.AndroidAppBackend(
        self._platform_backend, start_intent, is_app_ready_predicate,
        app_has_webviews)
    return android_app.AndroidApp(app_backend, self._platform_backend)
