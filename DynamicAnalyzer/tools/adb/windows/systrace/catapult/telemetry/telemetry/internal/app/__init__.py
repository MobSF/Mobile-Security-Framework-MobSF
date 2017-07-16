# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


class App(object):
  """ A running application instance that can be controlled in a limited way.

  Be sure to clean up after yourself by calling Close() when you are done with
  the app. Or better yet:
    with possible_app.Create(options) as app:
      ... do all your operations on app here
  """
  def __init__(self, app_backend, platform_backend):
    assert platform_backend.platform != None
    self._app_backend = app_backend
    self._platform_backend = platform_backend
    self._app_backend.SetApp(self)

  @property
  def app_type(self):
    return self._app_backend.app_type

  @property
  def platform(self):
    return self._platform_backend.platform

  def __enter__(self):
    return self

  def __exit__(self, *args):
    self.Close()

  def Close(self):
    raise NotImplementedError()

  def GetStandardOutput(self):
    return self._app_backend.GetStandardOutput()

  def GetStackTrace(self):
    return self._app_backend.GetStackTrace()

  def GetMostRecentMinidumpPath(self):
    return self._app_backend.GetMostRecentMinidumpPath()
