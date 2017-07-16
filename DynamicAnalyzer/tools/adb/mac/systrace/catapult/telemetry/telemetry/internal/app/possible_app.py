# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


class PossibleApp(object):
  """A factory class that can be used to create a running instance of app.

  Call Create() to launch the app and begin manipulating it.
  """

  def __init__(self, app_type, target_os):
    self._app_type = app_type
    self._target_os = target_os
    self._platform = None
    self._platform_backend = None

  def __repr__(self):
    return 'PossibleApp(app_type=%s)' % self.app_type

  @property
  def app_type(self):
    return self._app_type

  @property
  def target_os(self):
    """Target OS, the app will run on."""
    return self._target_os

  @property
  def platform(self):
    self._InitPlatformIfNeeded()
    return self._platform

  def _InitPlatformIfNeeded(self):
    raise NotImplementedError()

  def Create(self, finder_options):
    raise NotImplementedError()

  def SupportsOptions(self, browser_options):
    """Tests for extension support."""
    raise NotImplementedError()
