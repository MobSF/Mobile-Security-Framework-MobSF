# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


class RemotePlatformOptions(object):
  """Options to be used for creating a remote platform instance."""


class AndroidPlatformOptions(RemotePlatformOptions):
  """Android-specific remote platform options."""

  def __init__(self, device=None, android_blacklist_file=None):
    super(AndroidPlatformOptions, self).__init__()

    self.device = device
    self.android_blacklist_file = android_blacklist_file
