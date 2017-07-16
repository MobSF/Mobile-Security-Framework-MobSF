# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os

from telemetry.core import util

BASE_PROFILE_TYPES = ['clean', 'default']

PROFILE_TYPE_MAPPING = {
  'typical_user': 'content_scripts1',
  'power_user': 'extension_webrequest',
}

def GetProfileTypes():
  """Returns a list of all command line options that can be specified for
  profile type."""
  return BASE_PROFILE_TYPES + PROFILE_TYPE_MAPPING.keys()

def GetProfileDir(profile_type):
  """Given a |profile_type| (as returned by GetProfileTypes()), return the
  directory to use for that profile or None if the profile doesn't need a
  profile directory (e.g. using the browser default profile).
  """
  if profile_type in BASE_PROFILE_TYPES:
    return None

  path = os.path.join(
      util.GetTelemetryDir(), 'telemetry', 'internal', 'browser_profiles')

  assert os.path.exists(path)
  return path
