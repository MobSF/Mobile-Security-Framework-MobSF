# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os

from telemetry.core import discover
from telemetry.internal.platform import profiler
from telemetry.core import util


def _DiscoverProfilers():
  profiler_dir = os.path.dirname(__file__)
  return discover.DiscoverClasses(profiler_dir, util.GetTelemetryDir(),
                                  profiler.Profiler,
                                  index_by_class_name=True).values()


def FindProfiler(name):
  for p in _DiscoverProfilers():
    if p.name() == name:
      return p
  return None


def GetAllAvailableProfilers():
  return sorted([p.name() for p in _DiscoverProfilers()
                 if p.is_supported(browser_type='any')])
