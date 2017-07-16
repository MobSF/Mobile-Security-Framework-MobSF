# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.core import platform as platform_module
from telemetry.internal.util import binary_manager

def FetchTelemetryDependencies(
  platform=None, client_configs=None, chrome_reference_browser=False):
  if not platform:
    platform = platform_module.GetHostPlatform()
  if binary_manager.NeedsInit():
    binary_manager.InitDependencyManager(client_configs)
  else:
    raise Exception('Binary manager already initialized with other configs.')
  binary_manager.FetchBinaryDependencies(
    platform, client_configs, chrome_reference_browser)
