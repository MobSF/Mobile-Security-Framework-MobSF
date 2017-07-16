# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import tempfile

from telemetry import decorators
from telemetry.core import os_version
from telemetry.util import image_util
from telemetry.testing import tab_test_case


class PlatformScreenshotTest(tab_test_case.TabTestCase):

  def testScreenshotSupported(self):
    if self._platform.GetOSName() == 'android':
      self.assertTrue(self._platform.CanTakeScreenshot())

  # Run this test in serial to avoid multiple browsers pop up on the screen.
  @decorators.Isolated
  @decorators.Disabled('linux')  # crbug.com/563656
  @decorators.Disabled('mac')  # crbug.com/660587
  def testScreenshot(self):
    if not self._platform.CanTakeScreenshot():
      self.skipTest('Platform does not support screenshots, skipping test.')
    # Skip the test on Mac 10.5, 10.6, 10.7 because png format isn't
    # recognizable on Mac < 10.8 (crbug.com/369490#c13)
    if (self._platform.GetOSName() == 'mac' and
        self._platform.GetOSVersionName() in
        (os_version.LEOPARD, os_version.SNOWLEOPARD, os_version.LION)):
      self.skipTest('OS X version %s too old' % self._platform.GetOSName())
    tf = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
    tf.close()
    try:
      self.Navigate('screenshot_test.html')
      self._platform.TakeScreenshot(tf.name)
      # Assert that screenshot image contains the color of the triangle defined
      # in screenshot_test.html.
      img = image_util.FromPngFile(tf.name)
      screenshot_pixels = image_util.Pixels(img)
      special_colored_pixel = bytearray([217, 115, 43])
      self.assertTrue(special_colored_pixel in screenshot_pixels)
    finally:
      os.remove(tf.name)
