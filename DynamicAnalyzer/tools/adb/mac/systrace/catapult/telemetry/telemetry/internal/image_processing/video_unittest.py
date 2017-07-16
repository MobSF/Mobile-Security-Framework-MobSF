# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import os
import unittest

from telemetry.core import platform
from telemetry.core import util
from telemetry import decorators
from telemetry.internal.image_processing import video
from telemetry.util import image_util


class VideoTest(unittest.TestCase):

  @decorators.Disabled('all')
  def testFramesFromMp4(self):
    host_platform = platform.GetHostPlatform()

    try:
      host_platform.InstallApplication('avconv')
    finally:
      if not host_platform.CanLaunchApplication('avconv'):
        logging.warning('Test not supported on this platform')
        return  # pylint: disable=lost-exception

    vid = os.path.join(util.GetUnittestDataDir(), 'vid.mp4')
    expected_timestamps = [
      0,
      763,
      783,
      940,
      1715,
      1732,
      1842,
      1926,
      ]

    video_obj = video.Video(vid)

    # Calling _FramesFromMp4 should return all frames.
    # pylint: disable=protected-access
    for i, timestamp_bitmap in enumerate(video_obj._FramesFromMp4(vid)):
      timestamp, bmp = timestamp_bitmap
      self.assertEquals(timestamp, expected_timestamps[i])
      expected_bitmap = image_util.FromPngFile(os.path.join(
          util.GetUnittestDataDir(), 'frame%d.png' % i))
      self.assertTrue(image_util.AreEqual(expected_bitmap, bmp))
