# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import subprocess

from py_utils import cloud_storage  # pylint: disable=import-error

from telemetry.core import platform
from telemetry.util import image_util
from telemetry.util import rgba_color

HIGHLIGHT_ORANGE_FRAME = rgba_color.WEB_PAGE_TEST_ORANGE

class BoundingBoxNotFoundException(Exception):
  pass


class Video(object):
  """Utilities for storing and interacting with the video capture."""

  def __init__(self, video_file_obj):
    assert video_file_obj.delete
    assert not video_file_obj.close_called
    self._video_file_obj = video_file_obj
    self._tab_contents_bounding_box = None

  def UploadToCloudStorage(self, bucket, target_path):
    """Uploads video file to cloud storage.

    Args:
      target_path: Path indicating where to store the file in cloud storage.
    """
    cloud_storage.Insert(bucket, target_path, self._video_file_obj.name)

  def GetVideoFrameIter(self):
    """Returns the iteration for processing the video capture.

    This looks for the initial color flash in the first frame to establish the
    tab content boundaries and then omits all frames displaying the flash.

    Yields:
      (time_ms, image) tuples representing each video keyframe. Only the first
      frame is a run of sequential duplicate bitmaps is typically included.
        time_ms is milliseconds since navigationStart.
        image may be a telemetry.core.Bitmap, or a numpy array depending on
        whether numpy is installed.
    """
    frame_generator = self._FramesFromMp4(self._video_file_obj.name)

    # Flip through frames until we find the initial tab contents flash.
    content_box = None
    for _, bmp in frame_generator:
      content_box = self._FindHighlightBoundingBox(
          bmp, HIGHLIGHT_ORANGE_FRAME)
      if content_box:
        break

    if not content_box:
      raise BoundingBoxNotFoundException(
          'Failed to identify tab contents in video capture.')

    # Flip through frames until the flash goes away and emit that as frame 0.
    timestamp = 0
    for timestamp, bmp in frame_generator:
      if not self._FindHighlightBoundingBox(bmp, HIGHLIGHT_ORANGE_FRAME):
        yield 0, image_util.Crop(bmp, *content_box)
        break

    start_time = timestamp
    for timestamp, bmp in frame_generator:
      yield timestamp - start_time, image_util.Crop(bmp, *content_box)

  def _FindHighlightBoundingBox(self, bmp, color, bounds_tolerance=8,
                                color_tolerance=8):
    """Returns the bounding box of the content highlight of the given color.

    Raises:
      BoundingBoxNotFoundException if the hightlight could not be found.
    """
    content_box, pixel_count = image_util.GetBoundingBox(bmp, color,
        tolerance=color_tolerance)

    if not content_box:
      return None

    # We assume arbitrarily that tabs are all larger than 200x200. If this
    # fails it either means that assumption has changed or something is
    # awry with our bounding box calculation.
    if content_box[2] < 200 or content_box[3] < 200:
      raise BoundingBoxNotFoundException('Unexpectedly small tab contents.')

    # TODO(tonyg): Can this threshold be increased?
    if pixel_count < 0.9 * content_box[2] * content_box[3]:
      raise BoundingBoxNotFoundException(
          'Low count of pixels in tab contents matching expected color.')

    # Since we allow some fuzziness in bounding box finding, we want to make
    # sure that the bounds are always stable across a run. So we cache the
    # first box, whatever it may be.
    #
    # This relies on the assumption that since Telemetry doesn't know how to
    # resize the window, we should always get the same content box for a tab.
    # If this assumption changes, this caching needs to be reworked.
    if not self._tab_contents_bounding_box:
      self._tab_contents_bounding_box = content_box

    # Verify that there is only minor variation in the bounding box. If it's
    # just a few pixels, we can assume it's due to compression artifacts.
    for x, y in zip(self._tab_contents_bounding_box, content_box):
      if abs(x - y) > bounds_tolerance:
        # If this fails, it means either that either the above assumption has
        # changed or something is awry with our bounding box calculation.
        raise BoundingBoxNotFoundException(
            'Unexpected change in tab contents box.')

    return self._tab_contents_bounding_box

  def _FramesFromMp4(self, mp4_file):
    host_platform = platform.GetHostPlatform()
    if not host_platform.CanLaunchApplication('avconv'):
      host_platform.InstallApplication('avconv')

    def GetDimensions(video):
      proc = subprocess.Popen(['avconv', '-i', video], stderr=subprocess.PIPE)
      dimensions = None
      output = ''
      for line in proc.stderr.readlines():
        output += line
        if 'Video:' in line:
          dimensions = line.split(',')[2]
          dimensions = map(int, dimensions.split()[0].split('x'))
          break
      proc.communicate()
      assert dimensions, ('Failed to determine video dimensions. output=%s' %
                          output)
      return dimensions

    def GetFrameTimestampMs(stderr):
      """Returns the frame timestamp in integer milliseconds from the dump log.

      The expected line format is:
      '  dts=1.715  pts=1.715\n'

      We have to be careful to only read a single timestamp per call to avoid
      deadlock because avconv interleaves its writes to stdout and stderr.
      """
      while True:
        line = ''
        next_char = ''
        while next_char != '\n':
          next_char = stderr.read(1)
          line += next_char
        if 'pts=' in line:
          return int(1000 * float(line.split('=')[-1]))

    dimensions = GetDimensions(mp4_file)
    frame_length = dimensions[0] * dimensions[1] * 3
    frame_data = bytearray(frame_length)

    # Use rawvideo so that we don't need any external library to parse frames.
    proc = subprocess.Popen(['avconv', '-i', mp4_file, '-vcodec',
                             'rawvideo', '-pix_fmt', 'rgb24', '-dump',
                             '-loglevel', 'debug', '-f', 'rawvideo', '-'],
                            stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    while True:
      num_read = proc.stdout.readinto(frame_data)
      if not num_read:
        raise StopIteration
      assert num_read == len(frame_data), 'Unexpected frame size: %d' % num_read
      yield (GetFrameTimestampMs(proc.stderr),
             image_util.FromRGBPixels(dimensions[0], dimensions[1], frame_data))
