# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.internal.image_processing import frame_generator
from telemetry.internal.util import external_modules

cv2 = external_modules.ImportRequiredModule('cv2')


class VideoFileFrameGenerator(frame_generator.FrameGenerator):
  """Provides a Frame Generator for a video file.

  Sample Usage:
    generator = VideoFileFrameGenerator(sys.argv[1]).GetGenerator()
    for frame in generator:
      # Do something

  Attributes:
    _capture: The openCV video capture.
    _frame_count: The number of frames in the video capture.
    _frame_index: The frame number of the current frame.
    _timestamp: The timestamp of the current frame.
    _dimensions: The dimensions of the video capture."""
  def __init__(self, video_filename, start_frame_index=0):
    """Initializes the VideoFileFrameGenerator object.

    Args:
      video_filename: str, The path to the video file.
      start_frame_index: int, The number of frames to skip at the start of the
          file.

    Raises:
      FrameReadError: A read error occurred during initialization."""
    self._capture = cv2.VideoCapture(video_filename)
    self._frame_count = int(self._capture.get(cv2.cv.CV_CAP_PROP_FRAME_COUNT))
    self._frame_index = -1
    self._timestamp = 0
    width = self._capture.get(cv2.cv.CV_CAP_PROP_FRAME_WIDTH)
    height = self._capture.get(cv2.cv.CV_CAP_PROP_FRAME_HEIGHT)
    self._dimensions = (int(width), int(height))
    if self._frame_count <= start_frame_index:
      raise frame_generator.FrameReadError('Not enough frames in capture.')
    while self._frame_index < start_frame_index - 1:
      self._ReadFrame(True)

    super(self.__class__, self).__init__()

  def _ReadFrame(self, skip_decode=False):
    """Reads the next frame, updates attributes.

    Args:
      skip_decode: Whether or not to skip decoding. Useful for seeking.

    Returns:
      The frame if not EOF, 'None' if EOF.

    Raises:
      FrameReadError: Unexpectedly failed to read a frame from the capture."""
    if self._frame_index >= self._frame_count - 1:
      return None
    self._timestamp = self._capture.get(cv2.cv.CV_CAP_PROP_POS_MSEC)
    if skip_decode:
      ret = self._capture.grab()
      frame = None
    else:
      ret, frame = self._capture.read()
    if not ret:
      raise frame_generator.FrameReadError(
          'Failed to read frame from capture.')
    self._frame_index += 1
    return frame

  # OVERRIDE
  def _CreateGenerator(self):
    while True:
      frame = self._ReadFrame()
      if frame is None:
        break
      yield frame

  # OVERRIDE
  @property
  def CurrentTimestamp(self):
    return self._timestamp

  # OVERRIDE
  @property
  def CurrentFrameNumber(self):
    return self._frame_index

  # OVERRIDE
  @property
  def Dimensions(self):
    return self._dimensions
