# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.internal.image_processing import frame_generator
from telemetry.internal.util import external_modules

np = external_modules.ImportRequiredModule('numpy')


class FakeFrameGenerator(frame_generator.FrameGenerator):
  """ Fakes a Frame Generator, for testing.

  Attributes:
    _frame_index: A frame read counter.
    _timestamps: A generator of timestamps to return, or None.
    _timestamp: The current timestamp.
    _dimensions: The dimensions to return.
    _channels: The number of color channels to return in the generated frames.
    _frames: The number of frames to return before fake EOF."""
  def __init__(self, frames=1e16, dimensions=(320, 240), channels=3,
               timestamps=(x for x in iter(int, 1))):
    """ Initializes the FakeFrameGenerator object.

    Args:
      frames: int, The number of frames to return before fake EOF.
      dimensions: (int, int), The dimensions to return.
      timestamps: generator, A generator of timestamps to return. The default
          value is an infinite 0 generator.
      channels: int, The number of color channels to return in the generated
          frames, 1 for greyscale, 3 for RGB."""
    self._dimensions = dimensions
    self._timestamps = timestamps
    self._timestamp = 0
    self._frame_index = -1
    self._channels = channels
    self._frames = frames

    super(FakeFrameGenerator, self).__init__()

  # OVERRIDE
  def _CreateGenerator(self):
    while self._frame_index < self._frames - 1:
      self._frame_index += 1
      self._timestamp = next(self._timestamps)
      yield np.zeros((self._dimensions[0], self._dimensions[1],
                      self._channels), np.uint8)

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
