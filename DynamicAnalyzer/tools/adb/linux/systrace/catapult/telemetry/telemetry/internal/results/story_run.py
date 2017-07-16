# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.value import failure
from telemetry.value import skip


class StoryRun(object):
  def __init__(self, story):
    self._story = story
    self._values = []

  def AddValue(self, value):
    self._values.append(value)

  @property
  def story(self):
    return self._story

  @property
  def values(self):
    """The values that correspond to this story run."""
    return self._values

  @property
  def ok(self):
    """Whether the current run is still ok.

    To be precise: returns true if there is neither FailureValue nor
    SkipValue in self.values.
    """
    return not self.skipped and not self.failed

  @property
  def skipped(self):
    """Whether the current run is being skipped.

    To be precise: returns true if there is any SkipValue in self.values.
    """
    return any(isinstance(v, skip.SkipValue) for v in self.values)

  @property
  def failed(self):
    """Whether the current run failed.

    To be precise: returns true if there is a FailureValue but not
    SkipValue in self.values.
    """
    return not self.skipped and any(
        isinstance(v, failure.FailureValue) for v in self.values)
