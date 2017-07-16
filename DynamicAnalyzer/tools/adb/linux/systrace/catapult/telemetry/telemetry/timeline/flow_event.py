# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import telemetry.timeline.event as event


class FlowEvent(event.TimelineEvent):
  """A FlowEvent represents an interval of time plus parameters associated
  with that interval.
  """
  def __init__(self, category, event_id, name, start, args=None):
    super(FlowEvent, self).__init__(
        category, name, start, duration=0, args=args)
    self.event_id = event_id
