# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.web_perf.metrics import single_event

EVENT_NAME = 'FrameView::performLayout'
METRIC_NAME = 'layout'

class LayoutMetric(single_event._SingleEventMetric):
  """Reports directly durations of FrameView::performLayout events.

    layout: Durations of FrameView::performLayout events that were caused by and
            start during user interaction.

  Layout happens no more than once per frame, so per-frame-ness is implied.
  """

  def __init__(self):
    super(LayoutMetric, self).__init__(EVENT_NAME, METRIC_NAME,
        metric_description=('List of durations of layouts that were caused by '
                            'and start during interactions'))
