# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.web_perf.metrics import single_event

EVENT_NAME = 'WebLocalFrameImpl::moveRangeSelectionExtent'
METRIC_NAME = 'text-selection'

class TextSelectionMetric(single_event._SingleEventMetric):
  """Reports directly durations of WebLocalFrameImpl::moveRangeSelectionExtent
  events associated with moving a selection extent.
  """

  def __init__(self):
    super(TextSelectionMetric, self).__init__(EVENT_NAME, METRIC_NAME,
        metric_description=('List of durations of selection extent movements '
                            'that were caused by and start during '
                            'interactions'))
