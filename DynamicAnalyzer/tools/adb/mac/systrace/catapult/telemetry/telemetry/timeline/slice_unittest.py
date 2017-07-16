# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.timeline.slice import Slice


class SliceTest(unittest.TestCase):
  def testChildrenLogic(self):
    # [      top          ]
    #   [ a  ]    [  b  ]
    #    [x]
    top = Slice(None, 'cat', 'top', 0, duration=10, thread_timestamp=0,
                thread_duration=5)
    a = Slice(None, 'cat', 'a', 1, duration=2, thread_timestamp=0.5,
              thread_duration=1)
    x = Slice(None, 'cat', 'x', 1.5, duration=0.25, thread_timestamp=0.75,
              thread_duration=0.125)
    b = Slice(None, 'cat', 'b', 5, duration=2, thread_timestamp=None,
              thread_duration=None)
    top.sub_slices.extend([a, b])
    a.sub_slices.append(x)

    all_children = list(top.IterEventsInThisContainerRecrusively())
    self.assertEquals([a, x, b], all_children)

    self.assertEquals(x.self_time, 0.25)
    self.assertEquals(a.self_time, 1.75) # 2 - 0.25
    self.assertEquals(top.self_time, 6) # 10 - 2 - 2

    self.assertEquals(x.self_thread_time, 0.125)
    self.assertEquals(a.self_thread_time, 0.875) # 1 - 0.125
    self.assertEquals(top.self_thread_time, None) # b has no thread time
