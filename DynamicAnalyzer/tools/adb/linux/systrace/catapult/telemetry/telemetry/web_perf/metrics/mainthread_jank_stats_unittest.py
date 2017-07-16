# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.timeline import async_slice
from telemetry.timeline import model as model_module
from telemetry.web_perf.metrics import mainthread_jank_stats
from telemetry.web_perf import timeline_interaction_record as tir_module


class MainthreadJankTests(unittest.TestCase):

  def CreateTestRecord(self, name, start, end, thread_start, thread_end,
                       parent_thread):
    s = async_slice.AsyncSlice(
        'cat', 'Interaction.%s' % name,
        timestamp=start, duration=end - start, start_thread=parent_thread,
        end_thread=parent_thread, thread_start=thread_start,
        thread_duration=thread_end - thread_start)
    return tir_module.TimelineInteractionRecord.FromAsyncEvent(s)

  def testComputeMainthreadJankStatsForRecord(self):
    # The slice hierarchy should look something like this:
    # [  MessageLoop::RunTask   ] [MessageLoop::RunTask][  MessagLoop::RunTask ]
    #                                 [ foo ]                  [ bar ]
    #            |                                                |
    #          200ms                                            800ms
    #       (thread_start)                                   (thread_end)
    #
    # Note: all timings mentioned here and in comments below are thread time.

    model = model_module.TimelineModel()
    renderer_main = model.GetOrCreateProcess(1).GetOrCreateThread(2)
    renderer_main.name = 'CrRendererMain'

    #   [     MessageLoop::RunTask             ]
    # 100ms                                   300ms
    renderer_main.BeginSlice('toplevel', 'MessageLoop::RunTask', 112, 100)
    renderer_main.EndSlice(240, 300)

    #   [     MessageLoop::RunTask             ]
    # 450ms     [   foo  ]                    475 ms
    #         460ms    470ms
    renderer_main.BeginSlice('toplevel', 'MessageLoop::RunTask', 462, 450)
    renderer_main.BeginSlice('otherlevel', 'foo', 468, 460)
    renderer_main.EndSlice(475, 470)
    renderer_main.EndSlice(620, 475)

    #   [     MessageLoop::RunTask             ]
    #  620ms     [   bar  ]                   900ms
    #         750ms    850ms
    renderer_main.BeginSlice('toplevel', 'MessageLoop::RunTask', 652, 620)
    renderer_main.BeginSlice('otherlevel', 'bar', 785, 750)
    renderer_main.EndSlice(875, 850)
    renderer_main.EndSlice(1040, 900)

    model.FinalizeImport(shift_world_to_zero=False)

    # Make a record that starts at 200ms and ends at 800ms in thread time
    record = self.CreateTestRecord('test', 100, 700, 200, 800, renderer_main)
    # pylint: disable=protected-access
    stat = mainthread_jank_stats._ComputeMainthreadJankStatsForRecord(
        renderer_main, record)

    # The overlapped between thread time range(200ms -> 800ms)
    # with the first top slice (100ms -> 300ms) is 300 - 200 = 100ms,
    # with the second slice (450ms -> 475ms) is 475 - 450 = 25 ms,
    # with the third slice (620ms -> 900ms) is 800 - 620 = 180 ms.
    #
    # Hence we have 2 big top slices which overlapped duration > 50ms,
    # the biggest top slice is 180ms, and the total big top slice's thread time
    # is 100 + 180 = 280ms.
    self.assertEquals(180, stat.biggest_top_slice_thread_time)
    self.assertEquals(280, stat.sum_big_top_slices_thread_time)

  def testMainthreadJankStats(self):
    # [ MessageLoop::RunTask]  [MessageLoop::RunTask]  [MessagLoop::RunTask]
    # 10                   100 120                 400 450                750
    #     [  record_1  ]       [  record_2  ]   [            record_3        ]
    #     40          70      120          200  220                         900

    model = model_module.TimelineModel()
    renderer_main = model.GetOrCreateProcess(1).GetOrCreateThread(2)
    renderer_main.name = 'CrRendererMain'

    #   [     MessageLoop::RunTask  ]
    #   10ms                       100ms
    renderer_main.BeginSlice('toplevel', 'MessageLoop::RunTask', 12, 10)
    renderer_main.EndSlice(120, 100)

    #   [     MessageLoop::RunTask  ]
    #   120ms                      200ms
    renderer_main.BeginSlice('toplevel', 'MessageLoop::RunTask', 115, 120)
    renderer_main.EndSlice(410, 400)

    #   [     MessageLoop::RunTask  ]
    #  220ms                       900ms
    renderer_main.BeginSlice('toplevel', 'MessageLoop::RunTask', 477, 450)
    renderer_main.EndSlice(772, 750)

    model.FinalizeImport(shift_world_to_zero=False)

    test_records = [
        self.CreateTestRecord('record_1', 10, 80, 40, 70, renderer_main),
        self.CreateTestRecord('record_2', 100, 210, 120, 200, renderer_main),
        self.CreateTestRecord('record_3', 215, 920, 220, 900, renderer_main)
    ]

    stats = mainthread_jank_stats.MainthreadJankStats(
        renderer_main, test_records)
    # Main thread janks covered by records' ranges are:
    # Record 1: (40ms -> 70ms)
    # Record 2: (120ms -> 200ms)
    # Record 3: (220ms -> 400ms), (450ms -> 750ms)
    self.assertEquals(560, stats.total_big_jank_thread_time)
    self.assertEquals(300, stats.biggest_jank_thread_time)
