# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import unittest

from telemetry.timeline import model as model_module


class ThreadUnittest(unittest.TestCase):

  def testIterAllSlicesInRange(self):
    model = model_module.TimelineModel()
    renderer_main = model.GetOrCreateProcess(1).GetOrCreateThread(2)
    #    [       X     ] [   Y    ] [   U   ]
    #        [   Z   ]     [ T ]
    #      |                           |
    #    start                        end
    renderer_main.BeginSlice('cat1', 'X', 10)
    renderer_main.BeginSlice('cat1', 'Z', 20)
    renderer_main.EndSlice(30)
    renderer_main.EndSlice(40)
    renderer_main.BeginSlice('cat1', 'Y', 50)
    renderer_main.BeginSlice('cat1', 'T', 52)
    renderer_main.EndSlice(55)
    renderer_main.EndSlice(60)
    renderer_main.BeginSlice('cat1', 'U', 60)
    renderer_main.EndSlice(70)

    model.FinalizeImport(shift_world_to_zero=False)
    slice_names = set(s.name for s in
                      renderer_main.IterAllSlicesInRange(start=12, end=65))
    self.assertEqual(slice_names, {'Z', 'Y', 'T'})
