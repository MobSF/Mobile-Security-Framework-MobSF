# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""
Classes in this package define additional actions that need to be taken to run a
test under some kind of runtime error detection tool.

The interface is intended to be used as follows.

1. For tests that simply run a native process (i.e. no activity is spawned):

Call tool.CopyFiles(device).
Prepend test command line with tool.GetTestWrapper().

2. For tests that spawn an activity:

Call tool.CopyFiles(device).
Call tool.SetupEnvironment().
Run the test as usual.
Call tool.CleanUpEnvironment().
"""
