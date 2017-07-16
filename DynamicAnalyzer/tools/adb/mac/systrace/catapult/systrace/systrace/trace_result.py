#!/usr/bin/env python

# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

'''Tracing agent result wrapper for systrace.

This class represents the captured trace results from a particular
tool (e.g. atrace, ftrace.)
'''


class TraceResult(object):
  def __init__(self, source_name, raw_data):
    self.source_name = source_name
    self.raw_data = raw_data
