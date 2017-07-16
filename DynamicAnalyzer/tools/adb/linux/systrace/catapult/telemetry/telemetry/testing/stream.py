# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


class TestOutputStream(object):
  def __init__(self):
    self._output_data = []

  @property
  def output_data(self):
    return ''.join(self._output_data)

  def write(self, data):
    self._output_data.append(data)

  def flush(self):
    pass
