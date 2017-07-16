# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from horn import horn_object  # pylint: disable=relative-import

class Moose(object):
  def __init__(self):
    self._horn = horn_object.Horn()

  def Run(self):
    if self._horn.IsBig():
      print 'I need to drop my horn! It is big!'
