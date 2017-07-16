# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry import story


class TestSimpleTwoPageSet(story.StorySet):
  def __init__(self):
    super(TestSimpleTwoPageSet, self).__init__(
      archive_data_file='data/archive_files/test.json',
      credentials_path='data/credential')
