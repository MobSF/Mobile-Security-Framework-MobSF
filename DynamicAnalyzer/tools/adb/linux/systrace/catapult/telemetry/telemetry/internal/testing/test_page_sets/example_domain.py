# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry import story
from telemetry.page import page


class ExampleDomainPageSet(story.StorySet):
  def __init__(self):
    super(ExampleDomainPageSet, self).__init__(
      archive_data_file='data/example_domain.json',
      cloud_storage_bucket=story.PUBLIC_BUCKET)

    self.AddStory(page.Page('http://www.example.com', self))
    self.AddStory(page.Page('https://www.example.com', self))
