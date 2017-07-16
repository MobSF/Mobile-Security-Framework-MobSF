# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from py_utils import cloud_storage  # pylint: disable=import-error

from telemetry.story.shared_state import SharedState
from telemetry.story.story import Story
from telemetry.story.story_filter import StoryFilter
from telemetry.story.story_set import StorySet


PUBLIC_BUCKET = cloud_storage.PUBLIC_BUCKET
PARTNER_BUCKET = cloud_storage.PARTNER_BUCKET
INTERNAL_BUCKET = cloud_storage.INTERNAL_BUCKET
