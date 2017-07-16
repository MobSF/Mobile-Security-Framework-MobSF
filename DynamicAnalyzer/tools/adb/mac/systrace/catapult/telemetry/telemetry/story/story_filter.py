# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import optparse
import re

from telemetry.internal.util import command_line


class _StoryMatcher(object):
  def __init__(self, pattern):
    self._regex = None
    self.has_compile_error = False
    if pattern:
      try:
        self._regex = re.compile(pattern)
      except re.error:
        self.has_compile_error = True

  def __nonzero__(self):
    return self._regex is not None

  def HasMatch(self, story):
    return self and bool(
        self._regex.search(story.display_name) or
        (story.name and self._regex.search(story.name)))


class _StoryTagMatcher(object):
  def __init__(self, tags_str):
    self._tags = tags_str.split(',') if tags_str else None

  def __nonzero__(self):
    return self._tags is not None

  def HasLabelIn(self, story):
    return self and bool(story.tags.intersection(self._tags))


class StoryFilter(command_line.ArgumentHandlerMixIn):
  """Filters stories in the story set based on command-line flags."""

  @classmethod
  def AddCommandLineArgs(cls, parser):
    group = optparse.OptionGroup(parser, 'User story filtering options')
    group.add_option('--story-filter',
        help='Use only stories whose names match the given filter regexp.')
    group.add_option('--story-filter-exclude',
        help='Exclude stories whose names match the given filter regexp.')
    group.add_option('--story-tag-filter',
        help='Use only stories that have any of these tags')
    group.add_option('--story-tag-filter-exclude',
        help='Exclude stories that have any of these tags')
    parser.add_option_group(group)

  @classmethod
  def ProcessCommandLineArgs(cls, parser, args):
    cls._include_regex = _StoryMatcher(args.story_filter)
    cls._exclude_regex = _StoryMatcher(args.story_filter_exclude)

    cls._include_tags = _StoryTagMatcher(args.story_tag_filter)
    cls._exclude_tags = _StoryTagMatcher(args.story_tag_filter_exclude)

    if cls._include_regex.has_compile_error:
      raise parser.error('--story-filter: Invalid regex.')
    if cls._exclude_regex.has_compile_error:
      raise parser.error('--story-filter-exclude: Invalid regex.')

  @classmethod
  def IsSelected(cls, story):
    # Exclude filters take priority.
    if cls._exclude_tags.HasLabelIn(story):
      return False
    if cls._exclude_regex.HasMatch(story):
      return False

    if cls._include_tags and not cls._include_tags.HasLabelIn(story):
      return False
    if cls._include_regex and not cls._include_regex.HasMatch(story):
      return False
    return True
