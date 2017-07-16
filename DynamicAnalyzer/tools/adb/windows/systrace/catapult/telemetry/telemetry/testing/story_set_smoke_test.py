# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import os
import unittest

from telemetry.core import discover
from telemetry.internal.browser import browser_credentials
from telemetry.internal import story_runner
from telemetry import page
from telemetry import story as story_module
from telemetry.wpr import archive_info


class StorySetSmokeTest(unittest.TestCase):

  def setUp(self):
    # Make sure the added failure message is appended to the default failure
    # message.
    self.longMessage = True

  def GetAllStorySetClasses(self, story_sets_dir, top_level_dir):
    # We can't test page sets that aren't directly constructible since we
    # don't know what arguments to put for the constructor.
    return discover.DiscoverClasses(story_sets_dir, top_level_dir,
                                    story_module.StorySet,
                                    directly_constructable=True).values()

  def CheckArchive(self, story_set):
    """Verify that all URLs of pages in story_set have an associated archive."""
    # TODO: Eventually these should be fatal.
    if not story_set.archive_data_file:
      logging.warning('Skipping %s: no archive data file', story_set.file_path)
      return

    logging.info('Testing %s', story_set.file_path)

    archive_data_file_path = os.path.join(story_set.base_dir,
                                          story_set.archive_data_file)
    self.assertTrue(os.path.exists(archive_data_file_path),
                    msg='Archive data file not found for %s' %
                    story_set.file_path)

    wpr_archive_info = archive_info.WprArchiveInfo.FromFile(
        archive_data_file_path, story_set.bucket)
    for story in story_set.stories:
      if isinstance(story, page.Page) and story.url.startswith('http'):
        self.assertTrue(wpr_archive_info.WprFilePathForStory(story),
                        msg='No archive found for %s in %s' % (
                            story.url, story_set.archive_data_file))

  def CheckCredentials(self, story_set):
    """Verify that all pages in story_set use proper credentials"""
    for story in story_set.stories:
      if not isinstance(story, page.Page):
        continue
      credentials = browser_credentials.BrowserCredentials()
      if story.credentials_path:
        credentials.credentials_path = (
            os.path.join(story.base_dir, story.credentials_path))
      fail_message = ('page %s of %s has invalid credentials %s' %
                      (story.url, story_set.file_path, story.credentials))
      if story.credentials:
        try:
          self.assertTrue(credentials.CanLogin(story.credentials), fail_message)
        except browser_credentials.CredentialsError:
          self.fail(fail_message)

  def CheckAttributes(self, story_set):
    """Verify that story_set and its stories base attributes have the right
       types.
    """
    self.CheckAttributesOfStorySetBasicAttributes(story_set)
    for story in story_set.stories:
      self.CheckAttributesOfStoryBasicAttributes(story)

  def CheckAttributesOfStorySetBasicAttributes(self, story_set):
    if story_set.base_dir is not None:
      self.assertTrue(
          isinstance(story_set.base_dir, str),
          msg='story_set %\'s base_dir must have type string')

    self.assertTrue(
        isinstance(story_set.archive_data_file, str),
        msg='story_set\'s archive_data_file path must have type string')

  def CheckAttributesOfStoryBasicAttributes(self, story):
    self.assertTrue(not hasattr(story, 'disabled'))
    self.assertTrue(
       isinstance(story.name, str),
       msg='story %s \'s name field must have type string' % story.display_name)
    self.assertTrue(
       isinstance(story.tags, set),
       msg='story %s \'s tags field must have type set' % story.display_name)
    for t in story.tags:
      self.assertTrue(
         isinstance(t, str),
         msg='tag %s in story %s \'s tags must have type string'
         % (str(t), story.display_name))
    if not isinstance(story, page.Page):
      return
    self.assertTrue(
       # We use basestring instead of str because story's URL can be string of
       # unicode.
       isinstance(story.url, basestring),
       msg='page %s \'s url must have type string' % story.display_name)
    self.assertTrue(
        isinstance(story.startup_url, str),
        msg=('page %s \'s startup_url field must have type string'
            % story.display_name))
    self.assertIsInstance(
        story.make_javascript_deterministic, bool,
        msg='page %s \'s make_javascript_deterministic must have type bool'
            % story.display_name)

  def CheckSharedStates(self, story_set):
    if not story_set.allow_mixed_story_states:
      shared_state_class = (
          story_set.stories[0].shared_state_class)
      for story in story_set:
        self.assertIs(
            shared_state_class,
            story.shared_state_class,
            msg='story %s\'s shared_state_class field is different '
            'from other story\'s shared_state_class whereas '
            'story set %s disallows having mixed states' %
            (story, story_set))

  def CheckPassingStoryRunnerValidation(self, story_set):
    errors = []
    for s in story_set:
      try:
        story_runner.ValidateStory(s)
      except ValueError as e:
        errors.append(e)
    self.assertFalse(
        errors, 'Errors validating user stories in %s:\n %s' % (
            story_set, '\n'.join(e.message for e in errors)))

  def RunSmokeTest(self, story_sets_dir, top_level_dir):
    """Run smoke test on all story sets in story_sets_dir.

    Subclass of StorySetSmokeTest is supposed to call this in some test
    method to run smoke test.
    """
    story_sets = self.GetAllStorySetClasses(story_sets_dir, top_level_dir)
    for story_set_class in story_sets:
      story_set = story_set_class()
      self.CheckArchive(story_set)
      self.CheckCredentials(story_set)
      self.CheckAttributes(story_set)
      self.CheckSharedStates(story_set)
      self.CheckPassingStoryRunnerValidation(story_set)
