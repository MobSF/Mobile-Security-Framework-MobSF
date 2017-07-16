# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from py_trace_event import trace_event


class SharedState(object):
  """A class that manages the test state across multiple stories.
  It's styled on unittest.TestCase for handling test setup & teardown logic.

  """

  __metaclass__ = trace_event.TracedMetaClass

  def __init__(self, test, options, story_set):
    """ This method is styled on unittest.TestCase.setUpClass.
    Override to do any action before running stories that
    share this same state.
    Args:
      test: a legacy_page_test.LegacyPageTest or story_test.StoryTest instance.
      options: a BrowserFinderOptions instance that contains command line
        options.
      story_set: a story.StorySet instance.
    """
    pass

  @property
  def platform(self):
    """ Override to return the platform which stories that share this same
    state will be run on.
    """
    raise NotImplementedError()

  def WillRunStory(self, story):
    """ Override to do any action before running each one of all stories
    that share this same state.
    This method is styled on unittest.TestCase.setUp.
    """
    raise NotImplementedError()

  def DidRunStory(self, results):
    """ Override to do any action after running each of all stories that
    share this same state.
    This method is styled on unittest.TestCase.tearDown.
    """
    raise NotImplementedError()

  def CanRunStory(self, story):
    """Indicate whether the story can be run in the current configuration.
    This is called after WillRunStory and before RunStory. Return True
    if the story should be run, and False if it should be skipped.
    Most subclasses will probably want to override this to always
    return True.
    Args:
      story: a story.Story instance.
    """
    raise NotImplementedError()

  def RunStory(self, results):
    """ Override to do any action before running each one of all stories
    that share this same state.
    This method is styled on unittest.TestCase.run.
    """
    raise NotImplementedError()

  def TearDownState(self):
    """ Override to do any action after running multiple stories that
    share this same state.
    This method is styled on unittest.TestCase.tearDownClass.
    """
    raise NotImplementedError()

  def DumpStateUponFailure(self, story, results):
    """ Dump the state upon failure.
    This method tries to dump as much information about the application under
    test as possible (output, log, screenshot, etc.) to simplify triaging the
    failure.
    """
    raise NotImplementedError()
