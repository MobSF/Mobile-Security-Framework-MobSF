# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import unittest

from telemetry import story
from telemetry.page import page

import mock


class TestPage(unittest.TestCase):

  def assertPathEqual(self, path1, path2):
    self.assertEqual(os.path.normpath(path1), os.path.normpath(path2))

  def testFilePathRelative(self):
    apage = page.Page('file://somedir/otherdir/file.html',
                      None, base_dir='basedir')
    self.assertPathEqual(apage.file_path, 'basedir/somedir/otherdir/file.html')

  def testFilePathAbsolute(self):
    apage = page.Page('file:///somedir/otherdir/file.html',
                      None, base_dir='basedir')
    self.assertPathEqual(apage.file_path, '/somedir/otherdir/file.html')

  def testFilePathQueryString(self):
    apage = page.Page('file://somedir/otherdir/file.html?key=val',
                      None, base_dir='basedir')
    self.assertPathEqual(apage.file_path, 'basedir/somedir/otherdir/file.html')

  def testFilePathUrlQueryString(self):
    apage = page.Page('file://somedir/file.html?key=val',
                      None, base_dir='basedir')
    self.assertPathEqual(apage.file_path_url,
                         'basedir/somedir/file.html?key=val')

  def testFilePathUrlTrailingSeparator(self):
    apage = page.Page('file://somedir/otherdir/',
                      None, base_dir='basedir')
    self.assertPathEqual(apage.file_path_url, 'basedir/somedir/otherdir/')
    self.assertTrue(apage.file_path_url.endswith(os.sep) or
                    (os.altsep and apage.file_path_url.endswith(os.altsep)))

  def testSort(self):
    story_set = story.StorySet(base_dir=os.path.dirname(__file__))
    story_set.AddStory(
        page.Page('http://www.foo.com/', story_set, story_set.base_dir))
    story_set.AddStory(
        page.Page('http://www.bar.com/', story_set, story_set.base_dir))

    pages = sorted([story_set.stories[0], story_set.stories[1]])
    self.assertEquals([story_set.stories[1], story_set.stories[0]],
                      pages)

  def testGetUrlBaseDirAndFileForUrlBaseDir(self):
    base_dir = os.path.dirname(__file__)
    file_path = os.path.join(
        os.path.dirname(base_dir), 'otherdir', 'file.html')
    story_set = story.StorySet(base_dir=base_dir,
                               serving_dirs=[os.path.join('..', 'somedir', '')])
    story_set.AddStory(
        page.Page('file://../otherdir/file.html', story_set,
                  story_set.base_dir))
    self.assertPathEqual(story_set[0].file_path, file_path)

  def testDisplayUrlForHttp(self):
    story_set = story.StorySet(base_dir=os.path.dirname(__file__))
    story_set.AddStory(
        page.Page('http://www.foo.com/', story_set, story_set.base_dir))
    story_set.AddStory(
        page.Page('http://www.bar.com/', story_set, story_set.base_dir))

    self.assertEquals(story_set[0].display_name, 'http://www.foo.com/')
    self.assertEquals(story_set[1].display_name, 'http://www.bar.com/')

  def testDisplayUrlForHttps(self):
    story_set = story.StorySet(base_dir=os.path.dirname(__file__))
    story_set.AddStory(
        page.Page('http://www.foo.com/', story_set, story_set.base_dir))
    story_set.AddStory(
        page.Page('https://www.bar.com/', story_set, story_set.base_dir))

    self.assertEquals(story_set[0].display_name, 'http://www.foo.com/')
    self.assertEquals(story_set[1].display_name, 'https://www.bar.com/')

  def testDisplayUrlForFile(self):
    story_set = story.StorySet(base_dir=os.path.dirname(__file__))
    story_set.AddStory(page.Page(
        'file://../../otherdir/foo.html', story_set, story_set.base_dir))
    story_set.AddStory(page.Page(
        'file://../../otherdir/bar.html', story_set, story_set.base_dir))

    self.assertEquals(story_set[0].display_name, 'foo.html')
    self.assertEquals(story_set[1].display_name, 'bar.html')

  def testDisplayUrlForFilesDifferingBySuffix(self):
    story_set = story.StorySet(base_dir=os.path.dirname(__file__))
    story_set.AddStory(page.Page(
        'file://../../otherdir/foo.html', story_set, story_set.base_dir))
    story_set.AddStory(page.Page(
        'file://../../otherdir/foo1.html', story_set, story_set.base_dir))

    self.assertEquals(story_set[0].display_name, 'foo.html')
    self.assertEquals(story_set[1].display_name, 'foo1.html')

  def testDisplayUrlForFileOfDifferentPaths(self):
    story_set = story.StorySet(base_dir=os.path.dirname(__file__))
    story_set.AddStory(
        page.Page(
            'file://../../somedir/foo.html', story_set, story_set.base_dir))
    story_set.AddStory(page.Page(
        'file://../../otherdir/bar.html', story_set, story_set.base_dir))

    self.assertEquals(story_set[0].display_name, 'somedir/foo.html')
    self.assertEquals(story_set[1].display_name, 'otherdir/bar.html')

  def testDisplayUrlForFileDirectories(self):
    story_set = story.StorySet(base_dir=os.path.dirname(__file__))
    story_set.AddStory(
        page.Page('file://../../otherdir/foo', story_set, story_set.base_dir))
    story_set.AddStory(
        page.Page('file://../../otherdir/bar', story_set, story_set.base_dir))

    self.assertEquals(story_set[0].display_name, 'foo')
    self.assertEquals(story_set[1].display_name, 'bar')

  def testDisplayUrlForSingleFile(self):
    story_set = story.StorySet(base_dir=os.path.dirname(__file__))
    story_set.AddStory(page.Page(
        'file://../../otherdir/foo.html', story_set, story_set.base_dir))

    self.assertEquals(story_set[0].display_name, 'foo.html')

  def testDisplayUrlForSingleDirectory(self):
    story_set = story.StorySet(base_dir=os.path.dirname(__file__))
    story_set.AddStory(
        page.Page('file://../../otherdir/foo', story_set, story_set.base_dir))

    self.assertEquals(story_set[0].display_name, 'foo')

  def testPagesHaveDifferentIds(self):
    p0 = page.Page("http://example.com")
    p1 = page.Page("http://example.com")
    self.assertNotEqual(p0.id, p1.id)

  def testNamelessPageAsDict(self):
    nameless_dict = page.Page('http://example.com/').AsDict()
    self.assertIn('id', nameless_dict)
    del nameless_dict['id']
    self.assertEquals({
                      'url': 'http://example.com/',
                      }, nameless_dict)

  def testNamedPageAsDict(self):
    named_dict = page.Page('http://example.com/', name='Example').AsDict()
    self.assertIn('id', named_dict)
    del named_dict['id']
    self.assertEquals({
                      'url': 'http://example.com/',
                      'name': 'Example'
                      }, named_dict)

  def testIsLocal(self):
    p = page.Page('file://foo.html')
    self.assertTrue(p.is_local)

    p = page.Page('chrome://extensions')
    self.assertTrue(p.is_local)

    p = page.Page('about:blank')
    self.assertTrue(p.is_local)

    p = page.Page('http://foo.com')
    self.assertFalse(p.is_local)


class TestPageRun(unittest.TestCase):

  def testFiveGarbageCollectionCallsByDefault(self):
    mock_shared_state = mock.Mock()
    p = page.Page('file://foo.html')
    p.Run(mock_shared_state)
    expected = [mock.call.current_tab.CollectGarbage(),
                mock.call.current_tab.CollectGarbage(),
                mock.call.current_tab.CollectGarbage(),
                mock.call.current_tab.CollectGarbage(),
                mock.call.current_tab.CollectGarbage(),
                mock.call.page_test.WillNavigateToPage(
                p, mock_shared_state.current_tab),
                mock.call.page_test.RunNavigateSteps(
                p, mock_shared_state.current_tab),
                mock.call.page_test.DidNavigateToPage(
                p, mock_shared_state.current_tab)]
    self.assertEquals(mock_shared_state.mock_calls, expected)

  def testNoGarbageCollectionCalls(self):
    mock_shared_state = mock.Mock()

    class NonGarbageCollectPage(page.Page):

      def __init__(self, url):
        super(NonGarbageCollectPage, self).__init__(url)
        self._collect_garbage_before_run = False

    p = NonGarbageCollectPage('file://foo.html')
    p.Run(mock_shared_state)
    expected = [mock.call.page_test.WillNavigateToPage(
                p, mock_shared_state.current_tab),
                mock.call.page_test.RunNavigateSteps(
                p, mock_shared_state.current_tab),
                mock.call.page_test.DidNavigateToPage(
                p, mock_shared_state.current_tab)]
    self.assertEquals(mock_shared_state.mock_calls, expected)
