# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import json
import os
import shutil
import tempfile
import unittest

from py_utils import cloud_storage  # pylint: disable=import-error

from telemetry.page import page
from telemetry.testing import system_stub
from telemetry.wpr import archive_info


class MockPage(page.Page):
  def __init__(self, url, name=None, platform_specific=False):
    super(MockPage, self).__init__(url, None, name=name)
    self._platform_specific = platform_specific

page1 = MockPage('http://www.foo.com/', 'Foo')
page2 = MockPage('http://www.bar.com/', 'Bar', True)
page3 = MockPage('http://www.baz.com/', platform_specific=True)
pageNew1 = MockPage('http://www.new.com/', 'New')
pageNew2 = MockPage('http://www.newer.com/', 'Newer', True)
recording1 = 'data_001.wpr'
recording2 = 'data_002.wpr'
recording3 = 'data_003.wpr'
recording4 = 'data_004.wpr'
recording5 = 'data_005.wpr'
_DEFAULT_PLATFORM = archive_info._DEFAULT_PLATFORM

default_archives_info_contents_dict = {
    "platform_specific": True,
    "archives": {
        "Foo": {
            _DEFAULT_PLATFORM: recording1
        },
        "Bar": {
            _DEFAULT_PLATFORM: recording2
        },
        "http://www.baz.com/": {
            _DEFAULT_PLATFORM: recording1,
            "win": recording2,
            "mac": recording3,
            "linux": recording4,
            "android": recording5
        }
    }
}

default_archive_info_contents = json.dumps(default_archives_info_contents_dict)
default_wpr_files = [
    'data_001.wpr', 'data_002.wpr', 'data_003.wpr', 'data_004.wpr',
    'data_005.wpr']
_BASE_ARCHIVE = {
        u'platform_specific': True,
        u'description': (u'Describes the Web Page Replay archives for a'
                         u' story set. Don\'t edit by hand! Use record_wpr for'
                         u' updating.'),
        u'archives': {},
}


class WprArchiveInfoTest(unittest.TestCase):
  def setUp(self):
    self.tmp_dir = tempfile.mkdtemp()
    # Set file for the metadata.
    self.story_set_archive_info_file = os.path.join(
        self.tmp_dir, 'info.json')
    self.overrides = system_stub.Override(archive_info, ['cloud_storage'])

  def tearDown(self):
    shutil.rmtree(self.tmp_dir)
    self.overrides.Restore()

  def createArchiveInfo(
      self, archive_data=default_archive_info_contents,
      cloud_storage_bucket=cloud_storage.PUBLIC_BUCKET, wpr_files=None):

    # Cannot set lists as a default parameter, so doing it this way.
    if wpr_files is None:
      wpr_files = default_wpr_files

    with open(self.story_set_archive_info_file, 'w') as f:
      f.write(archive_data)

    assert isinstance(wpr_files, list)
    for wpr_file in wpr_files:
      assert isinstance(wpr_file, basestring)
      with open(os.path.join(self.tmp_dir, wpr_file), 'w') as f:
        f.write(archive_data)
    return archive_info.WprArchiveInfo.FromFile(
        self.story_set_archive_info_file, cloud_storage_bucket)

  def testInitNotPlatformSpecific(self):
    with open(self.story_set_archive_info_file, 'w') as f:
      f.write('{}')
    with self.assertRaises(AssertionError):
      self.createArchiveInfo(archive_data='{}')


  def testDownloadArchivesIfNeededAllNeeded(self):
    test_archive_info = self.createArchiveInfo()
    cloud_storage_stub = self.overrides.cloud_storage
    # Second hash doesn't match, need to fetch it.
    cloud_storage_stub.SetRemotePathsForTesting(
        {cloud_storage.PUBLIC_BUCKET: {recording1: "dummyhash1_old",
                                       recording2: "dummyhash2_old",
                                       recording3: "dummyhash3_old",
                                       recording4: "dummyhash4_old"}})
    cloud_storage_stub.SetCalculatedHashesForTesting(
        {os.path.join(self.tmp_dir, recording1): "dummyhash1",
         os.path.join(self.tmp_dir, recording2): "dummyhash2",
         os.path.join(self.tmp_dir, recording3): "dummyhash3",
         os.path.join(self.tmp_dir, recording4): "dummyhash4",})

    test_archive_info.DownloadArchivesIfNeeded()
    self.assertItemsEqual(cloud_storage_stub.downloaded_files,
                          [recording1, recording2, recording3, recording4])


  def testDownloadArchivesIfNeededOneNeeded(self):
    test_archive_info = self.createArchiveInfo()
    cloud_storage_stub = self.overrides.cloud_storage
    # Second hash doesn't match, need to fetch it.
    cloud_storage_stub.SetRemotePathsForTesting(
        {cloud_storage.PUBLIC_BUCKET: {recording1: "dummyhash1_old",
                                       recording2: "dummyhash2",
                                       recording3: "dummyhash3",
                                       recording4: "dummyhash4"}})
    cloud_storage_stub.SetCalculatedHashesForTesting(
        {os.path.join(self.tmp_dir, recording1): "dummyhash1",
         os.path.join(self.tmp_dir, recording2): "dummyhash2",
         os.path.join(self.tmp_dir, recording3): "dummyhash3",
         os.path.join(self.tmp_dir, recording4): "dummyhash4",})
    test_archive_info.DownloadArchivesIfNeeded()
    self.assertItemsEqual(cloud_storage_stub.downloaded_files, [recording1])

  def testDownloadArchivesIfNeededNonDefault(self):
    data = {
        'platform_specific': True,
        'archives': {
            'http://www.baz.com/': {
                _DEFAULT_PLATFORM: 'data_001.wpr',
                'win': 'data_002.wpr',
                'linux': 'data_004.wpr',
                'mac': 'data_003.wpr',
                'android': 'data_005.wpr'},
            'Foo': {_DEFAULT_PLATFORM: 'data_003.wpr'},
            'Bar': {_DEFAULT_PLATFORM: 'data_002.wpr'}
        }
    }
    test_archive_info = self.createArchiveInfo(
        archive_data=json.dumps(data, separators=(',', ': ')))
    cloud_storage_stub = self.overrides.cloud_storage
    # Second hash doesn't match, need to fetch it.
    cloud_storage_stub.SetRemotePathsForTesting(
        {cloud_storage.PUBLIC_BUCKET: {recording1: "dummyhash1_old",
                                       recording2: "dummyhash2",
                                       recording3: "dummyhash3",
                                       recording4: "dummyhash4_old"}})
    cloud_storage_stub.SetCalculatedHashesForTesting(
        {os.path.join(self.tmp_dir, recording1): "dummyhash1",
         os.path.join(self.tmp_dir, recording2): "dummyhash2",
         os.path.join(self.tmp_dir, recording3): "dummyhash3",
         os.path.join(self.tmp_dir, recording4): "dummyhash4",})
    test_archive_info.DownloadArchivesIfNeeded(target_platforms=['linux'])
    self.assertItemsEqual(cloud_storage_stub.downloaded_files,
                          [recording1, recording4])

  def testDownloadArchivesIfNeededNoBucket(self):
    test_archive_info = self.createArchiveInfo(cloud_storage_bucket=None)
    cloud_storage_stub = self.overrides.cloud_storage
    # Second hash doesn't match, need to fetch it.
    cloud_storage_stub.SetRemotePathsForTesting(
        {cloud_storage.PUBLIC_BUCKET: {recording1: "dummyhash1",
                                       recording2: "dummyhash2",
                                       recording3: "dummyhash3",
                                       recording4: "dummyhash4_old"}})
    cloud_storage_stub.SetCalculatedHashesForTesting(
        {os.path.join(self.tmp_dir, recording1): "dummyhash1",
         os.path.join(self.tmp_dir, recording2): "dummyhash2",
         os.path.join(self.tmp_dir, recording3): "dummyhash3",
         os.path.join(self.tmp_dir, recording4): "dummyhash4",})
    test_archive_info.DownloadArchivesIfNeeded()
    self.assertItemsEqual(cloud_storage_stub.downloaded_files, [])

  def testWprFilePathForStoryDefault(self):
    test_archive_info = self.createArchiveInfo()
    self.assertEqual(
        test_archive_info.WprFilePathForStory(page1),
        os.path.join(self.tmp_dir, recording1))
    self.assertEqual(
        test_archive_info.WprFilePathForStory(page2),
        os.path.join(self.tmp_dir, recording2))
    self.assertEqual(
        test_archive_info.WprFilePathForStory(page3),
        os.path.join(self.tmp_dir, recording1))

  def testWprFilePathForStoryMac(self):
    test_archive_info = self.createArchiveInfo()
    self.assertEqual(test_archive_info.WprFilePathForStory(page1, 'mac'),
                     os.path.join(self.tmp_dir, recording1))
    self.assertEqual(test_archive_info.WprFilePathForStory(page2, 'mac'),
                     os.path.join(self.tmp_dir, recording2))
    self.assertEqual(test_archive_info.WprFilePathForStory(page3, 'mac'),
                     os.path.join(self.tmp_dir, recording3))

  def testWprFilePathForStoryWin(self):
    test_archive_info = self.createArchiveInfo()
    self.assertEqual(test_archive_info.WprFilePathForStory(page1, 'win'),
                     os.path.join(self.tmp_dir, recording1))
    self.assertEqual(test_archive_info.WprFilePathForStory(page2, 'win'),
                     os.path.join(self.tmp_dir, recording2))
    self.assertEqual(test_archive_info.WprFilePathForStory(page3, 'win'),
                     os.path.join(self.tmp_dir, recording2))

  def testWprFilePathForStoryAndroid(self):
    test_archive_info = self.createArchiveInfo()
    self.assertEqual(test_archive_info.WprFilePathForStory(page1, 'android'),
                     os.path.join(self.tmp_dir, recording1))
    self.assertEqual(test_archive_info.WprFilePathForStory(page2, 'android'),
                     os.path.join(self.tmp_dir, recording2))
    self.assertEqual(test_archive_info.WprFilePathForStory(page3, 'android'),
                     os.path.join(self.tmp_dir, recording5))

  def testWprFilePathForStoryLinux(self):
    test_archive_info = self.createArchiveInfo()
    self.assertEqual(test_archive_info.WprFilePathForStory(page1, 'linux'),
                     os.path.join(self.tmp_dir, recording1))
    self.assertEqual(test_archive_info.WprFilePathForStory(page2, 'linux'),
                     os.path.join(self.tmp_dir, recording2))
    self.assertEqual(test_archive_info.WprFilePathForStory(page3, 'linux'),
                     os.path.join(self.tmp_dir, recording4))

  def testWprFilePathForStoryBadStory(self):
    test_archive_info = self.createArchiveInfo()
    self.assertIsNone(test_archive_info.WprFilePathForStory(pageNew1))


  def testAddRecordedStoriesNoStories(self):
    test_archive_info = self.createArchiveInfo()
    old_data = test_archive_info._data.copy()
    test_archive_info.AddNewTemporaryRecording()
    test_archive_info.AddRecordedStories(None)
    self.assertDictEqual(old_data, test_archive_info._data)

  def assertWprFileDoesNotExist(self, file_name):
    sha_file = file_name + '.sha1'
    self.assertFalse(os.path.isfile(os.path.join(self.tmp_dir, sha_file)))
    self.assertFalse(os.path.isfile(os.path.join(self.tmp_dir, file_name)))

  def assertWprFileDoesExist(self, file_name):
    sha_file = file_name + '.sha1'
    self.assertTrue(os.path.isfile(os.path.join(self.tmp_dir, sha_file)))
    self.assertTrue(os.path.isfile(os.path.join(self.tmp_dir, file_name)))

  def testAddRecordedStoriesDefault(self):
    test_archive_info = self.createArchiveInfo()
    self.assertWprFileDoesNotExist('data_006.wpr')

    new_temp_recording = os.path.join(self.tmp_dir, 'recording.wpr')
    expected_archive_file_path = os.path.join(self.tmp_dir, 'data_006.wpr')
    hash_dictionary = {expected_archive_file_path: 'filehash'}
    cloud_storage_stub = self.overrides.cloud_storage
    cloud_storage_stub.SetCalculatedHashesForTesting(hash_dictionary)

    with open(new_temp_recording, 'w') as f:
      f.write('wpr data')

    test_archive_info.AddNewTemporaryRecording(new_temp_recording)
    test_archive_info.AddRecordedStories([page2, page3])

    with open(self.story_set_archive_info_file, 'r') as f:
      archive_file_contents = json.load(f)

    expected_archive_contents = _BASE_ARCHIVE.copy()
    expected_archive_contents['archives'] = {
        page1.display_name: {
            _DEFAULT_PLATFORM: recording1
        },
        page2.display_name: {
            _DEFAULT_PLATFORM: 'data_006.wpr'
        },
        page3.display_name: {
           _DEFAULT_PLATFORM: u'data_006.wpr',
           'linux': recording4,
           'mac': recording3,
           'win': recording2,
           'android': recording5
        }
    }

    self.assertDictEqual(expected_archive_contents, archive_file_contents)
    # Ensure the saved JSON does not contain trailing spaces.
    with open(self.story_set_archive_info_file, 'rU') as f:
      for line in f:
        self.assertFalse(line.rstrip('\n').endswith(' '))
    self.assertWprFileDoesExist('data_006.wpr')

  def testAddRecordedStoriesNotDefault(self):
    test_archive_info = self.createArchiveInfo()
    self.assertWprFileDoesNotExist('data_006.wpr')
    new_temp_recording = os.path.join(self.tmp_dir, 'recording.wpr')
    expected_archive_file_path = os.path.join(self.tmp_dir, 'data_006.wpr')
    hash_dictionary = {expected_archive_file_path: 'filehash'}
    cloud_storage_stub = self.overrides.cloud_storage
    cloud_storage_stub.SetCalculatedHashesForTesting(hash_dictionary)

    with open(new_temp_recording, 'w') as f:
      f.write('wpr data')
    test_archive_info.AddNewTemporaryRecording(new_temp_recording)
    test_archive_info.AddRecordedStories([page2, page3],
                                         target_platform='android')

    with open(self.story_set_archive_info_file, 'r') as f:
      archive_file_contents = json.load(f)

    expected_archive_contents = _BASE_ARCHIVE.copy()
    expected_archive_contents['archives'] = {
        page1.display_name: {
            _DEFAULT_PLATFORM: recording1
        },
        page2.display_name: {
            _DEFAULT_PLATFORM: recording2,
            'android': 'data_006.wpr'
        },
        page3.display_name: {
           _DEFAULT_PLATFORM: recording1,
           'linux': recording4,
           'mac': recording3,
           'win': recording2,
           'android': 'data_006.wpr'
        },
    }

    self.assertDictEqual(expected_archive_contents, archive_file_contents)
    # Ensure the saved JSON does not contain trailing spaces.
    with open(self.story_set_archive_info_file, 'rU') as f:
      for line in f:
        self.assertFalse(line.rstrip('\n').endswith(' '))
    self.assertWprFileDoesExist('data_006.wpr')



  def testAddRecordedStoriesNewPage(self):
    test_archive_info = self.createArchiveInfo()
    self.assertWprFileDoesNotExist('data_006.wpr')
    self.assertWprFileDoesNotExist('data_007.wpr')
    new_temp_recording = os.path.join(self.tmp_dir, 'recording.wpr')
    expected_archive_file_path1 = os.path.join(self.tmp_dir, 'data_006.wpr')
    expected_archive_file_path2 = os.path.join(self.tmp_dir, 'data_007.wpr')
    hash_dictionary = {
        expected_archive_file_path1: 'filehash',
        expected_archive_file_path2: 'filehash2'
    }
    cloud_storage_stub = self.overrides.cloud_storage
    cloud_storage_stub.SetCalculatedHashesForTesting(hash_dictionary)

    with open(new_temp_recording, 'w') as f:
      f.write('wpr data')
    test_archive_info.AddNewTemporaryRecording(new_temp_recording)
    test_archive_info.AddRecordedStories([pageNew1])

    with open(new_temp_recording, 'w') as f:
      f.write('wpr data2')

    test_archive_info.AddNewTemporaryRecording(new_temp_recording)
    test_archive_info.AddRecordedStories([pageNew2], target_platform='android')

    with open(self.story_set_archive_info_file, 'r') as f:
      archive_file_contents = json.load(f)


    expected_archive_contents = _BASE_ARCHIVE.copy()
    expected_archive_contents['archives'] = {
        page1.display_name: {
            _DEFAULT_PLATFORM: recording1
        },
        page2.display_name: {
            _DEFAULT_PLATFORM: recording2,
        },
        page3.display_name: {
           _DEFAULT_PLATFORM: recording1,
           'linux': recording4,
           'mac': recording3,
           'win': recording2,
           'android': recording5
        },
        pageNew1.display_name: {
          _DEFAULT_PLATFORM: 'data_006.wpr'
        },
        pageNew2.display_name: {
          _DEFAULT_PLATFORM: 'data_007.wpr',
          'android': 'data_007.wpr'
        }
    }

    self.assertDictEqual(expected_archive_contents, archive_file_contents)
    # Ensure the saved JSON does not contain trailing spaces.
    with open(self.story_set_archive_info_file, 'rU') as f:
      for line in f:
        self.assertFalse(line.rstrip('\n').endswith(' '))
    self.assertWprFileDoesExist('data_006.wpr')
    self.assertWprFileDoesExist('data_007.wpr')
