# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import datetime
import os
import StringIO
import unittest

from telemetry import benchmark
from telemetry import story
from telemetry.internal.results import legacy_html_output_formatter
from telemetry.internal.results import page_test_results
from telemetry import page as page_module
from telemetry.value import improvement_direction
from telemetry.value import scalar


def _MakeStorySet():
  story_set = story.StorySet(base_dir=os.path.dirname(__file__))
  story_set.AddStory(
      page_module.Page('http://www.foo.com/', story_set, story_set.base_dir))
  story_set.AddStory(
      page_module.Page('http://www.bar.com/', story_set, story_set.base_dir))
  story_set.AddStory(
      page_module.Page('http://www.baz.com/', story_set, story_set.base_dir))
  return story_set


class DeterministicHtmlOutputFormatter(
    legacy_html_output_formatter.LegacyHtmlOutputFormatter):
  def _GetBuildTime(self):
    return datetime.datetime(1998, 9, 4, 13, 0, 0, 7777)

  def _GetRevision(self):
    return 'revision'

class FakeMetadataForTest(benchmark.BenchmarkMetadata):
  def __init__(self):
    super(FakeMetadataForTest, self).__init__('test_name')

# Wrap string IO with a .name property so that it behaves more like a file.
class StringIOFile(StringIO.StringIO):
  name = 'fake_output_file'


class LegacyHtmlOutputFormatterTest(unittest.TestCase):

  def setUp(self):
    self.maxDiff = 100000

  def test_basic_summary(self):
    test_story_set = _MakeStorySet()
    output_file = StringIOFile()

    # Run the first time and verify the results are written to the HTML file.
    results = page_test_results.PageTestResults()
    results.WillRunPage(test_story_set.stories[0])
    results.AddValue(scalar.ScalarValue(
        test_story_set.stories[0], 'a', 'seconds', 3,
        improvement_direction=improvement_direction.DOWN))
    results.DidRunPage(test_story_set.stories[0])

    results.WillRunPage(test_story_set.stories[1])
    results.AddValue(scalar.ScalarValue(
        test_story_set.stories[1], 'a', 'seconds', 7,
        improvement_direction=improvement_direction.DOWN))
    results.DidRunPage(test_story_set.stories[1])

    formatter = DeterministicHtmlOutputFormatter(
        output_file, FakeMetadataForTest(), False, 'browser_type')
    formatter.Format(results)
    expected = {
      "platform": "browser_type",
      "buildTime": "1998-09-04T13:00:00.007777",
      "label": 'test_name (1998-09-04 13:00:00)',
      "tests": {
        "test_name": {
          "metrics": {
            "a": {
              "current": [3, 7],
              "std": 0.0,  # Only one sample per page.
              "units": "seconds",
              "important": True
            },
            "telemetry_page_measurement_results.num_failed": {
              "current": [0],
              "units": "count",
              "important": False
            },
            "a.http://www.bar.com/": {
              "current": [7],
              "std": 0.0,
              "units": "seconds",
              "important": False
            },
            "a.http://www.foo.com/": {
              "current": [3],
              "std": 0.0,
              "units": "seconds",
              "important": False
            }
          }
        }
      },
    }
    self.assertEquals(expected, formatter.GetResults())

    # Run the second time and verify the results are appended to the HTML file.
    output_file.seek(0)
    results = page_test_results.PageTestResults()
    results.WillRunPage(test_story_set.stories[0])
    results.AddValue(scalar.ScalarValue(
        test_story_set.stories[0], 'a', 'seconds', 4,
        improvement_direction=improvement_direction.DOWN))
    results.DidRunPage(test_story_set.stories[0])

    results.WillRunPage(test_story_set.stories[1])
    results.AddValue(scalar.ScalarValue(
        test_story_set.stories[1], 'a', 'seconds', 8,
        improvement_direction=improvement_direction.DOWN))
    results.DidRunPage(test_story_set.stories[1])

    formatter = DeterministicHtmlOutputFormatter(
        output_file, FakeMetadataForTest(), False, 'browser_type')
    formatter.Format(results)
    expected = [
      {
        "platform": "browser_type",
        "buildTime": "1998-09-04T13:00:00.007777",
        "label": 'test_name (1998-09-04 13:00:00)',
        "tests": {
          "test_name": {
            "metrics": {
              "a": {
                "current": [3, 7],
                "units": "seconds",
                "std": 0.0,  # Only one sample per page.
                "important": True
              },
              "telemetry_page_measurement_results.num_failed": {
                "current": [0],
                "units": "count",
                "important": False
              },
              "a.http://www.bar.com/": {
                "current": [7],
                "std": 0.0,
                "units": "seconds",
                "important": False
              },
              "a.http://www.foo.com/": {
                "current": [3],
                "std": 0.0,
                "units": "seconds",
                "important": False
              }
            }
          }
        },
      },
      {
        "platform": "browser_type",
        "buildTime": "1998-09-04T13:00:00.007777",
        "label": 'test_name (1998-09-04 13:00:00)',
        "tests": {
          "test_name": {
            "metrics": {
              "a": {
                "current": [4, 8],
                'std': 0.0,  # Only one sample per page.
                "units": "seconds",
                "important": True
              },
              "telemetry_page_measurement_results.num_failed": {
                "current": [0],
                "units": "count",
                "important": False,
              },
              "a.http://www.bar.com/": {
                "current": [8],
                "std": 0.0,
                "units": "seconds",
                "important": False
              },
              "a.http://www.foo.com/": {
                "current": [4],
                "std": 0.0,
                "units": "seconds",
                "important": False
              }
            }
          }
        },
      }]
    self.assertEquals(expected, formatter.GetCombinedResults())
    last_output_len = len(output_file.getvalue())

    # Now reset the results and verify the old ones are gone.
    output_file.seek(0)
    results = page_test_results.PageTestResults()
    results.WillRunPage(test_story_set.stories[0])
    results.AddValue(scalar.ScalarValue(
        test_story_set.stories[0], 'a', 'seconds', 5,
        improvement_direction=improvement_direction.DOWN))
    results.DidRunPage(test_story_set.stories[0])

    results.WillRunPage(test_story_set.stories[1])
    results.AddValue(scalar.ScalarValue(
        test_story_set.stories[1], 'a', 'seconds', 9,
        improvement_direction=improvement_direction.DOWN))
    results.AddValue(scalar.ScalarValue(
        test_story_set.stories[1], 'b', 'seconds', 20, tir_label='foo'))
    results.DidRunPage(test_story_set.stories[1])

    formatter = DeterministicHtmlOutputFormatter(
       output_file, FakeMetadataForTest(), True, 'browser_type')
    formatter.Format(results)
    expected = [{
      "platform": "browser_type",
      "buildTime": "1998-09-04T13:00:00.007777",
      "label": 'test_name (1998-09-04 13:00:00)',
      "tests": {
        "test_name": {
          "metrics": {
            "a": {
              "current": [5, 9],
              'std': 0.0,  # Only one sample per page.
              "units": "seconds",
              "important": True
            },
            "telemetry_page_measurement_results.num_failed": {
              "current": [0],
              "units": "count",
              "important": False
            },
            "a.http://www.bar.com/": {
              "current": [9],
              "std": 0.0,
              "units": "seconds",
              "important": False
            },
            "a.http://www.foo.com/": {
              "current": [5],
              "std": 0.0,
              "units": "seconds",
              "important": False
            },
            "foo-b.http://www.bar.com/": {
              "current": [20],
              "std": 0.0,
              "units": "seconds",
              "important": False
            },
            "foo-b": {
              "current": [20],
              "std": 0.0,
              "units": "seconds",
              "important": True
            }
          }
        }
      },
    }]
    self.assertEquals(expected, formatter.GetCombinedResults())
    self.assertTrue(len(output_file.getvalue()) < last_output_len)
