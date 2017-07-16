# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


class ProgressReporter(object):
  """A class that reports progress of a benchmark.

  The reporter produces output whenever a significant event happens
  during the progress of a benchmark, including (but not limited to):
  when a page run is started, when a page run finished, any failures
  during a page run.

  The default implementation outputs nothing.
  """

  def DidAddValue(self, value):
    pass

  def WillRunPage(self, page_test_results):
    pass

  def DidRunPage(self, page_test_results):
    pass

  def DidFinishAllTests(self, page_test_results):
    pass
