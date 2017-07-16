# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os

from telemetry.core import util
from telemetry.testing import tab_test_case


class MemoryCacheHTTPServerTest(tab_test_case.TabTestCase):

  def setUp(self):
    super(MemoryCacheHTTPServerTest, self).setUp()
    self._test_filename = 'bear.webm'
    _test_file = os.path.join(util.GetUnittestDataDir(), 'bear.webm')
    self._test_file_size = os.stat(_test_file).st_size

  def testBasicHostingAndRangeRequests(self):
    self.Navigate('blank.html')
    x = self._tab.EvaluateJavaScript('document.body.innerHTML')
    x = x.strip()

    # Test basic html hosting.
    self.assertEquals(x, 'Hello world')

    file_size = self._test_file_size
    last_byte = file_size - 1
    # Test byte range request: no end byte.
    self.CheckContentHeaders('0-', '0-%d' % last_byte, file_size)

    # Test byte range request: greater than zero start byte.
    self.CheckContentHeaders('100-', '100-%d' % last_byte, file_size - 100)

    # Test byte range request: explicit byte range.
    self.CheckContentHeaders('2-500', '2-500', '499')

    # Test byte range request: no start byte.
    self.CheckContentHeaders('-228', '%d-%d' % (file_size - 228, last_byte),
                             '228')

    # Test byte range request: end byte less than start byte.
    self.CheckContentHeaders('100-5', '100-%d' % last_byte, file_size - 100)

  def CheckContentHeaders(self, content_range_request, content_range_response,
                          content_length_response):
    self._tab.ExecuteJavaScript("""
        var loaded = false;
        var xmlhttp = new XMLHttpRequest();
        xmlhttp.onload = function(e) {
          loaded = true;
        };
        // Avoid cached content by appending unique URL param.
        xmlhttp.open('GET', {{ url }} + "?t=" + Date.now(), true);
        xmlhttp.setRequestHeader('Range', {{ range }});
        xmlhttp.send();
        """,
        url=self.UrlOfUnittestFile(self._test_filename),
        range='bytes=%s' % content_range_request)
    self._tab.WaitForJavaScriptCondition('loaded', timeout=5)
    content_range = self._tab.EvaluateJavaScript(
        'xmlhttp.getResponseHeader("Content-Range");')
    content_range_response = 'bytes %s/%d' % (content_range_response,
                                              self._test_file_size)
    self.assertEquals(content_range, content_range_response)
    content_length = self._tab.EvaluateJavaScript(
        'xmlhttp.getResponseHeader("Content-Length");')
    self.assertEquals(content_length, str(content_length_response))

  def testAbsoluteAndRelativePathsYieldSameURL(self):
    test_file_rel_path = 'green_rect.html'
    test_file_abs_path = os.path.abspath(os.path.join(util.GetUnittestDataDir(),
                                                      test_file_rel_path))
    # It's necessary to bypass self.UrlOfUnittestFile since that
    # concatenates the unittest directory on to the incoming path,
    # causing the same code path to be taken in both cases.
    self._platform.SetHTTPServerDirectories(util.GetUnittestDataDir())
    self.assertEquals(
      self._platform.http_server.UrlOf(test_file_rel_path),
      self._platform.http_server.UrlOf(test_file_abs_path))
