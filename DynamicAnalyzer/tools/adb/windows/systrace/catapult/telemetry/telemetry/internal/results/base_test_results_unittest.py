# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import sys
import unittest

from telemetry.core import exceptions


class BaseTestResultsUnittest(unittest.TestCase):

  def CreateException(self):
    try:
      raise exceptions.IntentionalException
    except Exception:
      return sys.exc_info()

  def assertEquals(self, ex, res):
    # This helps diagnose result mismatches.
    if ex != res and isinstance(ex, list):
      def CleanList(l):
        res = []
        for x in l:
          x = x.split('\n')
          res.extend(x)
        return res
      ex = CleanList(ex)
      res = CleanList(res)
      max_len = max(len(ex), len(res))
      max_width = max([len(x) for x in ex + res])
      max_width = max(10, max_width)
      print 'Lists differ!'
      print '%*s | %*s' % (max_width, 'expected', max_width, 'result')
      for i in range(max_len):
        if i < len(ex):
          e = ex[i]
        else:
          e = ''
        if i < len(res):
          r = res[i]
        else:
          r = ''
        if e != r:
          sep = '*'
        else:
          sep = '|'
        print '%*s %s %*s' % (max_width, e, sep, max_width, r)
      print ''
    if ex != res and isinstance(ex, str) and isinstance(res, str):
      print 'Strings differ!'
      print 'exepected:\n%s' % repr(ex)
      print 'result:\n%s\n' % repr(res)
    super(BaseTestResultsUnittest, self).assertEquals(ex, res)
