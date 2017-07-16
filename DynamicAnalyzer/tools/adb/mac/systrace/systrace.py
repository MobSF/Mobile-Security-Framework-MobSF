#!/usr/bin/env python

# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import sys

version = sys.version_info[:2]
if version != (2, 7):
  sys.stderr.write('Systrace does not support Python %d.%d. '
                   'Please use Python 2.7.\n' % version)
  sys.exit(1)

systrace_dir = os.path.abspath(
    os.path.join(os.path.dirname(__file__), 'catapult', 'systrace'))
sys.path.insert(0, systrace_dir)

def RemoveAllStalePycFiles(base_dir):
  """Scan directories for old .pyc files without a .py file and delete them."""
  for dirname, _, filenames in os.walk(base_dir):
    if '.git' in dirname:
      continue
    for filename in filenames:
      root, ext = os.path.splitext(filename)
      if ext != '.pyc':
        continue

      pyc_path = os.path.join(dirname, filename)
      py_path = os.path.join(dirname, root + '.py')

      try:
        if not os.path.exists(py_path):
          os.remove(pyc_path)
      except OSError:
        # Wrap OS calls in try/except in case another process touched this file.
        pass

    try:
      os.removedirs(dirname)
    except OSError:
      # Wrap OS calls in try/except in case another process touched this dir.
      pass

if __name__ == '__main__':
  RemoveAllStalePycFiles(os.path.dirname(__file__))
  from systrace import run_systrace
  sys.exit(run_systrace.main())
