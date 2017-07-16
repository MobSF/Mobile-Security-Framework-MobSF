# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import sys


_CATAPULT_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', '..')
sys.path.append(os.path.join(_CATAPULT_DIR, 'devil'))
sys.path.append(os.path.join(_CATAPULT_DIR, 'systrace'))
sys.path.append(os.path.join(_CATAPULT_DIR, 'common', 'py_utils'))
