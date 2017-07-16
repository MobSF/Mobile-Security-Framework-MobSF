# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os


def InjectJavaScript(tab, jsFileName):
  with open(os.path.join(os.path.dirname(__file__), jsFileName)) as f:
    js = f.read()
    tab.ExecuteJavaScript(js)
