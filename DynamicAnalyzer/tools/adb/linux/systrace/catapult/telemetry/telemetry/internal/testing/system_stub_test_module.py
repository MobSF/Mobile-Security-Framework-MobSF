# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
class SystemStubTest(object):
  @staticmethod
  def TestOpen(file_path):
    return open(file_path)
