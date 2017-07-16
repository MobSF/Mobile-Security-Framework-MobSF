# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import eslint
import os
import tempfile
import unittest


_TEMP_FILE_CONTENTS = '''<!DOCTYPE html>
<!--
Copyright 2016 The Chromium Authors. All rights reserved.
Use of this source code is governed by a BSD-style license that can be
found in the LICENSE file.
-->
<script>
// This should cause a linter error because we require camelCase.
var non_camel_case = 0;
</script>
'''


class SmokeTest(unittest.TestCase):
  def testEslintFindsError(self):
    try:
      tmp_file =  tempfile.NamedTemporaryFile(
          delete=False, dir=os.path.dirname(__file__), suffix=".html")
      tmp_file.write(_TEMP_FILE_CONTENTS)
      tmp_file.close()

      success, output = eslint.RunEslint([tmp_file.name])
      self.assertFalse(success)
      self.assertTrue('is not in camel case' in output)
    finally:
      os.remove(tmp_file.name)
