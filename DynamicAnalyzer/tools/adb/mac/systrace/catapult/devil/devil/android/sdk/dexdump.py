# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from devil.android.sdk import build_tools
from devil.utils import cmd_helper
from devil.utils import lazy


_dexdump_path = lazy.WeakConstant(lambda: build_tools.GetPath('dexdump'))


def DexDump(dexfiles, file_summary=False):
  """A wrapper around the Android SDK's dexdump tool.

  Args:
    dexfiles: The dexfile or list of dex files to dump.
    file_summary: Display summary information from the file header. (-f)

  Returns:
    An iterable over the output lines.
  """
  # TODO(jbudorick): Add support for more options as necessary.
  if isinstance(dexfiles, basestring):
    dexfiles = [dexfiles]
  args = [_dexdump_path.read()] + dexfiles
  if file_summary:
    args.append('-f')

  return cmd_helper.IterCmdOutputLines(args)

