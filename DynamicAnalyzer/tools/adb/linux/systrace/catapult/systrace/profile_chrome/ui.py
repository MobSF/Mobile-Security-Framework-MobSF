# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import select
import sys


def PrintMessage(heading, eol='\n'):
  sys.stdout.write('%s%s' % (heading, eol))
  sys.stdout.flush()


def WaitForEnter(timeout):
  select.select([sys.stdin], [], [], timeout)


def EnableTestMode():
  def NoOp(*_, **__):  # pylint: disable=unused-argument
    pass
  # pylint: disable=W0601
  global PrintMessage
  global WaitForEnter
  PrintMessage = NoOp
  WaitForEnter = NoOp
  logging.getLogger().disabled = True
