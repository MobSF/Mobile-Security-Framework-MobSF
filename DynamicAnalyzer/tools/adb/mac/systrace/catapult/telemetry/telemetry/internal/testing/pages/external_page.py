#!/usr/bin/env python
# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.page.page import Page


class ExternalPage(Page):
  def __init__(self, ps):
    super(ExternalPage, self).__init__('file://foo.html', page_set=ps)
