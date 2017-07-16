# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from systrace.tracing_agents import atrace_agent

class AtraceConfig(object):
  """Stores configuration options specific to Atrace.

    categories: List that specifies the Atrace categories to trace.
        Example: ['sched', 'webview']
    app_name: String or list that specifies the application name (or names)
        on which to run application level tracing.
        Example: 'org.chromium.webview_shell'
  """
  def __init__(self):
    self.categories = atrace_agent.DEFAULT_CATEGORIES
    self.app_name = None
