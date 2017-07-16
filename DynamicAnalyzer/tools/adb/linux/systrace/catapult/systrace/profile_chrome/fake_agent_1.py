# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import optparse
import tempfile

from systrace import trace_result
from systrace import tracing_agents


class FakeAgent(object):
  def __init__(self, contents='fake-contents'):
    self.contents = contents
    self.stopped = False
    self.filename = None
    self.config = None
    self.timeout = None

  def StartAgentTracing(self, config, timeout=None):
    self.config = config
    self.timeout = timeout
    return True

  # pylint: disable=unused-argument
  def StopAgentTracing(self, timeout=None):
    self.stopped = True
    return True

  # pylint: disable=unused-argument
  def GetResults(self, timeout=None):
    trace_data = open(self._PullTrace()).read()
    return trace_result.TraceResult('fakeData', trace_data)

  def _PullTrace(self):
    with tempfile.NamedTemporaryFile(delete=False) as f:
      self.filename = f.name
      f.write(self.contents)
      return f.name

  # pylint: disable=no-self-use
  def SupportsExplicitClockSync(self):
    return False

  # pylint: disable=unused-argument, no-self-use
  def RecordClockSyncMarker(self, sync_id, did_record_sync_marker_callback):
    print ('Clock sync marker cannot be recorded since explicit clock sync '
           'is not supported.')

  def __repr__(self):
    return 'faketrace'


class FakeConfig(tracing_agents.TracingConfig):
  def __init__(self):
    tracing_agents.TracingConfig.__init__(self)


# pylint: disable=unused-argument
def try_create_agent(config):
  return FakeAgent()

def add_options(parser):
  options = optparse.OptionGroup(parser, 'Fake options.')
  return options

# pylint: disable=unused-argument
def get_config(options):
  return FakeConfig()
