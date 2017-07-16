# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import math
import json


class ParsedTraceEvents(object):
  def __init__(self, events = None, trace_filename = None):
    """
    Utility class for filtering and manipulating trace data.

    events -- An iterable object containing trace events
    trace_filename -- A file object that contains a complete trace.

    """
    if trace_filename and events:
      raise Exception("Provide either a trace file or event list")
    if not trace_filename and events == None:
      raise Exception("Provide either a trace file or event list")

    if trace_filename:
      f = open(trace_filename, 'r')
      t = f.read()
      f.close()

      # If the event data begins with a [, then we know it should end with a ].
      # The reason we check for this is because some tracing implementations
      # cannot guarantee that a ']' gets written to the trace file. So, we are
      # forgiving and if this is obviously the case, we fix it up before
      # throwing the string at JSON.parse.
      if t[0] == '[':
        n = len(t);
        if t[n - 1] != ']' and t[n - 1] != '\n':
          t = t + ']'
        elif t[n - 2] != ']' and t[n - 1] == '\n':
          t = t + ']'
        elif t[n - 3] != ']' and t[n - 2] == '\r' and t[n - 1] == '\n':
          t = t + ']'

      try:
        events = json.loads(t)
      except ValueError:
        raise Exception("Corrupt trace, did not parse. Value: %s" % t)

      if 'traceEvents' in events:
        events = events['traceEvents']

    if not hasattr(events, '__iter__'):
      raise Exception, 'events must be iteraable.'
    self.events = events
    self.pids = None
    self.tids = None

  def __len__(self):
    return len(self.events)

  def __getitem__(self, i):
    return self.events[i]

  def __setitem__(self, i, v):
    self.events[i] = v

  def __repr__(self):
    return "[%s]" % ",\n ".join([repr(e) for e in self.events])

  def findProcessIds(self):
    if self.pids:
      return self.pids
    pids = set()
    for e in self.events:
      if "pid" in e and e["pid"]:
        pids.add(e["pid"])
    self.pids = list(pids)
    return self.pids

  def findThreadIds(self):
    if self.tids:
      return self.tids
    tids = set()
    for e in self.events:
      if "tid" in e and e["tid"]:
        tids.add(e["tid"])
    self.tids = list(tids)
    return self.tids

  def findEventsOnProcess(self, pid):
    return ParsedTraceEvents([e for e in self.events if e["pid"] == pid])

  def findEventsOnThread(self, tid):
    return ParsedTraceEvents(
        [e for e in self.events if e["ph"] != "M" and e["tid"] == tid])

  def findByPhase(self, ph):
    return ParsedTraceEvents([e for e in self.events if e["ph"] == ph])

  def findByName(self, n):
    return ParsedTraceEvents([e for e in self.events if e["name"] == n])
