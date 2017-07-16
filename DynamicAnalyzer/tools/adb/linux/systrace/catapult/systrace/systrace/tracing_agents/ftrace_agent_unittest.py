#!/usr/bin/env python

# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest
import logging

from systrace import decorators
from systrace import run_systrace
from systrace.tracing_agents import ftrace_agent


SYSTRACE_HOST_CMD_DEFAULT = ['./systrace.py', '--target=linux']
FT_DIR = "/sys/kernel/debug/tracing/"
FT_EVENT_DIR = FT_DIR + "events/"
FT_TRACE_ON = FT_DIR + "tracing_on"
FT_TRACE = FT_DIR + "trace"
FT_BUFFER_SIZE = FT_DIR + "buffer_size_kb"


def make_test_io_interface(permitted_files):
  class TestIoImpl(object):

    @staticmethod
    def writeFile(path, data):
      permitted_files[path] = data

    @staticmethod
    def readFile(path):
      if path in permitted_files:
        return permitted_files[path]
      else:
        return ""

    @staticmethod
    def haveWritePermissions(path):
      return path in permitted_files

  return TestIoImpl


class FtraceAgentTest(unittest.TestCase):

  @decorators.HostOnlyTest
  def test_avail_categories(self):
    # sched only has required events
    permitted_files = {
      FT_EVENT_DIR + "sched/sched_switch/enable": "0",
      FT_EVENT_DIR + "sched/sched_wakeup/enable": "0"
    }
    io_interface = make_test_io_interface(permitted_files)
    agent = ftrace_agent.FtraceAgent(io_interface)
    self.assertEqual(['sched'], agent._avail_categories())

    # check for no available categories
    permitted_files = {}
    io_interface = make_test_io_interface(permitted_files)
    agent = ftrace_agent.FtraceAgent(io_interface)
    self.assertEqual([], agent._avail_categories())

    # block has some required, some optional events
    permitted_files = {
      FT_EVENT_DIR + "block/block_rq_complete/enable": "0",
      FT_EVENT_DIR + "block/block_rq_issue/enable": "0"
    }
    io_interface = make_test_io_interface(permitted_files)
    agent = ftrace_agent.FtraceAgent(io_interface)
    self.assertEqual(['disk'], agent._avail_categories())

  @decorators.HostOnlyTest
  def test_tracing_bootstrap(self):
    workq_event_path = FT_EVENT_DIR + "workqueue/enable"
    permitted_files = {
      workq_event_path: "0",
      FT_TRACE: "x"
    }
    io_interface = make_test_io_interface(permitted_files)
    systrace_cmd = SYSTRACE_HOST_CMD_DEFAULT + ["workq"]
    options, categories = run_systrace.parse_options(systrace_cmd)
    agent = ftrace_agent.FtraceAgent(io_interface)
    self.assertEqual(['workq'], agent._avail_categories())

    # confirm tracing is enabled, buffer is cleared
    agent.StartAgentTracing(options, categories)
    self.assertEqual(permitted_files[FT_TRACE_ON], "1")
    self.assertEqual(permitted_files[FT_TRACE], "")

    # fill in file with dummy contents
    dummy_trace = "trace_contents"
    permitted_files[FT_TRACE] = dummy_trace

    # confirm tracing is disabled
    agent.StopAgentTracing()
    agent.GetResults()
    self.assertEqual(permitted_files[FT_TRACE_ON], "0")

    # confirm trace is expected, and read from fs
    self.assertEqual(agent.GetResults().raw_data, dummy_trace)

    # confirm buffer size is reset to 1
    self.assertEqual(permitted_files[FT_BUFFER_SIZE], "1")

  @decorators.HostOnlyTest
  def test_tracing_event_enable_disable(self):
    # turn on irq tracing
    ipi_event_path = FT_EVENT_DIR + "ipi/enable"
    irq_event_path = FT_EVENT_DIR + "irq/enable"
    permitted_files = {
      ipi_event_path: "0",
      irq_event_path: "0"
    }
    io_interface = make_test_io_interface(permitted_files)
    systrace_cmd = SYSTRACE_HOST_CMD_DEFAULT + ["irq"]
    options, categories = run_systrace.parse_options(systrace_cmd)
    options.ftrace_categories = categories
    agent = ftrace_agent.FtraceAgent(io_interface)
    self.assertEqual(['irq'], agent._avail_categories())

    # confirm all the event nodes are turned on during tracing
    agent.StartAgentTracing(options)
    self.assertEqual(permitted_files[irq_event_path], "1")
    self.assertEqual(permitted_files[ipi_event_path], "1")

    # and then turned off when completed.
    agent.StopAgentTracing()
    agent.GetResults()
    self.assertEqual(permitted_files[irq_event_path], "0")
    self.assertEqual(permitted_files[ipi_event_path], "0")

  @decorators.HostOnlyTest
  def test_buffer_size(self):
    systrace_cmd = SYSTRACE_HOST_CMD_DEFAULT + ['-b', '16000']
    options, categories = run_systrace.parse_options(systrace_cmd)
    agent = ftrace_agent.FtraceAgent()
    agent._config = options
    agent._config.atrace_categories = categories
    self.assertEqual(agent._get_trace_buffer_size(), 16000)

if __name__ == "__main__":
  logging.getLogger().setLevel(logging.DEBUG)
  unittest.main(verbosity=2)
