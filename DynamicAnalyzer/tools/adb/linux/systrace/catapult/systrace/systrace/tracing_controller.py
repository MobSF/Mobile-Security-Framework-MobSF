#!/usr/bin/env python

# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

'''Tracing controller class. This class manages
multiple tracing agents and collects data from all of them. It also
manages the clock sync process.
'''

import ast
import sys
import py_utils
import tempfile
import uuid

from systrace import trace_result
from systrace import tracing_agents
from py_trace_event import trace_event


TRACE_DATA_CONTROLLER_NAME = 'systraceController'


def ControllerAgentClockSync(issue_ts, name):
  """Record the clock sync marker for controller tracing agent.

  Unlike with the other tracing agents, the tracing controller should not
  call this directly. Rather, it is called via callback from the other
  tracing agents when they write a trace.
  """
  trace_event.clock_sync(name, issue_ts=issue_ts)


class TracingControllerAgent(tracing_agents.TracingAgent):
  def __init__(self):
    super(TracingControllerAgent, self).__init__()
    self._log_path = None

  @py_utils.Timeout(tracing_agents.START_STOP_TIMEOUT)
  def StartAgentTracing(self, config, timeout=None):
    """Start tracing for the controller tracing agent.

    Start tracing for the controller tracing agent. Note that
    the tracing controller records the "controller side"
    of the clock sync records, and nothing else.
    """
    del config
    if not trace_event.trace_can_enable():
      raise RuntimeError, ('Cannot enable trace_event;'
                           ' ensure py_utils is in PYTHONPATH')

    controller_log_file = tempfile.NamedTemporaryFile(delete=False)
    self._log_path = controller_log_file.name
    controller_log_file.close()
    trace_event.trace_enable(self._log_path)
    return True

  @py_utils.Timeout(tracing_agents.START_STOP_TIMEOUT)
  def StopAgentTracing(self, timeout=None):
    """Stops tracing for the controller tracing agent.
    """
    # pylint: disable=no-self-use
    # This function doesn't use self, but making it a member function
    # for consistency with the other TracingAgents
    trace_event.trace_disable()
    return True

  @py_utils.Timeout(tracing_agents.GET_RESULTS_TIMEOUT)
  def GetResults(self, timeout=None):
    """Gets the log output from the controller tracing agent.

    This output only contains the "controller side" of the clock sync records.
    """
    with open(self._log_path, 'r') as outfile:
      result = outfile.read() + ']'
    return trace_result.TraceResult(TRACE_DATA_CONTROLLER_NAME,
                                    ast.literal_eval(result))

  def SupportsExplicitClockSync(self):
    """Returns whether this supports explicit clock sync.
    Although the tracing controller conceptually supports explicit clock
    sync, it is not an agent controlled by other controllers so it does not
    define RecordClockSyncMarker (rather, the recording of the "controller
    side" of the clock sync marker is done in _IssueClockSyncMarker). Thus,
    SupportsExplicitClockSync must return false.
    """
    return False

  # pylint: disable=unused-argument
  def RecordClockSyncMarker(self, sync_id, callback):
    raise NotImplementedError

class TracingController(object):
  def __init__(self, agents_with_config, controller_config):
    """Create tracing controller.

    Create a tracing controller object. Note that the tracing
    controller is also a tracing agent.

    Args:
       agents_with_config: List of tracing agents for this controller with the
                           corresponding tracing configuration objects.
       controller_config:  Configuration options for the tracing controller.
    """
    self._child_agents = None
    self._child_agents_with_config = agents_with_config
    self._controller_agent = TracingControllerAgent()
    self._controller_config = controller_config
    self._trace_in_progress = False
    self.all_results = None

  @property
  def get_child_agents(self):
    return self._child_agents

  def StartTracing(self):
    """Start tracing for all tracing agents.

    This function starts tracing for both the controller tracing agent
    and the child tracing agents.

    Returns:
        Boolean indicating whether or not the start tracing succeeded.
        Start tracing is considered successful if at least the
        controller tracing agent was started.
    """
    assert not self._trace_in_progress, 'Trace already in progress.'
    self._trace_in_progress = True

    # Start the controller tracing agents. Controller tracing agent
    # must be started successfully to proceed.
    if not self._controller_agent.StartAgentTracing(
        self._controller_config,
        timeout=self._controller_config.timeout):
      print 'Unable to start controller tracing agent.'
      return False

    # Start the child tracing agents.
    succ_agents = []
    for agent_and_config in self._child_agents_with_config:
      agent = agent_and_config.agent
      config = agent_and_config.config
      if agent.StartAgentTracing(config,
                                 timeout=self._controller_config.timeout):
        succ_agents.append(agent)
      else:
        print 'Agent %s not started.' % str(agent)

    # Print warning if all agents not started.
    na = len(self._child_agents_with_config)
    ns = len(succ_agents)
    if ns < na:
      print 'Warning: Only %d of %d tracing agents started.' % (ns, na)
    self._child_agents = succ_agents
    return True

  def StopTracing(self):
    """Issue clock sync marker and stop tracing for all tracing agents.

    This function stops both the controller tracing agent
    and the child tracing agents. It issues a clock sync marker prior
    to stopping tracing.

    Returns:
        Boolean indicating whether or not the stop tracing succeeded
        for all agents.
    """
    assert self._trace_in_progress, 'No trace in progress.'
    self._trace_in_progress = False

    # Issue the clock sync marker and stop the child tracing agents.
    self._IssueClockSyncMarker()
    succ_agents = []
    for agent in self._child_agents:
      if agent.StopAgentTracing(timeout=self._controller_config.timeout):
        succ_agents.append(agent)
      else:
        print 'Agent %s not stopped.' % str(agent)

    # Stop the controller tracing agent. Controller tracing agent
    # must be stopped successfully to proceed.
    if not self._controller_agent.StopAgentTracing(
        timeout=self._controller_config.timeout):
      print 'Unable to stop controller tracing agent.'
      return False

    # Print warning if all agents not stopped.
    na = len(self._child_agents)
    ns = len(succ_agents)
    if ns < na:
      print 'Warning: Only %d of %d tracing agents stopped.' % (ns, na)
      self._child_agents = succ_agents

    # Collect the results from all the stopped tracing agents.
    all_results = []
    for agent in self._child_agents + [self._controller_agent]:
      try:
        result = agent.GetResults(
            timeout=self._controller_config.collection_timeout)
        if not result:
          print 'Warning: Timeout when getting results from %s.' % str(agent)
          continue
        if result.source_name in [r.source_name for r in all_results]:
          print ('Warning: Duplicate tracing agents named %s.' %
                 result.source_name)
        all_results.append(result)
      # Check for exceptions. If any exceptions are seen, reraise and abort.
      # Note that a timeout exception will be swalloed by the timeout
      # mechanism and will not get to that point (it will return False instead
      # of the trace result, which will be dealt with above)
      except:
        print 'Warning: Exception getting results from %s:' % str(agent)
        print sys.exc_info()[0]
        raise
    self.all_results = all_results
    return all_results

  def GetTraceType(self):
    """Return a string representing the child agents that are being traced."""
    sorted_agents = sorted(map(str, self._child_agents))
    return ' + '.join(sorted_agents)

  def _IssueClockSyncMarker(self):
    """Issue clock sync markers to all the child tracing agents."""
    for agent in self._child_agents:
      if agent.SupportsExplicitClockSync():
        sync_id = GetUniqueSyncID()
        agent.RecordClockSyncMarker(sync_id, ControllerAgentClockSync)

def GetUniqueSyncID():
  """Get a unique sync ID.

  Gets a unique sync ID by generating a UUID and converting it to a string
  (since UUIDs are not JSON serializable)
  """
  return str(uuid.uuid4())


class AgentWithConfig(object):
  def __init__(self, agent, config):
    self.agent = agent
    self.config = config


def CreateAgentsWithConfig(options, modules):
  """Create tracing agents.

  This function will determine which tracing agents are valid given the
  options and create those agents along with their corresponding configuration
  object.
  Args:
    options: The command-line options.
    modules: The modules for either Systrace or profile_chrome.
             TODO(washingtonp): After all profile_chrome agents are in
             Systrace, this parameter will no longer be valid.
  Returns:
    A list of AgentWithConfig options containing agents and their corresponding
    configuration object.
  """
  result = []
  for module in modules:
    config = module.get_config(options)
    agent = module.try_create_agent(config)
    if agent and config:
      result.append(AgentWithConfig(agent, config))
  return [x for x in result if x and x.agent]


class TracingControllerConfig(tracing_agents.TracingConfig):
  def __init__(self, output_file, trace_time, write_json,
               link_assets, asset_dir, timeout, collection_timeout,
               device_serial_number, target):
    tracing_agents.TracingConfig.__init__(self)
    self.output_file = output_file
    self.trace_time = trace_time
    self.write_json = write_json
    self.link_assets = link_assets
    self.asset_dir = asset_dir
    self.timeout = timeout
    self.collection_timeout = collection_timeout
    self.device_serial_number = device_serial_number
    self.target = target


def GetControllerConfig(options):
  return TracingControllerConfig(options.output_file, options.trace_time,
                                 options.write_json,
                                 options.link_assets, options.asset_dir,
                                 options.timeout, options.collection_timeout,
                                 options.device_serial_number, options.target)

def GetChromeStartupControllerConfig(options):
  return TracingControllerConfig(None, options.trace_time,
                                 options.write_json, None, None, None, None,
                                 None, None)
