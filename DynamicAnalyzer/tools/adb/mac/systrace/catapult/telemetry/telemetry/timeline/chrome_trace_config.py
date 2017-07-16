# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import re

from telemetry.timeline import chrome_trace_category_filter


RECORD_MODE_PARAM = 'record_mode'

ECHO_TO_CONSOLE = 'trace-to-console'
RECORD_AS_MUCH_AS_POSSIBLE = 'record-as-much-as-possible'
RECORD_CONTINUOUSLY = 'record-continuously'
RECORD_UNTIL_FULL = 'record-until-full'

# Map telemetry's tracing record_mode to the DevTools API string.
# (The keys happen to be the same as the values.)
RECORD_MODE_MAP = {
  RECORD_UNTIL_FULL: 'record-until-full',
  RECORD_CONTINUOUSLY: 'record-continuously',
  RECORD_AS_MUCH_AS_POSSIBLE: 'record-as-much-as-possible',
  ECHO_TO_CONSOLE: 'trace-to-console'
}


def ConvertStringToCamelCase(string):
  """Convert an underscore/hyphen-case string to its camel-case counterpart.

  This function is the inverse of Chromium's ConvertFromCamelCase function
  in src/content/browser/devtools/protocol/tracing_handler.cc.
  """
  parts = re.split(r'[-_]', string)
  return parts[0] + ''.join([p.title() for p in parts[1:]])


def ConvertDictKeysToCamelCaseRecursively(data):
  """Recursively convert dictionary keys from underscore/hyphen- to camel-case.

  This function is the inverse of Chromium's ConvertDictKeyStyle function
  in src/content/browser/devtools/protocol/tracing_handler.cc.
  """
  if isinstance(data, dict):
    return {ConvertStringToCamelCase(k):
            ConvertDictKeysToCamelCaseRecursively(v)
            for k, v in data.iteritems()}
  elif isinstance(data, list):
    return map(ConvertDictKeysToCamelCaseRecursively, data)
  else:
    return data


class ChromeTraceConfig(object):
  """Stores configuration options specific to the Chrome tracing agent.

    This produces the trace config JSON string for tracing in Chrome.

    record_mode: can be any mode in RECORD_MODE_MAP. This corresponds to
        record modes in chrome.
    category_filter: Object that specifies which tracing categories to trace.
    memory_dump_config: Stores the triggers for memory dumps.
  """

  def __init__(self):
    self._record_mode = RECORD_AS_MUCH_AS_POSSIBLE
    self._category_filter = (
        chrome_trace_category_filter.ChromeTraceCategoryFilter())
    self._memory_dump_config = None

  def SetLowOverheadFilter(self):
    self._category_filter = (
        chrome_trace_category_filter.CreateLowOverheadFilter())

  def SetDefaultOverheadFilter(self):
    self._category_filter = (
        chrome_trace_category_filter.CreateDefaultOverheadFilter())

  def SetDebugOverheadFilter(self):
    self._category_filter = (
        chrome_trace_category_filter.CreateDebugOverheadFilter())

  @property
  def category_filter(self):
    return self._category_filter

  def SetCategoryFilter(self, cf):
    if isinstance(cf, chrome_trace_category_filter.ChromeTraceCategoryFilter):
      self._category_filter = cf
    else:
      raise TypeError(
          'Must pass SetCategoryFilter a ChromeTraceCategoryFilter instance')

  def SetMemoryDumpConfig(self, dump_config):
    if isinstance(dump_config, MemoryDumpConfig):
      self._memory_dump_config = dump_config
    else:
      raise TypeError(
          'Must pass SetMemoryDumpConfig a MemoryDumpConfig instance')

  @property
  def record_mode(self):
    return self._record_mode

  @record_mode.setter
  def record_mode(self, value):
    assert value in RECORD_MODE_MAP
    self._record_mode = value

  def GetChromeTraceConfigForStartupTracing(self):
    """Map the config to a JSON string for startup tracing.

    All keys in the returned dictionary use underscore-case (e.g.
    'record_mode'). In addition, the 'record_mode' value uses hyphen-case
    (e.g. 'record-until-full').
    """
    result = {
        RECORD_MODE_PARAM: RECORD_MODE_MAP[self._record_mode]
    }
    result.update(self._category_filter.GetDictForChromeTracing())
    if self._memory_dump_config:
      result.update(self._memory_dump_config.GetDictForChromeTracing())
    return result

  @property
  def requires_modern_devtools_tracing_start_api(self):
    """Returns True iff the config CANNOT be passed via the legacy DevTools API.

    Legacy DevTools Tracing.start API:
      Available since:    the introduction of the Tracing.start request.
      Parameters:         categories (string), options (string),
                          bufferUsageReportingInterval (number),
                          transferMode (enum).
      TraceConfig method: GetChromeTraceCategoriesAndOptionsStringsForDevTools()

    Modern DevTools Tracing.start API:
      Available since:    Chrome 51.0.2683.0.
      Parameters:         traceConfig (dict),
                          bufferUsageReportingInterval (number),
                          transferMode (enum).
      TraceConfig method: GetChromeTraceConfigDictForDevTools()
    """
    # Memory dump config cannot be passed via the 'options' string (legacy API)
    # in the DevTools Tracing.start request.
    return bool(self._memory_dump_config)

  def GetChromeTraceConfigForDevTools(self):
    """Map the config to a DevTools API config dictionary.

    All keys in the returned dictionary use camel-case (e.g. 'recordMode').
    In addition, the 'recordMode' value also uses camel-case (e.g.
    'recordUntilFull'). This is to invert the camel-case ->
    underscore/hyphen-delimited mapping performed in Chromium devtools.
    """
    result = self.GetChromeTraceConfigForStartupTracing()
    if result[RECORD_MODE_PARAM]:
      result[RECORD_MODE_PARAM] = ConvertStringToCamelCase(
          result[RECORD_MODE_PARAM])
    return ConvertDictKeysToCamelCaseRecursively(result)

  def GetChromeTraceCategoriesAndOptionsForDevTools(self):
    """Map the categories and options to their DevTools API counterparts."""
    assert not self.requires_modern_devtools_tracing_start_api
    options_parts = [RECORD_MODE_MAP[self._record_mode]]
    return (self._category_filter.stable_filter_string,
            ','.join(options_parts))


class MemoryDumpConfig(object):
  """Stores the triggers for memory dumps in ChromeTraceConfig."""
  def __init__(self):
    self._triggers = []

  def AddTrigger(self, mode, periodic_interval_ms):
    """Adds a new trigger to config.

    Args:
      periodic_interval_ms: Dump time period in milliseconds.
      level_of_detail: Memory dump level of detail string.
          Valid arguments are "background", "light" and "detailed".
    """
    assert mode in ['background', 'light', 'detailed']
    assert periodic_interval_ms > 0
    self._triggers.append({'mode': mode,
                           'periodic_interval_ms': periodic_interval_ms})

  def GetDictForChromeTracing(self):
    """Returns the dump config as dictionary for chrome tracing."""
    # An empty trigger list would mean no periodic memory dumps.
    return {'memory_dump_config': {'triggers': self._triggers}}
