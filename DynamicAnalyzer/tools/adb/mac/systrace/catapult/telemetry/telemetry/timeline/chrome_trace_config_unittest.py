# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.timeline import chrome_trace_category_filter
from telemetry.timeline import chrome_trace_config


class ChromeTraceConfigTests(unittest.TestCase):
  def testDefault(self):
    config = chrome_trace_config.ChromeTraceConfig()

    # Trace config for startup tracing.
    self.assertEquals({
        'record_mode': 'record-as-much-as-possible'
    }, config.GetChromeTraceConfigForStartupTracing())

    # Trace config for DevTools (modern API).
    self.assertEquals({
        'recordMode': 'recordAsMuchAsPossible'
    }, config.GetChromeTraceConfigForDevTools())

    # Trace categories and options for DevTools (legacy API).
    self.assertFalse(config.requires_modern_devtools_tracing_start_api)
    self.assertEquals(
        ('', 'record-as-much-as-possible'),
        config.GetChromeTraceCategoriesAndOptionsForDevTools())

  def testBasic(self):
    category_filter = chrome_trace_category_filter.ChromeTraceCategoryFilter(
        'x,-y,disabled-by-default-z,DELAY(7;foo)')
    config = chrome_trace_config.ChromeTraceConfig()
    config.SetCategoryFilter(category_filter)
    config.record_mode = chrome_trace_config.RECORD_UNTIL_FULL

    # Trace config for startup tracing.
    self.assertEquals({
        'excluded_categories': ['y'],
        'included_categories': ['x', 'disabled-by-default-z'],
        'record_mode': 'record-until-full',
        'synthetic_delays': ['DELAY(7;foo)']
    }, config.GetChromeTraceConfigForStartupTracing())

    # Trace config for DevTools (modern API).
    self.assertEquals({
        'excludedCategories': ['y'],
        'includedCategories': ['x', 'disabled-by-default-z'],
        'recordMode': 'recordUntilFull',
        'syntheticDelays': ['DELAY(7;foo)']
    }, config.GetChromeTraceConfigForDevTools())

    # Trace categories and options for DevTools (legacy API).
    self.assertFalse(config.requires_modern_devtools_tracing_start_api)
    self.assertEquals(
        ('x,disabled-by-default-z,-y,DELAY(7;foo)',
         'record-until-full'),
        config.GetChromeTraceCategoriesAndOptionsForDevTools())

  def testMemoryDumpConfigFormat(self):
    config = chrome_trace_config.ChromeTraceConfig()
    config.record_mode = chrome_trace_config.ECHO_TO_CONSOLE
    dump_config = chrome_trace_config.MemoryDumpConfig()
    config.SetMemoryDumpConfig(dump_config)

    # Trace config for startup tracing.
    self.assertEquals({
        'memory_dump_config': {'triggers': []},
        'record_mode': 'trace-to-console'
    }, config.GetChromeTraceConfigForStartupTracing())

    # Trace config for DevTools (modern API).
    self.assertEquals({
        'memoryDumpConfig': {'triggers': []},
        'recordMode': 'traceToConsole'
    }, config.GetChromeTraceConfigForDevTools())

    # Trace categories and options for DevTools (legacy API).
    self.assertTrue(config.requires_modern_devtools_tracing_start_api)
    with self.assertRaises(AssertionError):
      config.GetChromeTraceCategoriesAndOptionsForDevTools()

    dump_config.AddTrigger('light', 250)
    dump_config.AddTrigger('detailed', 2000)

    # Trace config for startup tracing.
    self.assertEquals({
        'memory_dump_config': {
            'triggers': [
                {'mode': 'light', 'periodic_interval_ms': 250},
                {'mode': 'detailed', 'periodic_interval_ms': 2000}
            ]
        },
        'record_mode': 'trace-to-console'
    }, config.GetChromeTraceConfigForStartupTracing())

    # Trace config for DevTools (modern API).
    self.assertEquals({
        'memoryDumpConfig': {
            'triggers': [
                {'mode': 'light', 'periodicIntervalMs': 250},
                {'mode': 'detailed', 'periodicIntervalMs': 2000}
            ]
        },
        'recordMode': 'traceToConsole'
    }, config.GetChromeTraceConfigForDevTools())

    # Trace categories and options for DevTools (legacy API).
    self.assertTrue(config.requires_modern_devtools_tracing_start_api)
    with self.assertRaises(AssertionError):
      config.GetChromeTraceCategoriesAndOptionsForDevTools()
