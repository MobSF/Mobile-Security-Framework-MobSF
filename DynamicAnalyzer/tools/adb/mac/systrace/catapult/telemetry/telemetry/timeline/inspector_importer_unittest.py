# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import unittest

from telemetry.timeline import inspector_importer
from telemetry.timeline import model
from tracing.trace_data import trace_data


_BACKGROUND_MESSAGE = {
  'data': {},
  'type': 'BeginFrame',
  'thread': '2',
  'startTime': 1352783525921.824}

_SAMPLE_MESSAGE = {
  'children': [
    {'data': {},
     'startTime': 1352783525921.823,
     'type': 'BeginFrame',
     'usedHeapSize': 1870736},
    {'children': [],
     'data': {'height': 723,
              'width': 1272,
              'x': 0,
              'y': 0},
     'endTime': 1352783525921.8992,
     'frameId': '10.2',
     'startTime': 1352783525921.8281,
     'type': 'Layout',
     'usedHeapSize': 1870736},
    {'children': [
        {'children': [],
         'data': {'imageType': 'PNG'},
         'endTime': 1352783525927.7939,
         'startTime': 1352783525922.4241,
         'type': 'DecodeImage',
         'usedHeapSize': 1870736}
        ],
     'data': {'height': 432,
              'width': 1272,
              'x': 0,
              'y': 8},
     'endTime': 1352783525927.9822,
     'frameId': '10.2',
     'startTime': 1352783525921.9292,
     'type': 'Paint',
     'usedHeapSize': 1870736}
    ],
  'data': {},
  'endTime': 1352783525928.041,
  'startTime': 1352783525921.8049,
  'type': 'Program'}

class InspectorEventParsingTest(unittest.TestCase):
  def testParsingWithSampleData(self):
    root_event = (inspector_importer.InspectorTimelineImporter
        .RawEventToTimelineEvent(_SAMPLE_MESSAGE))
    self.assertTrue(root_event)
    decode_image_event = [
      child for child in root_event.IterEventsInThisContainerRecrusively()
      if child.name == 'DecodeImage'][0]
    self.assertEquals(decode_image_event.args['data']['imageType'], 'PNG')
    self.assertTrue(decode_image_event.duration > 0)

  def testParsingWithSimpleData(self):
    raw_event = {'type': 'Foo',
                 'startTime': 1,
                 'endTime': 3,
                 'children': []}
    event = (inspector_importer.InspectorTimelineImporter
        .RawEventToTimelineEvent(raw_event))
    self.assertEquals('Foo', event.name)
    self.assertEquals(1, event.start)
    self.assertEquals(3, event.end)
    self.assertEquals(2, event.duration)
    self.assertEquals([], event.sub_slices)

  def testParsingWithArgs(self):
    raw_event = {'type': 'Foo',
                 'startTime': 1,
                 'endTime': 3,
                 'foo': 7,
                 'bar': {'x': 1}}
    event = (inspector_importer.InspectorTimelineImporter
        .RawEventToTimelineEvent(raw_event))
    self.assertEquals('Foo', event.name)
    self.assertEquals(1, event.start)
    self.assertEquals(3, event.end)
    self.assertEquals(2, event.duration)
    self.assertEquals([], event.sub_slices)
    self.assertEquals(7, event.args['foo'])
    self.assertEquals(1, event.args['bar']['x'])

  def testEventsWithNoStartTimeAreDropped(self):
    raw_event = {'type': 'Foo',
                 'endTime': 1,
                 'children': []}
    event = (inspector_importer.InspectorTimelineImporter.
        RawEventToTimelineEvent(raw_event))
    self.assertEquals(None, event)

  def testEventsWithNoEndTimeAreOk(self):
    raw_event = {'type': 'Foo',
                 'startTime': 1,
                 'children': []}
    event = (inspector_importer.InspectorTimelineImporter.
        RawEventToTimelineEvent(raw_event))
    self.assertEquals(1, event.start)
    self.assertEquals(1, event.end)

  def testOutOfOrderData(self):
    builder = trace_data.TraceDataBuilder()
    builder.AddTraceFor(
      trace_data.INSPECTOR_TRACE_PART, [{
      'startTime': 5295.004, 'endTime': 5305.004,
      'data': {}, 'type': 'Program',
      'children': [
        {'startTime': 5295.004, 'data': {'id': 0}, 'type': 'BeginFrame', },
        {'startTime': 4492.973, 'endTime': 4493.086, 'data': {'rootNode': -3},
         'type': 'PaintSetup'},
        {'startTime': 5298.004, 'endTime': 5301.004, 'type': 'Paint',
         'frameId': '53228.1',
         'data': {'rootNode': -3, 'clip': [0, 0, 1018, 0, 1018, 764, 0, 764],
                  'layerId': 10}, 'children': []},
        {'startTime': 5301.004, 'endTime': 5305.004, 'data': {},
         'type': 'CompositeLayers', 'children': []},
        {'startTime': 5305.004, 'data': {}, 'type': 'MarkFirstPaint'}
    ]}])
    model.TimelineModel(builder.AsData(), shift_world_to_zero=False)

class InspectorImporterTest(unittest.TestCase):
  def testImport(self):
    builder = trace_data.TraceDataBuilder()
    builder.AddTraceFor(trace_data.INSPECTOR_TRACE_PART,
                        [_BACKGROUND_MESSAGE, _SAMPLE_MESSAGE])
    m = model.TimelineModel(builder.AsData(), shift_world_to_zero=False)
    self.assertEquals(1, len(m.processes))
    process = m.processes.values()[0]
    threads = process.threads
    self.assertEquals(2, len(threads))
    renderer_thread = threads[0]
    self.assertEquals(1, len(renderer_thread.toplevel_slices))
    self.assertEquals('Program',
                      renderer_thread.toplevel_slices[0].name)
    second_thread = threads['2']
    self.assertEquals(1, len(second_thread.toplevel_slices))
    self.assertEquals('BeginFrame',
                      second_thread.toplevel_slices[0].name)
