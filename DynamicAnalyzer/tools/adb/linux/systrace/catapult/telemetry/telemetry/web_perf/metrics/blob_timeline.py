# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.value import improvement_direction
from telemetry.value import list_of_scalar_values
from telemetry.web_perf.metrics import timeline_based_metric


WRITE_EVENT_NAME = 'Registry::RegisterBlob'
READ_EVENT_NAME = 'BlobRequest'


class BlobTimelineMetric(timeline_based_metric.TimelineBasedMetric):
  """BlobTimelineMetric reports timing information about blob storage.

  The following metrics are added to the results:
    * blob write times (blob_writes)
    * blob read times (blob_reads)
  """

  def __init__(self):
    super(BlobTimelineMetric, self).__init__()

  @staticmethod
  def IsWriteEvent(event):
    return event.name == WRITE_EVENT_NAME

  @staticmethod
  def IsReadEvent(event):
    return event.name == READ_EVENT_NAME

  @staticmethod
  def IsEventInInteraction(event, interaction):
    return interaction.start <= event.start <= interaction.end

  @staticmethod
  def ThreadDurationIfPresent(event):
    if event.thread_duration:
      return event.thread_duration
    else:
      return event.duration

  def AddResults(self, model, renderer_thread, interactions, results):
    assert interactions

    write_events = []
    read_events = []
    for event in model.IterAllEvents(
        event_predicate=lambda e: self.IsWriteEvent(e) or self.IsReadEvent(e)):
      if self.IsReadEvent(event):
        read_events.append(event)
      else:
        write_events.append(event)

    # Only these private methods are tested for mocking simplicity.
    self._AddWriteResultsInternal(write_events, interactions, results)
    self._AddReadResultsInternal(read_events, interactions, results)

  def _AddWriteResultsInternal(self, events, interactions, results):
    writes = []
    for event in events:
      if (self.IsWriteEvent(event) and
          any(self.IsEventInInteraction(event, interaction)
              for interaction in interactions)):
        writes.append(self.ThreadDurationIfPresent(event))
    if writes:
      results.AddValue(list_of_scalar_values.ListOfScalarValues(
          page=results.current_page,
          tir_label=interactions[0].label,
          name='blob-writes',
          units='ms',
          values=writes,
          description='List of durations of blob writes.',
          improvement_direction=improvement_direction.DOWN))
    else:
      results.AddValue(list_of_scalar_values.ListOfScalarValues(
          page=results.current_page,
          tir_label=interactions[0].label,
          name='blob-writes',
          units='ms',
          values=None,
          none_value_reason='No blob write events found for this interaction.',
          improvement_direction=improvement_direction.DOWN))

  def _AddReadResultsInternal(self, events, interactions, results):
    reads = dict()
    for event in events:
      if (not self.IsReadEvent(event) or
          not any(self.IsEventInInteraction(event, interaction)
                 for interaction in interactions)):
        continue
      # Every blob has unique UUID.  To get the total time for reading
      # a blob, we add up the time of all events with the same blob UUID.
      uuid = event.args['uuid']
      if uuid not in reads:
        reads[uuid] = 0
      reads[uuid] += self.ThreadDurationIfPresent(event)

    if reads:
      results.AddValue(list_of_scalar_values.ListOfScalarValues(
          page=results.current_page,
          tir_label=interactions[0].label,
          name='blob-reads',
          units='ms',
          values=reads.values(),
          description='List of read times for blobs.',
          improvement_direction=improvement_direction.DOWN))
    else:
      results.AddValue(list_of_scalar_values.ListOfScalarValues(
          page=results.current_page,
          tir_label=interactions[0].label,
          name='blob-reads',
          units='ms',
          values=None,
          none_value_reason='No blob read events found for this interaction.',
          improvement_direction=improvement_direction.DOWN))
