# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.timeline import async_slice as async_slice_module
from telemetry.timeline import flow_event as flow_event_module
from telemetry.timeline import slice as slice_module


class TimelineEventContainer(object):
  """Represents a container for events.

  """
  def __init__(self, name, parent):
    self.parent = parent
    self.name = name

  @staticmethod
  def IsAsyncSlice(t):
    return t == async_slice_module.AsyncSlice

  # Basic functions that subclasses of TimelineEventContainer should implement
  # in order to expose their events. New methods should be added to this part of
  # the code only when absolutely certain they're needed.

  def IterChildContainers(self):
    raise NotImplementedError()

  def IterEventsInThisContainer(self, event_type_predicate, event_predicate):
    """Iterates all the TimelineEvents in this container.

    Only events with a type matching event_type_predicate AND matching event
    event_predicate will be yielded.

    event_type_predicate is given an actual type object, e.g.:
        event_type_predicate(slice_module.Slice)

    event_predicate is given actual events:
        event_predicate(thread.slices[7])

    DO NOT ASSUME that the event_type_predicate will be called for every event
    found. The relative calling order of the two is left up to the implementer
    of the method.

    """
    del event_type_predicate, event_predicate  # unused
    return
    yield # pylint: disable=unreachable


  def IterAllEvents(self,
                    recursive=True,
                    event_type_predicate=lambda t: True,
                    event_predicate=lambda e: True):
    """Iterates all events in this container, pre-filtered by two predicates.

    Only events with a type matching event_type_predicate AND matching event
    event_predicate will be yielded.

    event_type_predicate is given an actual type object, e.g.:
        event_type_predicate(slice_module.Slice)

    event_predicate is given actual events:
        event_predicate(thread.slices[7])
    """
    if not recursive:
      for e in self.IterEventsInThisContainer(
          event_type_predicate, event_predicate):
        yield e
      return

    # TODO(nduca): Write this as a proper iterator instead of one that creates a
    # list and then iterates it.
    containers = []
    def GetContainersRecursive(container):
      containers.append(container)
      for container in container.IterChildContainers():
        GetContainersRecursive(container)
    GetContainersRecursive(self)

    # Actually create the iterator.
    for c in containers:
      for e in c.IterEventsInThisContainer(event_type_predicate,
                                           event_predicate):
        yield e

  # Helper functions for finding common kinds of events. Must always take an
  # optinal recurisve parameter and be implemented in terms fo IterAllEvents.
  def IterAllEventsOfName(self, name, recursive=True):
    return self.IterAllEvents(
      recursive=recursive,
      event_type_predicate=lambda t: True,
      event_predicate=lambda e: e.name == name)

  def IterAllSlices(self, recursive=True):
    return self.IterAllEvents(
      recursive=recursive,
      event_type_predicate=lambda t: t == slice_module.Slice)

  def IterAllSlicesInRange(self, start, end, recursive=True):
    return self.IterAllEvents(
      recursive=recursive,
      event_type_predicate=lambda t: t == slice_module.Slice,
      event_predicate=lambda s: s.start >= start and s.end <= end)

  def IterAllSlicesOfName(self, name, recursive=True):
    return self.IterAllEvents(
      recursive=recursive,
      event_type_predicate=lambda t: t == slice_module.Slice,
      event_predicate=lambda e: e.name == name)

  def IterAllToplevelSlicesOfName(self, name, recursive=True):
    return self.IterAllEvents(
      recursive=recursive,
      event_type_predicate=lambda t: t == slice_module.Slice,
      event_predicate=lambda e: e.name == name and e.parent_slice == None)

  def IterAllAsyncSlicesOfName(self, name, recursive=True):
    return self.IterAllEvents(
      recursive=recursive,
      event_type_predicate=self.IsAsyncSlice,
      event_predicate=lambda e: e.name == name)

  def IterAllAsyncSlicesStartsWithName(self, name, recursive=True):
    return self.IterAllEvents(
      recursive=recursive,
      event_type_predicate=self.IsAsyncSlice,
      event_predicate=lambda e: e.name.startswith(name))

  def IterAllFlowEvents(self, recursive=True):
    return self.IterAllEvents(
      recursive=recursive,
      event_type_predicate=lambda t: t == flow_event_module.FlowEvent)

  # List versions. These should always be simple expressions that list() on
  # an underlying iter method.
  def GetAllEvents(self, recursive=True):
    return list(self.IterAllEvents(recursive=recursive))

  def GetAllEventsOfName(self, name, recursive=True):
    return list(self.IterAllEventsOfName(name, recursive))

  def GetAllToplevelSlicesOfName(self, name, recursive=True):
    return list(self.IterAllToplevelSlicesOfName(name, recursive))
