# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import collections
from telemetry.core import exceptions


def DebuggerUrlToId(debugger_url):
  return debugger_url.split('/')[-1]


class InspectorBackendList(collections.Sequence):
  """A dynamic sequence of active InspectorBackends."""

  def __init__(self, browser_backend):
    """Constructor.

    Args:
      browser_backend: The BrowserBackend instance to query for
          InspectorBackends.
    """
    self._browser_backend = browser_backend
    self._devtools_context_map_backend = None
    # A list of filtered contexts.
    self._filtered_context_ids = []
    # A cache of inspector backends, by context ID.
    self._wrapper_dict = {}

  @property
  def _devtools_client(self):
    return self._browser_backend.devtools_client

  @property
  def app(self):
    return self._browser_backend.app

  def GetContextInfo(self, context_id):
    return self._devtools_context_map_backend.GetContextInfo(context_id)

  def ShouldIncludeContext(self, _):
    """Override this method to control which contexts are included."""
    return True

  def CreateWrapper(self, inspector_backend_instance):
    """Override to return the wrapper API over InspectorBackend.

    The wrapper API is the public interface for InspectorBackend. It
    may expose whatever methods are desired on top of that backend.
    """
    raise NotImplementedError

  # TODO(nednguyen): Remove this method and turn inspector_backend_list API to
  # dictionary-like API (crbug.com/398467)
  def __getitem__(self, index):
    self._Update()
    if index >= len(self._filtered_context_ids):
      raise exceptions.DevtoolsTargetCrashException(
          self.app,
          'Web content with index %s may have crashed. '
          'filtered_context_ids = %s' % (
              index, repr(self._filtered_context_ids)))
    context_id = self._filtered_context_ids[index]
    return self.GetBackendFromContextId(context_id)

  def GetTabById(self, identifier):
    self._Update()
    return self.GetBackendFromContextId(identifier)

  def GetBackendFromContextId(self, context_id):
    self._Update()
    if context_id not in self._wrapper_dict:
      try:
        backend = self._devtools_context_map_backend.GetInspectorBackend(
            context_id)
      except exceptions.Error as e:
        self._HandleDevToolsConnectionError(e)
        raise e
      # Propagate KeyError from GetInspectorBackend call.

      wrapper = self.CreateWrapper(backend)
      self._wrapper_dict[context_id] = wrapper
    return self._wrapper_dict[context_id]

  def IterContextIds(self):
    self._Update()
    return iter(self._filtered_context_ids)

  def __iter__(self):
    self._Update()
    for context_id in self._filtered_context_ids:
      yield self.GetTabById(context_id)

  def __len__(self):
    self._Update()
    return len(self._filtered_context_ids)

  def _Update(self):
    backends_map = self._devtools_client.GetUpdatedInspectableContexts()
    self._devtools_context_map_backend = backends_map

    # Clear context ids that do not appear in the inspectable contexts.
    context_ids = [context['id'] for context in backends_map.contexts]
    self._filtered_context_ids = [context_id
                                  for context_id in self._filtered_context_ids
                                  if context_id in context_ids]
    # Add new context ids.
    for context in backends_map.contexts:
      if (context['id'] not in self._filtered_context_ids and
          self.ShouldIncludeContext(context)):
        self._filtered_context_ids.append(context['id'])

    # Clean up any backends for contexts that have gone away.
    for context_id in self._wrapper_dict.keys():
      if context_id not in self._filtered_context_ids:
        del self._wrapper_dict[context_id]

  def _HandleDevToolsConnectionError(self, error):
    """Called when handling errors in connecting to the DevTools websocket.

    This can be overwritten by sub-classes to add more debugging information to
    errors.
    """
    pass
