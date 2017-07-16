# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import collections

from telemetry.internal.backends.chrome_inspector import inspector_backend_list
from telemetry.internal.browser import extension_page


class ExtensionBackendList(inspector_backend_list.InspectorBackendList):
  """A dynamic sequence of extension_page.ExtensionPages."""

  def __init__(self, browser_backend):
    super(ExtensionBackendList, self).__init__(browser_backend)

  def ShouldIncludeContext(self, context):
    return context['url'].startswith('chrome-extension://')

  def CreateWrapper(self, inspector_backend):
    return extension_page.ExtensionPage(inspector_backend)

class ExtensionBackendDict(collections.Mapping):
  """A dynamic mapping of extension_id to extension_page.ExtensionPages."""

  def __init__(self, browser_backend):
    self._extension_backend_list = ExtensionBackendList(browser_backend)

  def __getitem__(self, extension_id):
    extensions = []
    for context_id in self._extension_backend_list.IterContextIds():
      if self.ContextIdToExtensionId(context_id) == extension_id:
        extensions.append(
            self._extension_backend_list.GetBackendFromContextId(context_id))
    if not extensions:
      raise KeyError('Cannot find an extension with id=%s' % extension_id)
    return extensions

  def __iter__(self):
    for context_id in self._extension_backend_list.IterContextIds():
      yield self._extension_backend_list.GetBackendFromContextId(context_id)

  def __len__(self):
    return len(self._extension_backend_list)

  def ContextIdToExtensionId(self, context_id):
    context = self._extension_backend_list.GetContextInfo(context_id)
    return extension_page.UrlToExtensionId(context['url'])
