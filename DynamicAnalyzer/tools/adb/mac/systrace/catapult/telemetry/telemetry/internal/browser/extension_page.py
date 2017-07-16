# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import re

from telemetry.internal.browser import web_contents


def UrlToExtensionId(url):
  return re.match(r"(chrome-extension://)([^/]+)", url).group(2)


class ExtensionPage(web_contents.WebContents):
  """Represents an extension page in the browser"""

  def __init__(self, inspector_backend):
    super(ExtensionPage, self).__init__(inspector_backend)
    self.url = inspector_backend.url
    self.extension_id = UrlToExtensionId(self.url)

  def Reload(self):
    """Reloading an extension page is used as a workaround for an extension
    binding bug for old versions of Chrome (crbug.com/263162). After Navigate
    returns, we are guaranteed that the inspected page is in the correct state.
    """
    self._inspector_backend.Navigate(self.url, None, 10)
