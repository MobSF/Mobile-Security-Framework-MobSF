# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.internal.backends.chrome import cros_browser_backend
from telemetry.internal.browser import browser


class CrOSBrowserWithOOBE(browser.Browser):
  """Cros-specific browser."""
  def __init__(self, backend, platform_backend, credentials_path):
    assert isinstance(backend, cros_browser_backend.CrOSBrowserBackend)
    super(CrOSBrowserWithOOBE, self).__init__(
        backend, platform_backend, credentials_path)

  @property
  def oobe(self):
    """The login webui (also serves as ui for screenlock and
    out-of-box-experience).
    """
    return self._browser_backend.oobe

  @property
  def oobe_exists(self):
    """True if the login/oobe/screenlock webui exists. This is more lightweight
    than accessing the oobe property.
    """
    return self._browser_backend.oobe_exists
