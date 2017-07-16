# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import logging
import os

from telemetry.core import util
from telemetry.internal.backends import codepen_credentials_backend
from telemetry.internal.backends import facebook_credentials_backend
from telemetry.internal.backends import google_credentials_backend
from telemetry.testing import options_for_unittests


class CredentialsError(Exception):
  """Error that can be thrown when logging in."""


class BrowserCredentials(object):
  def __init__(self, backends=None):
    self._credentials = {}
    self._credentials_path = None
    self._extra_credentials = {}

    if backends is None:
      backends = [
        codepen_credentials_backend.CodePenCredentialsBackend(),
        facebook_credentials_backend.FacebookCredentialsBackend(),
        facebook_credentials_backend.FacebookCredentialsBackend2(),
        google_credentials_backend.GoogleCredentialsBackend(),
        google_credentials_backend.GoogleCredentialsBackend2()]

    self._backends = {}
    for backend in backends:
      self._backends[backend.credentials_type] = backend

  def AddBackend(self, backend):
    assert backend.credentials_type not in self._backends
    self._backends[backend.credentials_type] = backend

  def IsLoggedIn(self, credentials_type):
    if credentials_type not in self._backends:
      raise CredentialsError(
          'Unrecognized credentials type: %s', credentials_type)
    if credentials_type not in self._credentials:
      return False
    return self._backends[credentials_type].IsLoggedIn()

  def CanLogin(self, credentials_type):
    if credentials_type not in self._backends:
      raise CredentialsError(
          'Unrecognized credentials type: %s', credentials_type)
    return credentials_type in self._credentials

  def LoginNeeded(self, tab, credentials_type):
    if credentials_type not in self._backends:
      raise CredentialsError(
          'Unrecognized credentials type: %s', credentials_type)
    if credentials_type not in self._credentials:
      return False
    runner = tab.action_runner
    return self._backends[credentials_type].LoginNeeded(
      tab, runner, self._credentials[credentials_type])

  def LoginNoLongerNeeded(self, tab, credentials_type):
    assert credentials_type in self._backends
    self._backends[credentials_type].LoginNoLongerNeeded(tab)

  @property
  def credentials_path(self):
    return self._credentials_path

  @credentials_path.setter
  def credentials_path(self, credentials_path):
    self._credentials_path = credentials_path
    self._RebuildCredentials()

  def Add(self, credentials_type, data):
    if credentials_type not in self._extra_credentials:
      self._extra_credentials[credentials_type] = {}
    for k, v in data.items():
      assert k not in self._extra_credentials[credentials_type]
      self._extra_credentials[credentials_type][k] = v
    self._RebuildCredentials()

  def _ResetLoggedInState(self):
    """Makes the backends think we're not logged in even though we are.
    Should only be used in unit tests to simulate --dont-override-profile.
    """
    for backend in self._backends.keys():
      # pylint: disable=protected-access
      self._backends[backend]._ResetLoggedInState()

  def _RebuildCredentials(self):
    credentials = {}
    if self._credentials_path == None:
      pass
    elif os.path.exists(self._credentials_path):
      with open(self._credentials_path, 'r') as f:
        credentials = json.loads(f.read())

    # TODO(nduca): use system keychain, if possible.
    homedir_credentials_path = os.path.expanduser('~/.telemetry-credentials')
    homedir_credentials = {}

    if (not options_for_unittests.GetCopy() and
        os.path.exists(homedir_credentials_path)):
      logging.info("Found ~/.telemetry-credentials. Its contents will be used "
                   "when no other credentials can be found.")
      with open(homedir_credentials_path, 'r') as f:
        homedir_credentials = json.loads(f.read())

    self._credentials = {}
    all_keys = set(credentials.keys()).union(
      homedir_credentials.keys()).union(
      self._extra_credentials.keys())

    for k in all_keys:
      if k in credentials:
        self._credentials[k] = credentials[k]
      if k in homedir_credentials:
        logging.info("Will use ~/.telemetry-credentials for %s logins." % k)
        self._credentials[k] = homedir_credentials[k]
      if k in self._extra_credentials:
        self._credentials[k] = self._extra_credentials[k]

  def WarnIfMissingCredentials(self, page):
    if page.credentials and not self.CanLogin(page.credentials):
      files_to_tweak = []
      if page.credentials_path:
        files_to_tweak.append(page.credentials_path)
      files_to_tweak.append('~/.telemetry-credentials')

      example_credentials_file = os.path.join(
          util.GetTelemetryDir(), 'examples', 'credentials_example.json')

      logging.warning("""
        Credentials for %s were not found. page %s will not be tested.

        To fix this, either follow the instructions to authenticate to gsutil
        here:
        http://www.chromium.org/developers/telemetry/upload_to_cloud_storage,

        or add your own credentials to:
            %s
        An example credentials file you can copy from is here:
            %s\n""" % (page.credentials, page, ' or '.join(files_to_tweak),
                       example_credentials_file))
