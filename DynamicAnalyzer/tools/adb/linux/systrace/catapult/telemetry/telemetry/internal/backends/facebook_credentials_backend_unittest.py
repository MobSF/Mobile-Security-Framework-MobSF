# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.internal.backends import facebook_credentials_backend
from telemetry.internal.backends \
       import form_based_credentials_backend_unittest_base


class TestFacebookCredentialsBackend(
    form_based_credentials_backend_unittest_base.
    FormBasedCredentialsBackendUnitTestBase):
  def setUp(self):
    self._credentials_type = 'facebook'

  def testLoginUsingMock(self):
    backend = facebook_credentials_backend.FacebookCredentialsBackend()
    self._LoginUsingMock(backend, backend.url, backend.login_input_id,
                         backend.password_input_id, backend.login_form_id,
                         backend.logged_in_javascript)
