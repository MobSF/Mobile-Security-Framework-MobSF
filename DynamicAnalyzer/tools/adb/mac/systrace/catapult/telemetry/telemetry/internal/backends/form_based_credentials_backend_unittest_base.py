# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.testing import simple_mock

_ = simple_mock.DONT_CARE


class FormBasedCredentialsBackendUnitTestBase(unittest.TestCase):
  def setUp(self):
    self._credentials_type = None

  def testLoginUsingMock(self):
    raise NotImplementedError()

  def _LoginUsingMock(self, backend, login_page_url, email_element_id,
                      password_element_id, form_element_id,
                      already_logged_in_js): # pylint: disable=no-self-use
    del form_element_id  # Unused.
    del email_element_id  # Unused.
    del password_element_id  # Unused.
    tab = simple_mock.MockObject()
    ar = simple_mock.MockObject()

    config = {'username': 'blah',
              'password': 'blargh'}

    tab.ExpectCall('Navigate', login_page_url)
    tab.ExpectCall(
        'EvaluateJavaScript', already_logged_in_js).WillReturn(False)
    tab.ExpectCall('WaitForDocumentReadyStateToBeInteractiveOrBetter')

    ar.ExpectCall(
        'WaitForJavaScriptCondition',
        '(document.querySelector({{ form_id }}) !== null) || ({{ @code }})')
    ar.ExpectCall('WaitForNavigate')

    def VerifyEmail(js):
      assert '{{ selector }}' in js
      assert '{{ username }}' in js
    tab.ExpectCall('ExecuteJavaScript', _).WhenCalled(VerifyEmail)

    def VerifyPw(js):
      assert '{{ selector }}' in js
      assert '{{ password }}' in js
    tab.ExpectCall('ExecuteJavaScript', _).WhenCalled(VerifyPw)

    def VerifySubmit(js):
      assert '.submit' in js or '.click' in js
    tab.ExpectCall('ExecuteJavaScript', _).WhenCalled(VerifySubmit)

    # Checking for form still up.
    tab.ExpectCall('EvaluateJavaScript', _).WillReturn(False)

    backend.LoginNeeded(tab, ar, config)
