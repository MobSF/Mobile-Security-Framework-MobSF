# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.internal.backends import form_based_credentials_backend


class CodePenCredentialsBackend(
    form_based_credentials_backend.FormBasedCredentialsBackend):

  @property
  def logged_in_javascript(self):
    """Evaluates to true iff already logged in."""
    return 'document.querySelector(".login-area") === null'

  @property
  def credentials_type(self):
    return 'codepen'

  @property
  def url(self):
    return 'https://codepen.io/login'

  @property
  def login_form_id(self):
    return 'login-login-form'

  @property
  def login_button_javascript(self):
    return """
        LoginSettings.timeOnPageStartTime = 0;
        document.getElementById("log-in-button").click();
        """

  @property
  def login_input_id(self):
    return 'login-email-field'

  @property
  def password_input_id(self):
    return 'login-password-field_'
