# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import copy
import sets


_global_test_context = None


def GetCopy():
  return copy.deepcopy(_global_test_context)


class TypTestContext(object):
  """ The TestContext that is used for passing data from the main test process
  to typ's subprocesses. Those includes:
     _ client_configs: list of client configs that contain infos about binaries
        to use.
     _ finder_options: the commandline options object. This is an instance of
        telemetry.internal.browser.browser_options.BrowserFinderOptions.
     _ test_class: the name of the test class to be run.
     _ test_case_ids_to_run: the ids of the test cases to be run. e.g:
        foo.bar.Test1, foo.bar.Test2,..


  This object is designed to be pickle-able so that it can be easily pass from
  the main process to test subprocesses. It also supports immutable mode to
  ensure its data won't be changed by the subprocesses.
  """
  def __init__(self):
    self._client_configs = []
    self._finder_options = None
    self._test_class = None
    self._test_cases_ids_to_run = set()
    self._frozen = False

  def Freeze(self):
    """ Makes the |self| object immutable.

    Calling setter on |self|'s property will throw exception.
    """
    assert self._finder_options
    assert self._test_class
    self._frozen = True
    self._test_cases_ids_to_run = sets.ImmutableSet(self._test_cases_ids_to_run)
    self._client_configs = tuple(self._client_configs)

  @property
  def finder_options(self):
    return self._finder_options

  @property
  def client_configs(self):
    return self._client_configs

  @property
  def test_class(self):
    return self._test_class

  @property
  def test_case_ids_to_run(self):
    return self._test_cases_ids_to_run

  @finder_options.setter
  def finder_options(self, value):
    assert not self._frozen
    self._finder_options = value

  @test_class.setter
  def test_class(self, value):
    assert not self._test_class
    self._test_class = value
