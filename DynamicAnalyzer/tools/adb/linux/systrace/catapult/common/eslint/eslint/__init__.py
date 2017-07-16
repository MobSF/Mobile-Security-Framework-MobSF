# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import subprocess
import sys


_CATAPULT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    os.path.pardir, os.path.pardir, os.path.pardir)


def _AddToPathIfNeeded(path):
  if path not in sys.path:
    sys.path.insert(0, path)


def _UpdateSysPathIfNeeded():
  _AddToPathIfNeeded(os.path.join(_CATAPULT_PATH, 'common', 'node_runner'))
  _AddToPathIfNeeded(os.path.join(_CATAPULT_PATH, 'common', 'py_utils'))


_UpdateSysPathIfNeeded()


import py_utils
from node_runner import node_util


BASE_ESLINT_CMD = [
  node_util.GetNodePath(),
  os.path.join(node_util.GetNodeModulesPath(), 'eslint', 'bin', 'eslint.js'),
  '--color'
]


DEFAULT_ESLINT_RULES_DIR = os.path.join(
    py_utils.GetCatapultDir(), 'common', 'eslint', 'rules')


def _CreateEslintCommand(rulesdir, extra_args):
  eslint_cmd = BASE_ESLINT_CMD + [
      '--rulesdir', rulesdir, '--ext', '.js,.html'
  ]
  if extra_args:
    eslint_cmd.extend(extra_args.strip().split(' '))
  return eslint_cmd


def RunEslint(paths, rules_dir=DEFAULT_ESLINT_RULES_DIR, extra_args=None):
  """Runs eslint on a list of paths.

  Args:
    paths: A list of paths to run eslint on.
    rules_dir: A directory of custom eslint rules.
    extra_args: A string to append to the end of the eslint command.
  """
  if type(paths) is not list or len(paths) == 0:
    raise ValueError('Must specify a non-empty list of paths to lint.')

  try:
    eslint_cmd = _CreateEslintCommand(rules_dir, extra_args)
    return True, subprocess.check_output(eslint_cmd + paths,
                                         stderr=subprocess.STDOUT).rstrip()
  except subprocess.CalledProcessError as e:
    return False, e.output.rstrip()
