# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import os
import subprocess
import sys

from telemetry.core import util


def Run(project_config, args):
  assert '--top-level-dir' not in args, (
      'Top level directory for running tests should be specified through '
      'the instance of telemetry.project_config.ProjectConfig.')
  assert '--client-config' not in args, (
      'Client config file to be used for telemetry should be specified through '
      'the instance of telemetry.project_config.ProjectConfig.')
  assert project_config.top_level_dir, 'Must specify top level dir for project'
  args.extend(['--top-level-dir', project_config.top_level_dir])
  for c in project_config.client_configs:
    args.extend(['--client-config', c])
  for s in project_config.start_dirs:
    args.extend(['--start-dir', s])

  if project_config.default_chrome_root and not '--chrome-root' in args:
    args.extend(['--chrome-root', project_config.default_chrome_root])

  env = os.environ.copy()
  telemetry_dir = util.GetTelemetryDir()
  if 'PYTHONPATH' in env:
    env['PYTHONPATH'] = os.pathsep.join([env['PYTHONPATH'], telemetry_dir])
  else:
    env['PYTHONPATH'] = telemetry_dir

  path_to_run_tests = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                                   'run_browser_tests.py')
  return subprocess.call([sys.executable, path_to_run_tests] + args, env=env)
