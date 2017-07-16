#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import os
import sys

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__),
                                 '..', '..', '..', 'dependency_manager')))
from dependency_manager import base_config # pylint: disable=import-error


_SUPPORTED_ARCHS = [
    'linux2_x86_64', 'darwin_x86_64', 'win_AMD64', 'win32_AMD64', 'win32_x86',
    'default'
]
_DEFAULT_DEP = 'battor_agent_binary'
_DEFAULT_CONFIG = os.path.join(os.path.dirname(__file__), '..', 'battor',
                               'battor_binary_dependencies.json')


def UploadBinary(arch, path, config, dep):
  print 'Uploading binary:'
  print '  arch: %s' % arch
  print '  path: %s' % path
  print '  config: %s' % config
  print '  dep: %s' % dep
  c = base_config.BaseConfig(config, writable=True)
  c.AddCloudStorageDependencyUpdateJob(
      dep, arch, path, version=None, execute_job=True)
  print 'Upload complete.'


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--arch', '--architecture', required=True,
                      help='Architecture binary is built for.')
  parser.add_argument('--path', required=True, help='Path to binary.')
  parser.add_argument('--config', default=_DEFAULT_CONFIG,
                      help='Path to dependency manager config')
  parser.add_argument('--dep', default=_DEFAULT_DEP,
                      help='Name of dependency to update.')
  args = parser.parse_args()
  if args.arch not in _SUPPORTED_ARCHS:
    print 'Arch must be one of: %s' % _SUPPORTED_ARCHS
    return 1
  UploadBinary(args.arch, args.path, args.config, args.dep)
  return 0

if __name__ == '__main__':
  sys.exit(main())
