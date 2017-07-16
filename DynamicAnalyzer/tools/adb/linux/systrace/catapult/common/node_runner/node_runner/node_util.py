# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import subprocess
import sys

import py_utils
from py_utils import binary_manager
from py_utils import dependency_util


def _NodeBinariesConfigPath():
  return os.path.realpath(os.path.join(
      os.path.dirname(os.path.abspath(__file__)), 'node_binaries.json'))


class _NodeManager(object):
  def __init__(self):
    self.bm = binary_manager.BinaryManager(
        [_NodeBinariesConfigPath()])
    self.os_name = dependency_util.GetOSNameForCurrentDesktopPlatform()
    self.arch_name = dependency_util.GetArchForCurrentDesktopPlatform(
        self.os_name)
    self.node_path = self.bm.FetchPath('node', self.os_name, self.arch_name)
    self.npm_path = self.bm.FetchPath('npm', self.os_name, self.arch_name)

    self.node_initialized = False

  def InitNode(self):
    if self.node_initialized:
      return  # So we only init once per run
    self.node_initialized = True
    old_dir = os.path.abspath(os.curdir)
    os.chdir(os.path.join(os.path.abspath(
        py_utils.GetCatapultDir()), 'common', 'node_runner', 'node_runner'))
    subprocess.call([self.node_path, self.npm_path, 'install'])
    os.chdir(old_dir)


_NODE_MANAGER = _NodeManager()


def InitNode():
  _NODE_MANAGER.InitNode()


def GetNodePath():
  return _NODE_MANAGER.node_path


def GetNodeModulesPath():
  _NODE_MANAGER.InitNode()
  path = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                      'node_modules'))
  if sys.platform.startswith('win'):
    # Escape path on Windows because it's very long and must be passed to NTFS.
    path = u'\\\\?\\' + path
  return path
