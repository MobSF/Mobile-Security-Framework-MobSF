# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os


class LocalPathInfo(object):

  def __init__(self, path_priority_groups):
    self._path_priority_groups = self._ParseLocalPaths(path_priority_groups)

  def GetLocalPath(self):
    for priority_group in self._path_priority_groups:
      priority_group = filter(os.path.exists, priority_group)
      if not priority_group:
        continue
      return max(priority_group, key=lambda path: os.stat(path).st_mtime)
    return None

  def IsPathInLocalPaths(self, path):
    return any(
        path in priority_group for priority_group in self._path_priority_groups)

  def Update(self, local_path_info):
    if not local_path_info:
      return
    for priority_group in local_path_info._path_priority_groups:
      group_list = []
      for path in priority_group:
        if not self.IsPathInLocalPaths(path):
          group_list.append(path)
      if group_list:
        self._path_priority_groups.append(group_list)

  @staticmethod
  def _ParseLocalPaths(local_paths):
    if not local_paths:
      return []
    return [[e] if isinstance(e, basestring) else e for e in local_paths]
