# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import fnmatch
import inspect
import os
import re
import sys

from telemetry.internal.util import camel_case
from telemetry.internal.util import classes as classes_module


def DiscoverModules(start_dir, top_level_dir, pattern='*'):
  """Discover all modules in |start_dir| which match |pattern|.

  Args:
    start_dir: The directory to recursively search.
    top_level_dir: The top level of the package, for importing.
    pattern: Unix shell-style pattern for filtering the filenames to import.

  Returns:
    list of modules.
  """
  # start_dir and top_level_dir must be consistent with each other.
  start_dir = os.path.realpath(start_dir)
  top_level_dir = os.path.realpath(top_level_dir)

  modules = []
  sub_paths = list(os.walk(start_dir))
  # We sort the directories & file paths to ensure a deterministic ordering when
  # traversing |top_level_dir|.
  sub_paths.sort(key=lambda paths_tuple: paths_tuple[0])
  for dir_path, _, filenames in sub_paths:
    # Sort the directories to walk recursively by the directory path.
    filenames.sort()
    for filename in filenames:
      # Filter out unwanted filenames.
      if filename.startswith('.') or filename.startswith('_'):
        continue
      if os.path.splitext(filename)[1] != '.py':
        continue
      if not fnmatch.fnmatch(filename, pattern):
        continue

      # Find the module.
      module_rel_path = os.path.relpath(
          os.path.join(dir_path, filename), top_level_dir)
      module_name = re.sub(r'[/\\]', '.', os.path.splitext(module_rel_path)[0])

      # Import the module.
      try:
        # Make sure that top_level_dir is the first path in the sys.path in case
        # there are naming conflict in module parts.
        original_sys_path = sys.path[:]
        sys.path.insert(0, top_level_dir)
        module = __import__(module_name, fromlist=[True])
        modules.append(module)
      finally:
        sys.path = original_sys_path
  return modules


def AssertNoKeyConflicts(classes_by_key_1, classes_by_key_2):
  for k in classes_by_key_1:
    if k in classes_by_key_2:
      assert classes_by_key_1[k] is classes_by_key_2[k], (
          'Found conflicting classes for the same key: '
          'key=%s, class_1=%s, class_2=%s' % (
              k, classes_by_key_1[k], classes_by_key_2[k]))


# TODO(dtu): Normalize all discoverable classes to have corresponding module
# and class names, then always index by class name.
def DiscoverClasses(start_dir,
                    top_level_dir,
                    base_class,
                    pattern='*',
                    index_by_class_name=True,
                    directly_constructable=False):
  """Discover all classes in |start_dir| which subclass |base_class|.

  Base classes that contain subclasses are ignored by default.

  Args:
    start_dir: The directory to recursively search.
    top_level_dir: The top level of the package, for importing.
    base_class: The base class to search for.
    pattern: Unix shell-style pattern for filtering the filenames to import.
    index_by_class_name: If True, use class name converted to
        lowercase_with_underscores instead of module name in return dict keys.
    directly_constructable: If True, will only return classes that can be
        constructed without arguments

  Returns:
    dict of {module_name: class} or {underscored_class_name: class}
  """
  modules = DiscoverModules(start_dir, top_level_dir, pattern)
  classes = {}
  for module in modules:
    new_classes = DiscoverClassesInModule(
        module, base_class, index_by_class_name, directly_constructable)
    # TODO(nednguyen): we should remove index_by_class_name once
    # benchmark_smoke_unittest in chromium/src/tools/perf no longer relied
    # naming collisions to reduce the number of smoked benchmark tests.
    # crbug.com/548652
    if index_by_class_name:
      AssertNoKeyConflicts(classes, new_classes)
    classes = dict(classes.items() + new_classes.items())
  return classes


# TODO(nednguyen): we should remove index_by_class_name once
# benchmark_smoke_unittest in chromium/src/tools/perf no longer relied
# naming collisions to reduce the number of smoked benchmark tests.
# crbug.com/548652
def DiscoverClassesInModule(module,
                            base_class,
                            index_by_class_name=False,
                            directly_constructable=False):
  """Discover all classes in |module| which subclass |base_class|.

  Base classes that contain subclasses are ignored by default.

  Args:
    module: The module to search.
    base_class: The base class to search for.
    index_by_class_name: If True, use class name converted to
        lowercase_with_underscores instead of module name in return dict keys.

  Returns:
    dict of {module_name: class} or {underscored_class_name: class}
  """
  classes = {}
  for _, obj in inspect.getmembers(module):
    # Ensure object is a class.
    if not inspect.isclass(obj):
      continue
    # Include only subclasses of base_class.
    if not issubclass(obj, base_class):
      continue
    # Exclude the base_class itself.
    if obj is base_class:
      continue
    # Exclude protected or private classes.
    if obj.__name__.startswith('_'):
      continue
    # Include only the module in which the class is defined.
    # If a class is imported by another module, exclude those duplicates.
    if obj.__module__ != module.__name__:
      continue

    if index_by_class_name:
      key_name = camel_case.ToUnderscore(obj.__name__)
    else:
      key_name = module.__name__.split('.')[-1]
    if (not directly_constructable or
        classes_module.IsDirectlyConstructable(obj)):
      if key_name in classes and index_by_class_name:
        assert classes[key_name] is obj, (
          'Duplicate key_name with different objs detected: '
          'key=%s, obj1=%s, obj2=%s' % (key_name, classes[key_name], obj))
      else:
        classes[key_name] = obj

  return classes


_counter = [0]


def _GetUniqueModuleName():
  _counter[0] += 1
  return "module_" + str(_counter[0])
