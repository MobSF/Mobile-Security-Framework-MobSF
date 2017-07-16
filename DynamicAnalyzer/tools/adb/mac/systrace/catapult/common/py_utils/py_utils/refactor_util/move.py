# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import functools
import os
import sys

from py_utils import refactor


def Run(sources, target, files_to_update):
  """Move modules and update imports.

  Args:
    sources: List of source module or package paths.
    target: Destination module or package path.
    files_to_update: Modules whose imports we should check for changes.
  """
  # TODO(dtu): Support moving classes and functions.
  moves = tuple(_Move(source, target) for source in sources)

  # Update imports and references.
  refactor.Transform(functools.partial(_Update, moves), files_to_update)

  # Move files.
  for move in moves:
    os.rename(move.source_path, move.target_path)


def _Update(moves, module):
  for import_statement in module.FindAll(refactor.Import):
    for move in moves:
      try:
        if move.UpdateImportAndReferences(module, import_statement):
          break
      except NotImplementedError as e:
        print >> sys.stderr, 'Error updating %s: %s' % (module.file_path, e)


class _Move(object):

  def __init__(self, source, target):
    self._source_path = os.path.realpath(source)
    self._target_path = os.path.realpath(target)

    if os.path.isdir(self._target_path):
      self._target_path = os.path.join(
          self._target_path, os.path.basename(self._source_path))

  @property
  def source_path(self):
    return self._source_path

  @property
  def target_path(self):
    return self._target_path

  @property
  def source_module_path(self):
    return _ModulePath(self._source_path)

  @property
  def target_module_path(self):
    return _ModulePath(self._target_path)

  def UpdateImportAndReferences(self, module, import_statement):
    """Update an import statement in a module and all its references..

    Args:
      module: The refactor.Module to update.
      import_statement:  The refactor.Import to update.

    Returns:
      True if the import statement was updated, or False if the import statement
      needed no updating.
    """
    statement_path_parts = import_statement.path.split('.')
    source_path_parts = self.source_module_path.split('.')
    if source_path_parts != statement_path_parts[:len(source_path_parts)]:
      return False

    # Update import statement.
    old_name_parts = import_statement.name.split('.')
    new_name_parts = ([self.target_module_path] +
                      statement_path_parts[len(source_path_parts):])
    import_statement.path = '.'.join(new_name_parts)
    new_name = import_statement.name

    # Update references.
    for reference in module.FindAll(refactor.Reference):
      reference_parts = reference.value.split('.')
      if old_name_parts != reference_parts[:len(old_name_parts)]:
        continue

      new_reference_parts = [new_name] + reference_parts[len(old_name_parts):]
      reference.value = '.'.join(new_reference_parts)

    return True


def _BaseDir(module_path):
  if not os.path.isdir(module_path):
    module_path = os.path.dirname(module_path)

  while '__init__.py' in os.listdir(module_path):
    module_path = os.path.dirname(module_path)

  return module_path


def _ModulePath(module_path):
  if os.path.split(module_path)[1] == '__init__.py':
    module_path = os.path.dirname(module_path)
  rel_path = os.path.relpath(module_path, _BaseDir(module_path))
  return os.path.splitext(rel_path)[0].replace(os.sep, '.')
