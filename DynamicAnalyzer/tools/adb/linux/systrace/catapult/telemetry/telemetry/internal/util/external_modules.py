# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import importlib

from distutils import version

MODULES = {
  'cv2': (version.StrictVersion('2.4.8'), version.StrictVersion('3.0.0')),
  'numpy': (version.StrictVersion('1.6.1'), None),
  'psutil': (version.StrictVersion('0.5.0'), None),
}

def ImportRequiredModule(module):
  """Tries to import the desired module.

  Returns:
    The module on success, raises error on failure.
  Raises:
    ImportError: The import failed."""
  versions = MODULES.get(module)
  if versions is None:
    raise NotImplementedError('Please teach telemetry about module %s.' %
                              module)
  min_version, max_version = versions

  module = importlib.import_module(module)
  try:
    if ((min_version is not None and
            version.StrictVersion(module.__version__) < min_version) or
        (max_version is not None and
            version.StrictVersion(module.__version__) >= max_version)):
      raise ImportError(('Incorrect {0} version found, expected {1} <= version '
                         '< {2}, found version {3}').format(
          module, min_version, max_version, module.__version__))
  except ValueError as e:
    # This error is raised when a module returns and incorrectly formatted
    # version string. ex. '$build 1456a'
    if 'invalid version number' in str(e):
      raise ImportError(('Incorrectly formatted {0} version found, expected '
                         '{1} <= version < {2}, found version {3}').format(
          module, min_version, max_version, module.__version__))
    else:
      raise
  return module

def ImportOptionalModule(module):
  """Tries to import the desired module.

  Returns:
    The module if successful, None if not."""
  try:
    return ImportRequiredModule(module)
  except ImportError:
    return None
