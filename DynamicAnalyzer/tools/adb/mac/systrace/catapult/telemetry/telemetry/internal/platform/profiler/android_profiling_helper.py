# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import glob
import hashlib
import logging
import os
import platform
import re
import shutil
import subprocess

from telemetry.internal.util import binary_manager
from telemetry.core import platform as telemetry_platform
from telemetry.core import util
from telemetry import decorators
from telemetry.internal.platform.profiler import android_prebuilt_profiler_helper

from devil.android import md5sum  # pylint: disable=import-error


try:
  import sqlite3
except ImportError:
  sqlite3 = None



_TEXT_SECTION = '.text'


def _ElfMachineId(elf_file):
  headers = subprocess.check_output(['readelf', '-h', elf_file])
  return re.match(r'.*Machine:\s+(\w+)', headers, re.DOTALL).group(1)


def _ElfSectionAsString(elf_file, section):
  return subprocess.check_output(['readelf', '-p', section, elf_file])


def _ElfSectionMd5Sum(elf_file, section):
  result = subprocess.check_output(
      'readelf -p%s "%s" | md5sum' % (section, elf_file), shell=True)
  return result.split(' ', 1)[0]


def _FindMatchingUnstrippedLibraryOnHost(device, lib):
  lib_base = os.path.basename(lib)

  device_md5sums = md5sum.CalculateDeviceMd5Sums([lib], device)
  if lib not in device_md5sums:
    return None

  device_md5 = device_md5sums[lib]

  def FindMatchingStrippedLibrary(out_path):
    # First find a matching stripped library on the host. This avoids the need
    # to pull the stripped library from the device, which can take tens of
    # seconds.
    # Check the GN stripped lib path first, and the GYP ones afterwards.
    host_lib_path = os.path.join(out_path, lib_base)
    host_lib_pattern = os.path.join(out_path, '*_apk', 'libs', '*', lib_base)
    for stripped_host_lib in [host_lib_path] + glob.glob(host_lib_pattern):
      if os.path.exists(stripped_host_lib):
        with open(stripped_host_lib) as f:
          host_md5 = hashlib.md5(f.read()).hexdigest()
          if host_md5 == device_md5:
            return stripped_host_lib
    return None

  out_path = None
  stripped_host_lib = None
  for out_path in util.GetBuildDirectories():
    stripped_host_lib = FindMatchingStrippedLibrary(out_path)
    if stripped_host_lib:
      break

  if not stripped_host_lib:
    return None

  # The corresponding unstripped library will be under lib.unstripped for GN, or
  # lib for GYP.
  unstripped_host_lib_paths = [
      os.path.join(out_path, 'lib.unstripped', lib_base),
      os.path.join(out_path, 'lib', lib_base)
  ]
  unstripped_host_lib = next(
      (lib for lib in unstripped_host_lib_paths if os.path.exists(lib)), None)
  if unstripped_host_lib is None:
    return None

  # Make sure the unstripped library matches the stripped one. We do this
  # by comparing the hashes of text sections in both libraries. This isn't an
  # exact guarantee, but should still give reasonable confidence that the
  # libraries are compatible.
  # TODO(skyostil): Check .note.gnu.build-id instead once we're using
  # --build-id=sha1.
  # pylint: disable=undefined-loop-variable
  if (_ElfSectionMd5Sum(unstripped_host_lib, _TEXT_SECTION) !=
      _ElfSectionMd5Sum(stripped_host_lib, _TEXT_SECTION)):
    return None
  return unstripped_host_lib


@decorators.Cache
def GetPerfhostName():
  return 'perfhost_' + telemetry_platform.GetHostPlatform().GetOSVersionName()


# Ignored directories for libraries that aren't useful for symbolization.
_IGNORED_LIB_PATHS = [
  '/data/dalvik-cache',
  '/tmp'
]


def GetRequiredLibrariesForPerfProfile(profile_file):
  """Returns the set of libraries necessary to symbolize a given perf profile.

  Args:
    profile_file: Path to perf profile to analyse.

  Returns:
    A set of required library file names.
  """
  with open(os.devnull, 'w') as dev_null:
    perfhost_path = binary_manager.FetchPath(
        GetPerfhostName(), 'x86_64', 'linux')
    perf = subprocess.Popen([perfhost_path, 'script', '-i', profile_file],
                             stdout=dev_null, stderr=subprocess.PIPE)
    _, output = perf.communicate()
  missing_lib_re = re.compile(
      ('^Failed to open (.*), continuing without symbols|'
       '^(.*[.]so).*not found, continuing without symbols'))
  libs = set()
  for line in output.split('\n'):
    lib = missing_lib_re.match(line)
    if lib:
      lib = lib.group(1) or lib.group(2)
      path = os.path.dirname(lib)
      if (any(path.startswith(ignored_path)
              for ignored_path in _IGNORED_LIB_PATHS)
          or path == '/' or not path):
        continue
      libs.add(lib)
  return libs


def GetRequiredLibrariesForVTuneProfile(profile_file):
  """Returns the set of libraries necessary to symbolize a given VTune profile.

  Args:
    profile_file: Path to VTune profile to analyse.

  Returns:
    A set of required library file names.
  """
  db_file = os.path.join(profile_file, 'sqlite-db', 'dicer.db')
  conn = sqlite3.connect(db_file)

  try:
    # The 'dd_module_file' table lists all libraries on the device. Only the
    # ones with 'bin_located_path' are needed for the profile.
    query = 'SELECT bin_path, bin_located_path FROM dd_module_file'
    return set(row[0] for row in conn.cursor().execute(query) if row[1])
  finally:
    conn.close()


def _FileMetadataMatches(filea, fileb):
  """Check if the metadata of two files matches."""
  assert os.path.exists(filea)
  if not os.path.exists(fileb):
    return False

  fields_to_compare = [
      'st_ctime', 'st_gid', 'st_mode', 'st_mtime', 'st_size', 'st_uid']

  filea_stat = os.stat(filea)
  fileb_stat = os.stat(fileb)
  for field in fields_to_compare:
    # shutil.copy2 doesn't get ctime/mtime identical when the file system
    # provides sub-second accuracy.
    if int(getattr(filea_stat, field)) != int(getattr(fileb_stat, field)):
      return False
  return True


def CreateSymFs(device, symfs_dir, libraries, use_symlinks=True):
  """Creates a symfs directory to be used for symbolizing profiles.

  Prepares a set of files ("symfs") to be used with profilers such as perf for
  converting binary addresses into human readable function names.

  Args:
    device: DeviceUtils instance identifying the target device.
    symfs_dir: Path where the symfs should be created.
    libraries: Set of library file names that should be included in the symfs.
    use_symlinks: If True, link instead of copy unstripped libraries into the
      symfs. This will speed up the operation, but the resulting symfs will no
      longer be valid if the linked files are modified, e.g., by rebuilding.

  Returns:
    The absolute path to the kernel symbols within the created symfs.
  """
  logging.info('Building symfs into %s.' % symfs_dir)

  for lib in libraries:
    device_dir = os.path.dirname(lib)
    output_dir = os.path.join(symfs_dir, device_dir[1:])
    if not os.path.exists(output_dir):
      os.makedirs(output_dir)
    output_lib = os.path.join(output_dir, os.path.basename(lib))

    if lib.startswith('/data/app'):
      # If this is our own library instead of a system one, look for a matching
      # unstripped library under the out directory.
      unstripped_host_lib = _FindMatchingUnstrippedLibraryOnHost(device, lib)
      if not unstripped_host_lib:
        logging.warning('Could not find symbols for %s.' % lib)
        logging.warning('Is the correct output directory selected '
                        '(CHROMIUM_OUTPUT_DIR)? Did you install the APK after '
                        'building?')
        continue
      if use_symlinks:
        if os.path.lexists(output_lib):
          os.remove(output_lib)
        os.symlink(os.path.abspath(unstripped_host_lib), output_lib)
      # Copy the unstripped library only if it has been changed to avoid the
      # delay.
      elif not _FileMetadataMatches(unstripped_host_lib, output_lib):
        logging.info('Copying %s to %s' % (unstripped_host_lib, output_lib))
        shutil.copy2(unstripped_host_lib, output_lib)
    else:
      # Otherwise save a copy of the stripped system library under the symfs so
      # the profiler can at least use the public symbols of that library. To
      # speed things up, only pull files that don't match copies we already
      # have in the symfs.
      if not os.path.exists(output_lib):
        pull = True
      else:
        host_md5sums = md5sum.CalculateHostMd5Sums([output_lib])
        device_md5sums = md5sum.CalculateDeviceMd5Sums([lib], device)

        pull = True
        if host_md5sums and device_md5sums and output_lib in host_md5sums \
          and lib in device_md5sums:
          pull = host_md5sums[output_lib] != device_md5sums[lib]

      if pull:
        logging.info('Pulling %s to %s', lib, output_lib)
        device.PullFile(lib, output_lib)

  # Also pull a copy of the kernel symbols.
  output_kallsyms = os.path.join(symfs_dir, 'kallsyms')
  if not os.path.exists(output_kallsyms):
    device.PullFile('/proc/kallsyms', output_kallsyms)
  return output_kallsyms


def PrepareDeviceForPerf(device):
  """Set up a device for running perf.

  Args:
    device: DeviceUtils instance identifying the target device.

  Returns:
    The path to the installed perf binary on the device.
  """
  android_prebuilt_profiler_helper.InstallOnDevice(device, 'perf')
  # Make sure kernel pointers are not hidden.
  device.WriteFile('/proc/sys/kernel/kptr_restrict', '0', as_root=True)
  return android_prebuilt_profiler_helper.GetDevicePath('perf')


def GetToolchainBinaryPath(library_file, binary_name):
  """Return the path to an Android toolchain binary on the host.

  Args:
    library_file: ELF library which is used to identify the used ABI,
        architecture and toolchain.
    binary_name: Binary to search for, e.g., 'objdump'
  Returns:
    Full path to binary or None if the binary was not found.
  """
  # Mapping from ELF machine identifiers to GNU toolchain names.
  toolchain_configs = {
    'x86': 'i686-linux-android',
    'MIPS': 'mipsel-linux-android',
    'ARM': 'arm-linux-androideabi',
    'x86-64': 'x86_64-linux-android',
    'AArch64': 'aarch64-linux-android',
  }
  toolchain_config = toolchain_configs[_ElfMachineId(library_file)]
  host_os = platform.uname()[0].lower()
  host_machine = platform.uname()[4]

  elf_comment = _ElfSectionAsString(library_file, '.comment')
  toolchain_version = re.match(r'.*GCC: \(GNU\) ([\w.]+)',
                               elf_comment, re.DOTALL)
  if not toolchain_version:
    return None
  toolchain_version = toolchain_version.group(1)
  toolchain_version = toolchain_version.replace('.x', '')

  toolchain_path = os.path.abspath(os.path.join(
      util.GetChromiumSrcDir(), 'third_party', 'android_tools', 'ndk',
      'toolchains', '%s-%s' % (toolchain_config, toolchain_version)))
  if not os.path.exists(toolchain_path):
    logging.warning(
        'Unable to find toolchain binary %s: toolchain not found at %s',
        binary_name, toolchain_path)
    return None

  path = os.path.join(
      toolchain_path, 'prebuilt', '%s-%s' % (host_os, host_machine), 'bin',
      '%s-%s' % (toolchain_config, binary_name))
  if not os.path.exists(path):
    logging.warning(
        'Unable to find toolchain binary %s: binary not found at %s',
        binary_name, path)
    return None

  return path
