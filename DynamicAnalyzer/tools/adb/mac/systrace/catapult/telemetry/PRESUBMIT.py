# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


def _CommonChecks(input_api, output_api):
  results = []

  results += input_api.RunTests(input_api.canned_checks.GetPylint(
      input_api, output_api, extra_paths_list=_GetPathsToPrepend(input_api),
      pylintrc='pylintrc'))
  results += _CheckNoMoreUsageOfDeprecatedCode(
      input_api, output_api, deprecated_code='GetChromiumSrcDir()',
      crbug_number=511332)
  return results


def _RunArgs(args, input_api):
  p = input_api.subprocess.Popen(args, stdout=input_api.subprocess.PIPE,
                                 stderr=input_api.subprocess.STDOUT)
  out, _ = p.communicate()
  return (out, p.returncode)


def _ValidateDependenciesFile(input_api, output_api, dependencies_path):
  """ Check that binary_dependencies.json has valid format and content.

  This check should only be done in CheckChangeOnUpload() only since it invokes
  network I/O.
  """
  results = []
  telemetry_dir = input_api.PresubmitLocalPath()
  for f in input_api.AffectedFiles():
    if not f.AbsoluteLocalPath() == dependencies_path:
      continue
    out, return_code = _RunArgs([
        input_api.python_executable,
        input_api.os_path.join(telemetry_dir, 'json_format'),
        dependencies_path], input_api)
    if return_code:
      results.append(output_api.PresubmitError(
           'Validating %s failed:' % dependencies_path, long_text=out))
      break
    out, return_code = _RunArgs([
        input_api.python_executable,
        input_api.os_path.join(telemetry_dir, 'validate_binary_dependencies'),
        dependencies_path], input_api)
    if return_code:
      results.append(output_api.PresubmitError(
          'Validating %s failed:' % dependencies_path, long_text=out))
      break
  return results


def _CheckNoMoreUsageOfDeprecatedCode(
    input_api, output_api, deprecated_code, crbug_number):
  results = []
  # These checks are not perfcet but should be good enough for most of our
  # usecases.
  def _IsAddedLine(line):
    return line.startswith('+') and not line.startswith('+++ ')
  def _IsRemovedLine(line):
    return line.startswith('-') and not line.startswith('--- ')

  presubmit_dir = input_api.os_path.join(
      input_api.PresubmitLocalPath(), 'PRESUBMIT.py')

  added_calls = 0
  removed_calls = 0
  for affected_file in input_api.AffectedFiles():
    # Do not do the check on PRESUBMIT.py itself.
    if affected_file.AbsoluteLocalPath() == presubmit_dir:
      continue
    for line in affected_file.GenerateScmDiff().splitlines():
      if _IsAddedLine(line) and deprecated_code in line:
        added_calls += 1
      elif _IsRemovedLine(line) and deprecated_code in line:
        removed_calls += 1

  if added_calls > removed_calls:
    results.append(output_api.PresubmitError(
        'Your patch adds more instances of %s. Please see crbug.com/%i for'
        'how to proceed.' % (deprecated_code, crbug_number)))
  return results


def _GetPathsToPrepend(input_api):
  telemetry_dir = input_api.PresubmitLocalPath()
  catapult_dir = input_api.os_path.join(telemetry_dir, '..')
  return [
      telemetry_dir,

      input_api.os_path.join(telemetry_dir, 'third_party', 'altgraph'),
      input_api.os_path.join(telemetry_dir, 'third_party', 'modulegraph'),
      input_api.os_path.join(telemetry_dir, 'third_party', 'pexpect'),
      input_api.os_path.join(telemetry_dir, 'third_party', 'png'),
      input_api.os_path.join(telemetry_dir, 'third_party', 'web-page-replay'),
      input_api.os_path.join(telemetry_dir, 'third_party', 'websocket-client'),

      input_api.os_path.join(catapult_dir, 'common', 'py_utils'),
      input_api.os_path.join(catapult_dir, 'dependency_manager'),
      input_api.os_path.join(catapult_dir, 'devil'),
      input_api.os_path.join(catapult_dir, 'systrace'),
      input_api.os_path.join(catapult_dir, 'tracing'),
      input_api.os_path.join(catapult_dir, 'common', 'battor'),
      input_api.os_path.join(catapult_dir, 'common', 'py_trace_event'),

      input_api.os_path.join(catapult_dir, 'third_party', 'mock'),
      input_api.os_path.join(catapult_dir, 'third_party', 'pyfakefs'),
      input_api.os_path.join(catapult_dir, 'third_party', 'pyserial'),
      input_api.os_path.join(catapult_dir, 'third_party', 'typ'),
  ]


def _ValidateAllDependenciesFiles(input_api, output_api):
  results = []
  telemetry_dir = input_api.PresubmitLocalPath()
  binary_dependencies = input_api.os_path.join(
      telemetry_dir, 'telemetry', 'internal', 'binary_dependencies.json')
  telemetry_unittest_dependencies = input_api.os_path.join(
      telemetry_dir, 'telemetry', 'telemetry_unittest_deps.json')
  for path in [binary_dependencies, telemetry_unittest_dependencies]:
    results += _ValidateDependenciesFile(input_api, output_api, path)
  return results


def CheckChangeOnUpload(input_api, output_api):
  results = []
  results += _CommonChecks(input_api, output_api)
  results += _ValidateAllDependenciesFiles(input_api, output_api)
  return results


def CheckChangeOnCommit(input_api, output_api):
  results = []
  results += _CommonChecks(input_api, output_api)
  return results
