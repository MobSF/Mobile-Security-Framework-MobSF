#!/bin/bash
# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This is a script meant to be run by a bot to periodically release new versions
# of the telemetry harness. It needs to be run from one level above src/ (such
# as build/).

src/tools/perf/find_dependencies \
  src/tools/perf/run_benchmark \
  src/tools/perf/record_wpr \
  src/content/test/gpu/run_gpu_test.py \
  --exclude=*/third_party/catapult/test_data/* \
  -z $1
