# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import sys

# Since this is an example of telemetry benchmarks in top level telemetry
# folder, we include the top level telemetry dir to sys.path so we can import
# from telemetry directly in the other modules.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
