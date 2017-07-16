<!-- Copyright 2016 The Chromium Authors. All rights reserved.
     Use of this source code is governed by a BSD-style license that can be
     found in the LICENSE file.
-->

# Devil: Persistent Device List

## What is it?

A persistent device list that stores all expected devices between builds. It
is used by the perf test runner in order to properly shard tests by device
affinity. This is important because the same performance test can yield
meaningfully different results when run on different devices.

## Bots

The list is usually located at one of these locations:

  - `/b/build/site_config/.known_devices`.
  - `~/.android`.

Look at recipes listed below in order to find more up to date location.

## Local Runs

The persistent device list is unnecessary for local runs. It is only used on the
bots that upload data to the perf dashboard.

## Where it is used

The persistent device list is used in performance test recipes via
[api.chromium\_tests.steps.DynamicPerfTests](https://cs.chromium.org/chromium/build/scripts/slave/recipe_modules/chromium_tests/steps.py?q=DynamicPerfTests).
For example, the [android/perf](https://cs.chromium.org/chromium/build/scripts/slave/recipes/android/perf.py) recipe uses it like this:

```python
dynamic_perf_tests = api.chromium_tests.steps.DynamicPerfTests(
    builder['perf_id'], 'android', None,
    known_devices_file=builder.get('known_devices_file', None))
dynamic_perf_tests.run(api, None)
```

