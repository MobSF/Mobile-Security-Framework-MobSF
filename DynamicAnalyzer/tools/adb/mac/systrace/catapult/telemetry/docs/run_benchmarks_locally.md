<!-- Copyright 2015 The Chromium Authors. All rights reserved.
     Use of this source code is governed by a BSD-style license that can be
     found in the LICENSE file.
-->

# Telemetry: Run Benchmarks Locally

## Set Up

If you don't have a Chromium checkout, download the
[latest Telemetry archive](https://storage.googleapis.com/chromium-telemetry/snapshots/telemetry.zip).
Unzip the archive. If you're running on Mac OS X, you're all set! For
Windows, Linux, Android, or Chrome OS, read on.

#### Windows

Some benchmarks require you to have
[pywin32](http://sourceforge.net/projects/pywin32/files/pywin32/Build%20219/).
Be sure to install a version that matches the version and bitness of the Python
you have installed.

#### Linux

Telemetry on Linux tries to scan for attached Android devices with
[adb](https://developer.android.com/tools/help/adb.html).
The included adb binary is 32-bit. On 64-bit machines, you need to install the
libstdc++6:i386 package.

#### Android

Running on Android is supported with a Linux or Mac OS X host. Windows is not
yet supported. There are also a few additional steps to set up:

  1. Telemetry requires [adb](http://developer.android.com/tools/help/adb.html).
     If you're running from the zip archive, adb is already included. But if
     you're running with a Chromium checkout, ensure your .gclient file contains
     target\_os = ['android'], then resync your code.
  2. If running from an OS X host, you need to run ADB as root. First, you need
     to install a "userdebug" build of Android on your device. Then run adb
     root. Sometimes you may also need to run adb remount.
  3. Enable [debugging over USB](http://developer.android.com/tools/device.html)
     on your device.
  4. You can get the name of your device with `adb devices` and use it with
     Telemetry via --device=<device\_name>.

#### Chrome OS

See [Running Telemetry on Chrome OS](http://www.chromium.org/developers/telemetry/running-telemetry-on-chrome-os).

## Benchmark Commands

Telemetry benchmarks can be run with run\_benchmark.

In the Telemetry zip archive, this is located at `telemetry/run_benchmark`.

In the Chromium source tree, this is located at `src/tools/perf/run_benchmark`.

#### Running a benchmark

List the available benchmarks with `telemetry/run_benchmark list`.

Here's an example for running a particular benchmark:

`telemetry/run_benchmark --browser=canary smoothness.top_25_smooth`

#### Running on another browser

To list available browsers, use:

`telemetry/run_benchmark --browser=list`

For ease of use, you can use default system browsers on desktop:

`telemetry/run_benchmark --browser=system`

and on Android:

`telemetry/run_benchmark --browser=android-system-chrome`

If you're running telemetry from within a Chromium checkout, the release and
debug browsers are what's built in out/Release and out/Debug, respectively.

To run a specific browser executable:

`telemetry/run_benchmark --browser=exact --browser-executable=/path/to/binary`

To run on a Chromebook:

`telemetry/run_benchmark --browser=cros-chrome --remote=[ip_address]`

#### Options

To see all options, run:

`telemetry/run_benchmark run --help`

Use --pageset-repeat to run the test repeatedly. For example:

`telemetry/run_benchmark smoothness.top_25 --pageset-repeat=30`

If you want to re-generate HTML results and add label, you can do this locally
by using the parameters `--reset-results --results-label="foo"`

`telemetry/run_benchmark smoothness.top_25 --reset-results
--results-label="foo"`

####Comparing Two Runs

`telemetry/run_benchmark some_test --browser-executable=path/to/version/1
--reset-results --results-label="Version 1"`

`telemetry/run_benchmark some_test --browser-executable=path/to/version/2
--results-label="Version 2"`

The results will be written to in the `results.html` file in the same location
of the `run_benchmark` script.
