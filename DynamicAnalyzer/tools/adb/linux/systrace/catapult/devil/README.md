<!-- Copyright 2015 The Chromium Authors. All rights reserved.
     Use of this source code is governed by a BSD-style license that can be
     found in the LICENSE file.
-->
## devil

😈

devil is a library used by the Chromium developers to interact with Android
devices. It currently supports SDK level 16 and above.

## Interfaces

devil provides python APIs:
  - [`devil.android.adb_wrapper`](docs/adb_wrapper.md) provides a thin wrapper
    around the adb binary. Most functions and methods have direct analogues on
    the adb command-line.
  - [`devil.android.device_utils`](docs/device_utils.md) provides higher-level
    functionality built on top of `adb_wrapper`. **This is the primary
    mechanism through which chromium's scripts interact with devices.**

## Utilities

devil also provides command-line utilities:
 - [`devil/utils/markdown.py`](docs/markdown.md) generated markdown
   documentation for python modules.

## Constraints and Caveats

devil is used with python 2.7. Its compatibility with python 3 has not been
tested, and neither achieving nor maintaining said compatibility is currently
a priority.

## Contributing

Please see the [contributor's guide](https://github.com/catapult-project/catapult/blob/master/CONTRIBUTING.md).

