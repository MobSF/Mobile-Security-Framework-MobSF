<!-- Copyright 2016 The Chromium Authors. All rights reserved.
     Use of this source code is governed by a BSD-style license that can be
     found in the LICENSE file.
-->

# Devil: Device Blacklist

## What is it?

The device blacklist is a per-run list of devices detected to be in a known bad
state along with the reason they are suspected of being in a bad state (offline,
not responding, etc). It is stored as a json file. This gets reset every run
during the device recovery step (currently part of `bb_device_status_check`).

## Bots

On bots, this is normally found at `//out/bad_devices.json`. If you are having
problems with blacklisted devices locally even though a device is in a good
state, you can safely delete this file.

# Tools for interacting with device black list.

You can interact with the device blacklist via [devil.android.device\_blacklist](https://cs.chromium.org/chromium/src/third_party/catapult/devil/devil/android/device_blacklist.py).
This allows for any interaction you would need with a device blacklist:

  - Reading
  - Writing
  - Extending
  - Resetting

An example usecase of this is:
```python
from devil.android import device_blacklist

blacklist = device_blacklist.Blacklist(blacklist_path)
blacklisted_devices = blacklist.Read()
for device in blacklisted_devices:
  print 'Device %s is blacklisted' % device
blacklist.Reset()
new_blacklist = {'device_id1': {'timestamp': ts, 'reason': reason}}
blacklist.Write(new_blacklist)
blacklist.Extend([device_2, device_3], reason='Reason for blacklisting')
```


## Where it is used.

The blacklist file path is passed directly to the following scripts in chromium:

  - [test\_runner.py](https://cs.chromium.org/chromium/src/build/android/test_runner.py)
  - [provision\_devices.py](https://cs.chromium.org/chromium/src/build/android/provision_devices.py)
  - [bb\_device\_status\_check.py](https://cs.chromium.org/chromium/src/build/android/buildbot/bb_device_status_check.py)

The blacklist is also used in the following scripts:

  - [device\_status.py](https://cs.chromium.org/chromium/src/third_party/catapult/devil/devil/android/tools/device_status.py)
  - [device\_recovery.py](https://cs.chromium.org/chromium/src/third_party/catapult/devil/devil/android/tools/device_recovery.py)


