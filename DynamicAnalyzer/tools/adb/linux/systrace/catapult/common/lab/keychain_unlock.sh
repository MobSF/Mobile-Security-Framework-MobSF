#!/bin/sh
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Script to SSH into a list of bots and set up their keychains for Telemetry.
# https://www.chromium.org/developers/telemetry/telemetry-mac-keychain-setup

for hostname in "$@"
do
  ssh -t "$hostname" 'security unlock-keychain login.keychain
security delete-generic-password -s "Chrome Safe Storage" login.keychain
security add-generic-password -a Chrome -w "+NTclOvR4wLMgRlLIL9bHQ==" \
  -s "Chrome Safe Storage" -A login.keychain'
done
