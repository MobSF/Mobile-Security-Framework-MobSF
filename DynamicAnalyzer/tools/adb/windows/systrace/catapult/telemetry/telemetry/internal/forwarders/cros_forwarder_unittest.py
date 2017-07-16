# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.internal import forwarders
from telemetry.internal.forwarders import cros_forwarder

# pylint: disable=protected-access
class ForwardingArgsTest(unittest.TestCase):
  port_pair = forwarders.PortPair(111, 222)

  def testForwardingArgsReverse(self):
    forwarding_args = cros_forwarder.CrOsSshForwarder._ForwardingArgs(
        use_remote_port_forwarding=True, host_ip='5.5.5.5',
        port_pair=self.port_pair)
    self.assertEqual(['-R222:5.5.5.5:111'], forwarding_args)

  def testForwardingArgs(self):
    forwarding_args = cros_forwarder.CrOsSshForwarder._ForwardingArgs(
        use_remote_port_forwarding=False, host_ip='2.2.2.2',
        port_pair=self.port_pair)
    self.assertEqual(['-L111:2.2.2.2:222'], forwarding_args)
