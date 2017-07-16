#!/usr/bin/env python
# Copyright 2011 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit tests for platformsettings.

Usage:
$ ./platformsettings_test.py
"""

import unittest

import platformsettings

WINDOWS_7_IP = '172.11.25.170'
WINDOWS_7_MAC = '00-1A-44-DA-88-C0'
WINDOWS_7_IPCONFIG = """
Windows IP Configuration

   Host Name . . . . . . . . . . . . : THEHOST1-W
   Primary Dns Suffix  . . . . . . . : something.example.com
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : example.com
                                       another.example.com

Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : somethingexample.com
   Description . . . . . . . . . . . : Int PRO/1000 MT Network Connection
   Physical Address. . . . . . . . . : %(mac_addr)s
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   IPv6 Address. . . . . . . . . . . : 1234:0:1000:1200:839f:d256:3a6c:210(Preferred)
   Temporary IPv6 Address. . . . . . : 2143:0:2100:1800:38f9:2d65:a3c6:120(Preferred)
   Link-local IPv6 Address . . . . . : abcd::1234:1a33:b2cc:238%%18(Preferred)
   IPv4 Address. . . . . . . . . . . : %(ip_addr)s(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.248.0
   Lease Obtained. . . . . . . . . . : Thursday, April 28, 2011 9:40:22 PM
   Lease Expires . . . . . . . . . . : Tuesday, May 10, 2011 12:15:48 PM
   Default Gateway . . . . . . . . . : abcd::2:37ee:ef70:56%%18
                                       172.11.25.254
   DHCP Server . . . . . . . . . . . : 172.11.22.33
   DNS Servers . . . . . . . . . . . : 8.8.4.4
   NetBIOS over Tcpip. . . . . . . . : Enabled
""" % {'ip_addr': WINDOWS_7_IP, 'mac_addr': WINDOWS_7_MAC}

WINDOWS_XP_IP = '172.1.2.3'
WINDOWS_XP_MAC = '00-34-B8-1F-FA-70'
WINDOWS_XP_IPCONFIG = """
Windows IP Configuration

        Host Name . . . . . . . . . . . . : HOSTY-0
        Primary Dns Suffix  . . . . . . . :
        Node Type . . . . . . . . . . . . : Unknown
        IP Routing Enabled. . . . . . . . : No
        WINS Proxy Enabled. . . . . . . . : No
        DNS Suffix Search List. . . . . . : example.com

Ethernet adapter Local Area Connection 2:

        Connection-specific DNS Suffix  . : example.com
        Description . . . . . . . . . . . : Int Adapter (PILA8470B)
        Physical Address. . . . . . . . . : %(mac_addr)s
        Dhcp Enabled. . . . . . . . . . . : Yes
        Autoconfiguration Enabled . . . . : Yes
        IP Address. . . . . . . . . . . . : %(ip_addr)s
        Subnet Mask . . . . . . . . . . . : 255.255.254.0
        Default Gateway . . . . . . . . . : 172.1.2.254
        DHCP Server . . . . . . . . . . . : 172.1.3.241
        DNS Servers . . . . . . . . . . . : 172.1.3.241
                                            8.8.8.8
                                            8.8.4.4
        Lease Obtained. . . . . . . . . . : Thursday, April 07, 2011 9:14:55 AM
        Lease Expires . . . . . . . . . . : Thursday, April 07, 2011 1:14:55 PM
""" % {'ip_addr': WINDOWS_XP_IP, 'mac_addr': WINDOWS_XP_MAC}


# scutil show State:/Network/Global/IPv4
OSX_IPV4_STATE = """
<dictionary> {
  PrimaryInterface : en1
  PrimaryService : 8824452C-FED4-4C09-9256-40FB146739E0
  Router : 192.168.1.1
}
"""

# scutil show State:/Network/Service/[PRIMARY_SERVICE_KEY]/DNS
OSX_DNS_STATE_LION = """
<dictionary> {
  DomainName : mtv.corp.google.com
  SearchDomains : <array> {
    0 : mtv.corp.google.com
    1 : corp.google.com
    2 : prod.google.com
    3 : prodz.google.com
    4 : google.com
  }
  ServerAddresses : <array> {
    0 : 172.72.255.1
    1 : 172.49.117.57
    2 : 172.54.116.57
  }
}
"""

OSX_DNS_STATE_SNOW_LEOPARD = """
<dictionary> {
  ServerAddresses : <array> {
    0 : 172.27.1.1
    1 : 172.94.117.57
    2 : 172.45.116.57
  }
  DomainName : mtv.corp.google.com
  SearchDomains : <array> {
    0 : mtv.corp.google.com
    1 : corp.google.com
    2 : prod.google.com
    3 : prodz.google.com
    4 : google.com
  }
}
"""


class SystemProxyTest(unittest.TestCase):

  def test_basic(self):
    system_proxy = platformsettings.SystemProxy(None, None)
    self.assertEqual(None, system_proxy.host)
    self.assertEqual(None, system_proxy.port)
    self.assertFalse(system_proxy)

  def test_from_url_empty(self):
    system_proxy = platformsettings.SystemProxy.from_url('')
    self.assertEqual(None, system_proxy.host)
    self.assertEqual(None, system_proxy.port)
    self.assertFalse(system_proxy)

  def test_from_url_basic(self):
    system_proxy = platformsettings.SystemProxy.from_url('http://pxy.com:8888/')
    self.assertEqual('pxy.com', system_proxy.host)
    self.assertEqual(8888, system_proxy.port)
    self.assertTrue(system_proxy)

  def test_from_url_no_port(self):
    system_proxy = platformsettings.SystemProxy.from_url('http://pxy.com/')
    self.assertEqual('pxy.com', system_proxy.host)
    self.assertEqual(None, system_proxy.port)
    self.assertTrue(system_proxy)

  def test_from_url_empty_string(self):
    system_proxy = platformsettings.SystemProxy.from_url('')
    self.assertEqual(None, system_proxy.host)
    self.assertEqual(None, system_proxy.port)
    self.assertFalse(system_proxy)

  def test_from_url_bad_string(self):
    system_proxy = platformsettings.SystemProxy.from_url('foo:80')
    self.assertEqual(None, system_proxy.host)
    self.assertEqual(None, system_proxy.port)
    self.assertFalse(system_proxy)


class HasSniTest(unittest.TestCase):
  def test_has_sni(self):
    # Check that no exception is raised.
    platformsettings.HasSniSupport()


# pylint: disable=abstract-method
class Win7Settings(platformsettings._WindowsPlatformSettings):
  @classmethod
  def _ipconfig(cls, *args):
    if args == ('/all',):
      return WINDOWS_7_IPCONFIG
    raise RuntimeError

class WinXpSettings(platformsettings._WindowsPlatformSettings):
  @classmethod
  def _ipconfig(cls, *args):
    if args == ('/all',):
      return WINDOWS_XP_IPCONFIG
    raise RuntimeError


class WindowsPlatformSettingsTest(unittest.TestCase):
  def test_get_mac_address_xp(self):
    self.assertEqual(WINDOWS_XP_MAC,
                     WinXpSettings()._get_mac_address(WINDOWS_XP_IP))

  def test_get_mac_address_7(self):
    self.assertEqual(WINDOWS_7_MAC,
                     Win7Settings()._get_mac_address(WINDOWS_7_IP))


class OsxSettings(platformsettings._OsxPlatformSettings):
  def __init__(self):
    super(OsxSettings, self).__init__()
    self.ipv4_state = OSX_IPV4_STATE
    self.dns_state = None  # varies by test

  def _scutil(self, cmd):
    if cmd == 'show State:/Network/Global/IPv4':
      return self.ipv4_state
    elif cmd.startswith('show State:/Network/Service/'):
      return self.dns_state
    raise RuntimeError("Unrecognized cmd: %s", cmd)


class OsxPlatformSettingsTest(unittest.TestCase):
  def setUp(self):
    self.settings = OsxSettings()

  def test_get_primary_nameserver_lion(self):
    self.settings.dns_state = OSX_DNS_STATE_LION
    self.assertEqual('172.72.255.1', self.settings._get_primary_nameserver())

  def test_get_primary_nameserver_snow_leopard(self):
    self.settings.dns_state = OSX_DNS_STATE_SNOW_LEOPARD
    self.assertEqual('172.27.1.1', self.settings._get_primary_nameserver())

  def test_get_primary_nameserver_unexpected_ipv4_state_raises(self):
    self.settings.ipv4_state = 'Some error'
    self.settings.dns_state = OSX_DNS_STATE_SNOW_LEOPARD
    self.assertRaises(platformsettings.DnsReadError,
                      self.settings._get_primary_nameserver)

  def test_get_primary_nameserver_unexpected_dns_state_raises(self):
    self.settings.dns_state = 'Some other error'
    self.assertRaises(platformsettings.DnsReadError,
                      self.settings._get_primary_nameserver)


if __name__ == '__main__':
  unittest.main()
