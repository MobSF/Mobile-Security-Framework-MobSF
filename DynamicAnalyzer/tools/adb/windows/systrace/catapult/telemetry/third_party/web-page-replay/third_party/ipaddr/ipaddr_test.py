#!/usr/bin/python
#
# Copyright 2007 Google Inc.
#  Licensed to PSF under a Contributor Agreement.
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

"""Unittest for ipaddr module."""


import unittest
import time
import ipaddr

# Compatibility function to cast str to bytes objects
if issubclass(ipaddr.Bytes, str):
    _cb = ipaddr.Bytes
else:
    _cb = lambda bytestr: bytes(bytestr, 'charmap')

class IpaddrUnitTest(unittest.TestCase):

    def setUp(self):
        self.ipv4 = ipaddr.IPv4Network('1.2.3.4/24')
        self.ipv4_hostmask = ipaddr.IPv4Network('10.0.0.1/0.255.255.255')
        self.ipv6 = ipaddr.IPv6Network('2001:658:22a:cafe:200:0:0:1/64')

    def tearDown(self):
        del(self.ipv4)
        del(self.ipv4_hostmask)
        del(self.ipv6)
        del(self)

    def testRepr(self):
        self.assertEqual("IPv4Network('1.2.3.4/32')",
                         repr(ipaddr.IPv4Network('1.2.3.4')))
        self.assertEqual("IPv6Network('::1/128')",
                         repr(ipaddr.IPv6Network('::1')))

    def testAutoMasking(self):
        addr1 = ipaddr.IPv4Network('1.1.1.255/24')
        addr1_masked = ipaddr.IPv4Network('1.1.1.0/24')
        self.assertEqual(addr1_masked, addr1.masked())

        addr2 = ipaddr.IPv6Network('2000:cafe::efac:100/96')
        addr2_masked = ipaddr.IPv6Network('2000:cafe::/96')
        self.assertEqual(addr2_masked, addr2.masked())

    # issue57
    def testAddressIntMath(self):
        self.assertEqual(ipaddr.IPv4Address('1.1.1.1') + 255,
                         ipaddr.IPv4Address('1.1.2.0'))
        self.assertEqual(ipaddr.IPv4Address('1.1.1.1') - 256,
                         ipaddr.IPv4Address('1.1.0.1'))
        self.assertEqual(ipaddr.IPv6Address('::1') + (2**16 - 2),
                         ipaddr.IPv6Address('::ffff'))
        self.assertEqual(ipaddr.IPv6Address('::ffff') - (2**16 - 2),
                         ipaddr.IPv6Address('::1'))

    def testInvalidStrings(self):
        def AssertInvalidIP(ip_str):
            self.assertRaises(ValueError, ipaddr.IPAddress, ip_str)
        AssertInvalidIP("")
        AssertInvalidIP("016.016.016.016")
        AssertInvalidIP("016.016.016")
        AssertInvalidIP("016.016")
        AssertInvalidIP("016")
        AssertInvalidIP("000.000.000.000")
        AssertInvalidIP("000")
        AssertInvalidIP("0x0a.0x0a.0x0a.0x0a")
        AssertInvalidIP("0x0a.0x0a.0x0a")
        AssertInvalidIP("0x0a.0x0a")
        AssertInvalidIP("0x0a")
        AssertInvalidIP("42.42.42.42.42")
        AssertInvalidIP("42.42.42")
        AssertInvalidIP("42.42")
        AssertInvalidIP("42")
        AssertInvalidIP("42..42.42")
        AssertInvalidIP("42..42.42.42")
        AssertInvalidIP("42.42.42.42.")
        AssertInvalidIP("42.42.42.42...")
        AssertInvalidIP(".42.42.42.42")
        AssertInvalidIP("...42.42.42.42")
        AssertInvalidIP("42.42.42.-0")
        AssertInvalidIP("42.42.42.+0")
        AssertInvalidIP(".")
        AssertInvalidIP("...")
        AssertInvalidIP("bogus")
        AssertInvalidIP("bogus.com")
        AssertInvalidIP("192.168.0.1.com")
        AssertInvalidIP("12345.67899.-54321.-98765")
        AssertInvalidIP("257.0.0.0")
        AssertInvalidIP("42.42.42.-42")
        AssertInvalidIP("3ffe::1.net")
        AssertInvalidIP("3ffe::1::1")
        AssertInvalidIP("1::2::3::4:5")
        AssertInvalidIP("::7:6:5:4:3:2:")
        AssertInvalidIP(":6:5:4:3:2:1::")
        AssertInvalidIP("2001::db:::1")
        AssertInvalidIP("FEDC:9878")
        AssertInvalidIP("+1.+2.+3.4")
        AssertInvalidIP("1.2.3.4e0")
        AssertInvalidIP("::7:6:5:4:3:2:1:0")
        AssertInvalidIP("7:6:5:4:3:2:1:0::")
        AssertInvalidIP("9:8:7:6:5:4:3::2:1")
        AssertInvalidIP("0:1:2:3::4:5:6:7")
        AssertInvalidIP("3ffe:0:0:0:0:0:0:0:1")
        AssertInvalidIP("3ffe::10000")
        AssertInvalidIP("3ffe::goog")
        AssertInvalidIP("3ffe::-0")
        AssertInvalidIP("3ffe::+0")
        AssertInvalidIP("3ffe::-1")
        AssertInvalidIP(":")
        AssertInvalidIP(":::")
        AssertInvalidIP("::1.2.3")
        AssertInvalidIP("::1.2.3.4.5")
        AssertInvalidIP("::1.2.3.4:")
        AssertInvalidIP("1.2.3.4::")
        AssertInvalidIP("2001:db8::1:")
        AssertInvalidIP(":2001:db8::1")
        AssertInvalidIP(":1:2:3:4:5:6:7")
        AssertInvalidIP("1:2:3:4:5:6:7:")
        AssertInvalidIP(":1:2:3:4:5:6:")
        AssertInvalidIP("192.0.2.1/32")
        AssertInvalidIP("2001:db8::1/128")

        self.assertRaises(ipaddr.AddressValueError, ipaddr.IPv4Network, '')
        self.assertRaises(ipaddr.AddressValueError, ipaddr.IPv4Network,
                          'google.com')
        self.assertRaises(ipaddr.AddressValueError, ipaddr.IPv4Network,
                          '::1.2.3.4')
        self.assertRaises(ipaddr.AddressValueError, ipaddr.IPv6Network, '')
        self.assertRaises(ipaddr.AddressValueError, ipaddr.IPv6Network,
                          'google.com')
        self.assertRaises(ipaddr.AddressValueError, ipaddr.IPv6Network,
                          '1.2.3.4')
        self.assertRaises(ipaddr.AddressValueError, ipaddr.IPv6Network,
                          'cafe:cafe::/128/190')
        self.assertRaises(ipaddr.AddressValueError, ipaddr.IPv6Network,
                          '1234:axy::b')
        self.assertRaises(ipaddr.AddressValueError, ipaddr.IPv6Address,
                          '1234:axy::b')
        self.assertRaises(ipaddr.AddressValueError, ipaddr.IPv6Address,
                          '2001:db8:::1')
        self.assertRaises(ipaddr.AddressValueError, ipaddr.IPv6Address,
                          '2001:888888::1')
        self.assertRaises(ipaddr.AddressValueError,
                          ipaddr.IPv4Address(1)._ip_int_from_string,
                          '1.a.2.3')
        self.assertEqual(False, ipaddr.IPv4Network(1)._is_hostmask('1.a.2.3'))

    def testGetNetwork(self):
        self.assertEqual(int(self.ipv4.network), 16909056)
        self.assertEqual(str(self.ipv4.network), '1.2.3.0')
        self.assertEqual(str(self.ipv4_hostmask.network), '10.0.0.0')

        self.assertEqual(int(self.ipv6.network),
                         42540616829182469433403647294022090752)
        self.assertEqual(str(self.ipv6.network),
                         '2001:658:22a:cafe::')
        self.assertEqual(str(self.ipv6.hostmask),
                         '::ffff:ffff:ffff:ffff')

    def testBadVersionComparison(self):
        # These should always raise TypeError
        v4addr = ipaddr.IPAddress('1.1.1.1')
        v4net = ipaddr.IPNetwork('1.1.1.1')
        v6addr = ipaddr.IPAddress('::1')
        v6net = ipaddr.IPAddress('::1')

        self.assertRaises(TypeError, v4addr.__lt__, v6addr)
        self.assertRaises(TypeError, v4addr.__gt__, v6addr)
        self.assertRaises(TypeError, v4net.__lt__, v6net)
        self.assertRaises(TypeError, v4net.__gt__, v6net)

        self.assertRaises(TypeError, v6addr.__lt__, v4addr)
        self.assertRaises(TypeError, v6addr.__gt__, v4addr)
        self.assertRaises(TypeError, v6net.__lt__, v4net)
        self.assertRaises(TypeError, v6net.__gt__, v4net)

    def testMixedTypeComparison(self):
        v4addr = ipaddr.IPAddress('1.1.1.1')
        v4net = ipaddr.IPNetwork('1.1.1.1/32')
        v6addr = ipaddr.IPAddress('::1')
        v6net = ipaddr.IPNetwork('::1/128')

        self.assertFalse(v4net.__contains__(v6net))
        self.assertFalse(v6net.__contains__(v4net))

        self.assertRaises(TypeError, lambda: v4addr < v4net)
        self.assertRaises(TypeError, lambda: v4addr > v4net)
        self.assertRaises(TypeError, lambda: v4net < v4addr)
        self.assertRaises(TypeError, lambda: v4net > v4addr)

        self.assertRaises(TypeError, lambda: v6addr < v6net)
        self.assertRaises(TypeError, lambda: v6addr > v6net)
        self.assertRaises(TypeError, lambda: v6net < v6addr)
        self.assertRaises(TypeError, lambda: v6net > v6addr)

        # with get_mixed_type_key, you can sort addresses and network.
        self.assertEqual([v4addr, v4net], sorted([v4net, v4addr],
                                                 key=ipaddr.get_mixed_type_key))
        self.assertEqual([v6addr, v6net], sorted([v6net, v6addr],
                                                 key=ipaddr.get_mixed_type_key))

    def testIpFromInt(self):
        self.assertEqual(self.ipv4.ip, ipaddr.IPv4Network(16909060).ip)
        self.assertRaises(ipaddr.AddressValueError,
                          ipaddr.IPv4Network, 2**32)
        self.assertRaises(ipaddr.AddressValueError,
                          ipaddr.IPv4Network, -1)

        ipv4 = ipaddr.IPNetwork('1.2.3.4')
        ipv6 = ipaddr.IPNetwork('2001:658:22a:cafe:200:0:0:1')
        self.assertEqual(ipv4, ipaddr.IPNetwork(int(ipv4)))
        self.assertEqual(ipv6, ipaddr.IPNetwork(int(ipv6)))

        v6_int = 42540616829182469433547762482097946625
        self.assertEqual(self.ipv6.ip, ipaddr.IPv6Network(v6_int).ip)
        self.assertRaises(ipaddr.AddressValueError,
                          ipaddr.IPv6Network, 2**128)
        self.assertRaises(ipaddr.AddressValueError,
                          ipaddr.IPv6Network, -1)

        self.assertEqual(ipaddr.IPNetwork(self.ipv4.ip).version, 4)
        self.assertEqual(ipaddr.IPNetwork(self.ipv6.ip).version, 6)

    def testIpFromPacked(self):
        ip = ipaddr.IPNetwork

        self.assertEqual(self.ipv4.ip,
                         ip(_cb('\x01\x02\x03\x04')).ip)
        self.assertEqual(ip('255.254.253.252'),
                         ip(_cb('\xff\xfe\xfd\xfc')))
        self.assertRaises(ValueError, ipaddr.IPNetwork, _cb('\x00' * 3))
        self.assertRaises(ValueError, ipaddr.IPNetwork, _cb('\x00' * 5))
        self.assertEqual(self.ipv6.ip,
                         ip(_cb('\x20\x01\x06\x58\x02\x2a\xca\xfe'
                           '\x02\x00\x00\x00\x00\x00\x00\x01')).ip)
        self.assertEqual(ip('ffff:2:3:4:ffff::'),
                         ip(_cb('\xff\xff\x00\x02\x00\x03\x00\x04' +
                               '\xff\xff' + '\x00' * 6)))
        self.assertEqual(ip('::'),
                         ip(_cb('\x00' * 16)))
        self.assertRaises(ValueError, ip, _cb('\x00' * 15))
        self.assertRaises(ValueError, ip, _cb('\x00' * 17))

    def testGetIp(self):
        self.assertEqual(int(self.ipv4.ip), 16909060)
        self.assertEqual(str(self.ipv4.ip), '1.2.3.4')
        self.assertEqual(str(self.ipv4_hostmask.ip), '10.0.0.1')

        self.assertEqual(int(self.ipv6.ip),
                         42540616829182469433547762482097946625)
        self.assertEqual(str(self.ipv6.ip),
                         '2001:658:22a:cafe:200::1')

    def testGetNetmask(self):
        self.assertEqual(int(self.ipv4.netmask), 4294967040L)
        self.assertEqual(str(self.ipv4.netmask), '255.255.255.0')
        self.assertEqual(str(self.ipv4_hostmask.netmask), '255.0.0.0')
        self.assertEqual(int(self.ipv6.netmask),
                         340282366920938463444927863358058659840)
        self.assertEqual(self.ipv6.prefixlen, 64)

    def testZeroNetmask(self):
        ipv4_zero_netmask = ipaddr.IPv4Network('1.2.3.4/0')
        self.assertEqual(int(ipv4_zero_netmask.netmask), 0)
        self.assertTrue(ipv4_zero_netmask._is_valid_netmask(str(0)))

        ipv6_zero_netmask = ipaddr.IPv6Network('::1/0')
        self.assertEqual(int(ipv6_zero_netmask.netmask), 0)
        self.assertTrue(ipv6_zero_netmask._is_valid_netmask(str(0)))

    def testGetBroadcast(self):
        self.assertEqual(int(self.ipv4.broadcast), 16909311L)
        self.assertEqual(str(self.ipv4.broadcast), '1.2.3.255')

        self.assertEqual(int(self.ipv6.broadcast),
                         42540616829182469451850391367731642367)
        self.assertEqual(str(self.ipv6.broadcast),
                         '2001:658:22a:cafe:ffff:ffff:ffff:ffff')

    def testGetPrefixlen(self):
        self.assertEqual(self.ipv4.prefixlen, 24)

        self.assertEqual(self.ipv6.prefixlen, 64)

    def testGetSupernet(self):
        self.assertEqual(self.ipv4.supernet().prefixlen, 23)
        self.assertEqual(str(self.ipv4.supernet().network), '1.2.2.0')
        self.assertEqual(ipaddr.IPv4Network('0.0.0.0/0').supernet(),
                         ipaddr.IPv4Network('0.0.0.0/0'))

        self.assertEqual(self.ipv6.supernet().prefixlen, 63)
        self.assertEqual(str(self.ipv6.supernet().network),
                         '2001:658:22a:cafe::')
        self.assertEqual(ipaddr.IPv6Network('::0/0').supernet(),
                         ipaddr.IPv6Network('::0/0'))

    def testGetSupernet3(self):
        self.assertEqual(self.ipv4.supernet(3).prefixlen, 21)
        self.assertEqual(str(self.ipv4.supernet(3).network), '1.2.0.0')

        self.assertEqual(self.ipv6.supernet(3).prefixlen, 61)
        self.assertEqual(str(self.ipv6.supernet(3).network),
                         '2001:658:22a:caf8::')

    def testGetSupernet4(self):
        self.assertRaises(ValueError, self.ipv4.supernet, prefixlen_diff=2,
                          new_prefix=1)
        self.assertRaises(ValueError, self.ipv4.supernet, new_prefix=25)
        self.assertEqual(self.ipv4.supernet(prefixlen_diff=2),
                         self.ipv4.supernet(new_prefix=22))

        self.assertRaises(ValueError, self.ipv6.supernet, prefixlen_diff=2,
                          new_prefix=1)
        self.assertRaises(ValueError, self.ipv6.supernet, new_prefix=65)
        self.assertEqual(self.ipv6.supernet(prefixlen_diff=2),
                         self.ipv6.supernet(new_prefix=62))

    def testIterSubnets(self):
        self.assertEqual(self.ipv4.subnet(), list(self.ipv4.iter_subnets()))
        self.assertEqual(self.ipv6.subnet(), list(self.ipv6.iter_subnets()))

    def testIterHosts(self):
        self.assertEqual([ipaddr.IPv4Address('2.0.0.0'),
                          ipaddr.IPv4Address('2.0.0.1')],
                         list(ipaddr.IPNetwork('2.0.0.0/31').iterhosts()))

    def testFancySubnetting(self):
        self.assertEqual(sorted(self.ipv4.subnet(prefixlen_diff=3)),
                         sorted(self.ipv4.subnet(new_prefix=27)))
        self.assertRaises(ValueError, self.ipv4.subnet, new_prefix=23)
        self.assertRaises(ValueError, self.ipv4.subnet,
                          prefixlen_diff=3, new_prefix=27)
        self.assertEqual(sorted(self.ipv6.subnet(prefixlen_diff=4)),
                         sorted(self.ipv6.subnet(new_prefix=68)))
        self.assertRaises(ValueError, self.ipv6.subnet, new_prefix=63)
        self.assertRaises(ValueError, self.ipv6.subnet,
                          prefixlen_diff=4, new_prefix=68)

    def testGetSubnet(self):
        self.assertEqual(self.ipv4.subnet()[0].prefixlen, 25)
        self.assertEqual(str(self.ipv4.subnet()[0].network), '1.2.3.0')
        self.assertEqual(str(self.ipv4.subnet()[1].network), '1.2.3.128')

        self.assertEqual(self.ipv6.subnet()[0].prefixlen, 65)

    def testGetSubnetForSingle32(self):
        ip = ipaddr.IPv4Network('1.2.3.4/32')
        subnets1 = [str(x) for x in ip.subnet()]
        subnets2 = [str(x) for x in ip.subnet(2)]
        self.assertEqual(subnets1, ['1.2.3.4/32'])
        self.assertEqual(subnets1, subnets2)

    def testGetSubnetForSingle128(self):
        ip = ipaddr.IPv6Network('::1/128')
        subnets1 = [str(x) for x in ip.subnet()]
        subnets2 = [str(x) for x in ip.subnet(2)]
        self.assertEqual(subnets1, ['::1/128'])
        self.assertEqual(subnets1, subnets2)

    def testSubnet2(self):
        ips = [str(x) for x in self.ipv4.subnet(2)]
        self.assertEqual(
            ips,
            ['1.2.3.0/26', '1.2.3.64/26', '1.2.3.128/26', '1.2.3.192/26'])

        ipsv6 = [str(x) for x in self.ipv6.subnet(2)]
        self.assertEqual(
            ipsv6,
            ['2001:658:22a:cafe::/66',
             '2001:658:22a:cafe:4000::/66',
             '2001:658:22a:cafe:8000::/66',
             '2001:658:22a:cafe:c000::/66'])

    def testSubnetFailsForLargeCidrDiff(self):
        self.assertRaises(ValueError, self.ipv4.subnet, 9)
        self.assertRaises(ValueError, self.ipv6.subnet, 65)

    def testSupernetFailsForLargeCidrDiff(self):
        self.assertRaises(ValueError, self.ipv4.supernet, 25)
        self.assertRaises(ValueError, self.ipv6.supernet, 65)

    def testSubnetFailsForNegativeCidrDiff(self):
        self.assertRaises(ValueError, self.ipv4.subnet, -1)
        self.assertRaises(ValueError, self.ipv6.subnet, -1)

    def testGetNumHosts(self):
        self.assertEqual(self.ipv4.numhosts, 256)
        self.assertEqual(self.ipv4.subnet()[0].numhosts, 128)
        self.assertEqual(self.ipv4.supernet().numhosts, 512)

        self.assertEqual(self.ipv6.numhosts, 18446744073709551616)
        self.assertEqual(self.ipv6.subnet()[0].numhosts, 9223372036854775808)
        self.assertEqual(self.ipv6.supernet().numhosts, 36893488147419103232)

    def testContains(self):
        self.assertTrue(ipaddr.IPv4Network('1.2.3.128/25') in self.ipv4)
        self.assertFalse(ipaddr.IPv4Network('1.2.4.1/24') in self.ipv4)
        self.assertTrue(self.ipv4 in self.ipv4)
        self.assertTrue(self.ipv6 in self.ipv6)
        # We can test addresses and string as well.
        addr1 = ipaddr.IPv4Address('1.2.3.37')
        self.assertTrue(addr1 in self.ipv4)
        # issue 61, bad network comparison on like-ip'd network objects
        # with identical broadcast addresses.
        self.assertFalse(ipaddr.IPv4Network('1.1.0.0/16').__contains__(
                ipaddr.IPv4Network('1.0.0.0/15')))

    def testBadAddress(self):
        self.assertRaises(ipaddr.AddressValueError, ipaddr.IPv4Network,
                          'poop')
        self.assertRaises(ipaddr.AddressValueError,
                          ipaddr.IPv4Network, '1.2.3.256')

        self.assertRaises(ipaddr.AddressValueError, ipaddr.IPv6Network,
                          'poopv6')
        self.assertRaises(ipaddr.AddressValueError,
                          ipaddr.IPv4Network, '1.2.3.4/32/24')
        self.assertRaises(ipaddr.AddressValueError,
                          ipaddr.IPv4Network, '10/8')
        self.assertRaises(ipaddr.AddressValueError,
                          ipaddr.IPv6Network, '10/8')


    def testBadNetMask(self):
        self.assertRaises(ipaddr.NetmaskValueError,
                          ipaddr.IPv4Network, '1.2.3.4/')
        self.assertRaises(ipaddr.NetmaskValueError,
                          ipaddr.IPv4Network, '1.2.3.4/33')
        self.assertRaises(ipaddr.NetmaskValueError,
                          ipaddr.IPv4Network, '1.2.3.4/254.254.255.256')
        self.assertRaises(ipaddr.NetmaskValueError,
                          ipaddr.IPv4Network, '1.1.1.1/240.255.0.0')
        self.assertRaises(ipaddr.NetmaskValueError,
                          ipaddr.IPv6Network, '::1/')
        self.assertRaises(ipaddr.NetmaskValueError,
                          ipaddr.IPv6Network, '::1/129')

    def testNth(self):
        self.assertEqual(str(self.ipv4[5]), '1.2.3.5')
        self.assertRaises(IndexError, self.ipv4.__getitem__, 256)

        self.assertEqual(str(self.ipv6[5]),
                         '2001:658:22a:cafe::5')

    def testGetitem(self):
        # http://code.google.com/p/ipaddr-py/issues/detail?id=15
        addr = ipaddr.IPv4Network('172.31.255.128/255.255.255.240')
        self.assertEqual(28, addr.prefixlen)
        addr_list = list(addr)
        self.assertEqual('172.31.255.128', str(addr_list[0]))
        self.assertEqual('172.31.255.128', str(addr[0]))
        self.assertEqual('172.31.255.143', str(addr_list[-1]))
        self.assertEqual('172.31.255.143', str(addr[-1]))
        self.assertEqual(addr_list[-1], addr[-1])

    def testEqual(self):
        self.assertTrue(self.ipv4 == ipaddr.IPv4Network('1.2.3.4/24'))
        self.assertFalse(self.ipv4 == ipaddr.IPv4Network('1.2.3.4/23'))
        self.assertFalse(self.ipv4 == ipaddr.IPv6Network('::1.2.3.4/24'))
        self.assertFalse(self.ipv4 == '')
        self.assertFalse(self.ipv4 == [])
        self.assertFalse(self.ipv4 == 2)
        self.assertTrue(ipaddr.IPNetwork('1.1.1.1/32') ==
                        ipaddr.IPAddress('1.1.1.1'))
        self.assertTrue(ipaddr.IPNetwork('1.1.1.1/24') ==
                        ipaddr.IPAddress('1.1.1.1'))
        self.assertFalse(ipaddr.IPNetwork('1.1.1.0/24') ==
                         ipaddr.IPAddress('1.1.1.1'))

        self.assertTrue(self.ipv6 ==
            ipaddr.IPv6Network('2001:658:22a:cafe:200::1/64'))
        self.assertTrue(ipaddr.IPNetwork('::1/128') ==
                        ipaddr.IPAddress('::1'))
        self.assertTrue(ipaddr.IPNetwork('::1/127') ==
                        ipaddr.IPAddress('::1'))
        self.assertFalse(ipaddr.IPNetwork('::0/127') ==
                         ipaddr.IPAddress('::1'))
        self.assertFalse(self.ipv6 ==
            ipaddr.IPv6Network('2001:658:22a:cafe:200::1/63'))
        self.assertFalse(self.ipv6 == ipaddr.IPv4Network('1.2.3.4/23'))
        self.assertFalse(self.ipv6 == '')
        self.assertFalse(self.ipv6 == [])
        self.assertFalse(self.ipv6 == 2)

    def testNotEqual(self):
        self.assertFalse(self.ipv4 != ipaddr.IPv4Network('1.2.3.4/24'))
        self.assertTrue(self.ipv4 != ipaddr.IPv4Network('1.2.3.4/23'))
        self.assertTrue(self.ipv4 != ipaddr.IPv6Network('::1.2.3.4/24'))
        self.assertTrue(self.ipv4 != '')
        self.assertTrue(self.ipv4 != [])
        self.assertTrue(self.ipv4 != 2)

        addr2 = ipaddr.IPAddress('2001:658:22a:cafe:200::1')
        self.assertFalse(self.ipv6 !=
            ipaddr.IPv6Network('2001:658:22a:cafe:200::1/64'))
        self.assertTrue(self.ipv6 !=
            ipaddr.IPv6Network('2001:658:22a:cafe:200::1/63'))
        self.assertTrue(self.ipv6 != ipaddr.IPv4Network('1.2.3.4/23'))
        self.assertTrue(self.ipv6 != '')
        self.assertTrue(self.ipv6 != [])
        self.assertTrue(self.ipv6 != 2)

    def testSlash32Constructor(self):
        self.assertEqual(str(ipaddr.IPv4Network('1.2.3.4/255.255.255.255')),
                          '1.2.3.4/32')

    def testSlash128Constructor(self):
        self.assertEqual(str(ipaddr.IPv6Network('::1/128')),
                                  '::1/128')

    def testSlash0Constructor(self):
        self.assertEqual(str(ipaddr.IPv4Network('1.2.3.4/0.0.0.0')),
                          '1.2.3.4/0')

    def testCollapsing(self):
        # test only IP addresses including some duplicates
        ip1 = ipaddr.IPv4Address('1.1.1.0')
        ip2 = ipaddr.IPv4Address('1.1.1.1')
        ip3 = ipaddr.IPv4Address('1.1.1.2')
        ip4 = ipaddr.IPv4Address('1.1.1.3')
        ip5 = ipaddr.IPv4Address('1.1.1.4')
        ip6 = ipaddr.IPv4Address('1.1.1.0')
        # check that addreses are subsumed properly.
        collapsed = ipaddr.collapse_address_list([ip1, ip2, ip3, ip4, ip5, ip6])
        self.assertEqual(collapsed, [ipaddr.IPv4Network('1.1.1.0/30'),
                                     ipaddr.IPv4Network('1.1.1.4/32')])

        # test a mix of IP addresses and networks including some duplicates
        ip1 = ipaddr.IPv4Address('1.1.1.0')
        ip2 = ipaddr.IPv4Address('1.1.1.1')
        ip3 = ipaddr.IPv4Address('1.1.1.2')
        ip4 = ipaddr.IPv4Address('1.1.1.3')
        ip5 = ipaddr.IPv4Network('1.1.1.4/30')
        ip6 = ipaddr.IPv4Network('1.1.1.4/30')
        # check that addreses are subsumed properly.
        collapsed = ipaddr.collapse_address_list([ip5, ip1, ip2, ip3, ip4, ip6])
        self.assertEqual(collapsed, [ipaddr.IPv4Network('1.1.1.0/29')])

        # test only IP networks
        ip1 = ipaddr.IPv4Network('1.1.0.0/24')
        ip2 = ipaddr.IPv4Network('1.1.1.0/24')
        ip3 = ipaddr.IPv4Network('1.1.2.0/24')
        ip4 = ipaddr.IPv4Network('1.1.3.0/24')
        ip5 = ipaddr.IPv4Network('1.1.4.0/24')
        # stored in no particular order b/c we want CollapseAddr to call [].sort
        ip6 = ipaddr.IPv4Network('1.1.0.0/22')
        # check that addreses are subsumed properly.
        collapsed = ipaddr.collapse_address_list([ip1, ip2, ip3, ip4, ip5, ip6])
        self.assertEqual(collapsed, [ipaddr.IPv4Network('1.1.0.0/22'),
                                     ipaddr.IPv4Network('1.1.4.0/24')])

        # test that two addresses are supernet'ed properly
        collapsed = ipaddr.collapse_address_list([ip1, ip2])
        self.assertEqual(collapsed, [ipaddr.IPv4Network('1.1.0.0/23')])

        # test same IP networks
        ip_same1 = ip_same2 = ipaddr.IPv4Network('1.1.1.1/32')
        self.assertEqual(ipaddr.collapse_address_list([ip_same1, ip_same2]),
                         [ip_same1])

        # test same IP addresses
        ip_same1 = ip_same2 = ipaddr.IPv4Address('1.1.1.1')
        self.assertEqual(ipaddr.collapse_address_list([ip_same1, ip_same2]),
                         [ipaddr.IPNetwork('1.1.1.1/32')])
        ip1 = ipaddr.IPv6Network('::2001:1/100')
        ip2 = ipaddr.IPv6Network('::2002:1/120')
        ip3 = ipaddr.IPv6Network('::2001:1/96')
        # test that ipv6 addresses are subsumed properly.
        collapsed = ipaddr.collapse_address_list([ip1, ip2, ip3])
        self.assertEqual(collapsed, [ip3])

        # the toejam test
        ip1 = ipaddr.IPAddress('1.1.1.1')
        ip2 = ipaddr.IPAddress('::1')
        self.assertRaises(TypeError, ipaddr.collapse_address_list,
                          [ip1, ip2])

    def testSummarizing(self):
        #ip = ipaddr.IPAddress
        #ipnet = ipaddr.IPNetwork
        summarize = ipaddr.summarize_address_range
        ip1 = ipaddr.IPAddress('1.1.1.0')
        ip2 = ipaddr.IPAddress('1.1.1.255')
        # test a /24 is sumamrized properly
        self.assertEqual(summarize(ip1, ip2)[0], ipaddr.IPNetwork('1.1.1.0/24'))
        # test an  IPv4 range that isn't on a network byte boundary
        ip2 = ipaddr.IPAddress('1.1.1.8')
        self.assertEqual(summarize(ip1, ip2), [ipaddr.IPNetwork('1.1.1.0/29'),
                                               ipaddr.IPNetwork('1.1.1.8')])

        ip1 = ipaddr.IPAddress('1::')
        ip2 = ipaddr.IPAddress('1:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
        # test a IPv6 is sumamrized properly
        self.assertEqual(summarize(ip1, ip2)[0], ipaddr.IPNetwork('1::/16'))
        # test an IPv6 range that isn't on a network byte boundary
        ip2 = ipaddr.IPAddress('2::')
        self.assertEqual(summarize(ip1, ip2), [ipaddr.IPNetwork('1::/16'),
                                               ipaddr.IPNetwork('2::/128')])

        # test exception raised when first is greater than last
        self.assertRaises(ValueError, summarize, ipaddr.IPAddress('1.1.1.0'),
            ipaddr.IPAddress('1.1.0.0'))
        # test exception raised when first and last aren't IP addresses
        self.assertRaises(TypeError, summarize,
                          ipaddr.IPNetwork('1.1.1.0'),
                          ipaddr.IPNetwork('1.1.0.0'))
        self.assertRaises(TypeError, summarize,
            ipaddr.IPNetwork('1.1.1.0'), ipaddr.IPNetwork('1.1.0.0'))
        # test exception raised when first and last are not same version
        self.assertRaises(TypeError, summarize, ipaddr.IPAddress('::'),
            ipaddr.IPNetwork('1.1.0.0'))

    def testAddressComparison(self):
        self.assertTrue(ipaddr.IPAddress('1.1.1.1') <=
                        ipaddr.IPAddress('1.1.1.1'))
        self.assertTrue(ipaddr.IPAddress('1.1.1.1') <=
                        ipaddr.IPAddress('1.1.1.2'))
        self.assertTrue(ipaddr.IPAddress('::1') <= ipaddr.IPAddress('::1'))
        self.assertTrue(ipaddr.IPAddress('::1') <= ipaddr.IPAddress('::2'))

    def testNetworkComparison(self):
        # ip1 and ip2 have the same network address
        ip1 = ipaddr.IPv4Network('1.1.1.0/24')
        ip2 = ipaddr.IPv4Network('1.1.1.1/24')
        ip3 = ipaddr.IPv4Network('1.1.2.0/24')

        self.assertTrue(ip1 < ip3)
        self.assertTrue(ip3 > ip2)

        self.assertEqual(ip1.compare_networks(ip2), 0)
        self.assertTrue(ip1._get_networks_key() == ip2._get_networks_key())
        self.assertEqual(ip1.compare_networks(ip3), -1)
        self.assertTrue(ip1._get_networks_key() < ip3._get_networks_key())

        ip1 = ipaddr.IPv6Network('2001::2000/96')
        ip2 = ipaddr.IPv6Network('2001::2001/96')
        ip3 = ipaddr.IPv6Network('2001:ffff::2000/96')

        self.assertTrue(ip1 < ip3)
        self.assertTrue(ip3 > ip2)
        self.assertEqual(ip1.compare_networks(ip2), 0)
        self.assertTrue(ip1._get_networks_key() == ip2._get_networks_key())
        self.assertEqual(ip1.compare_networks(ip3), -1)
        self.assertTrue(ip1._get_networks_key() < ip3._get_networks_key())

        # Test comparing different protocols.
        # Should always raise a TypeError.
        ipv6 = ipaddr.IPv6Network('::/0')
        ipv4 = ipaddr.IPv4Network('0.0.0.0/0')
        self.assertRaises(TypeError, ipv4.__lt__, ipv6)
        self.assertRaises(TypeError, ipv4.__gt__, ipv6)
        self.assertRaises(TypeError, ipv6.__lt__, ipv4)
        self.assertRaises(TypeError, ipv6.__gt__, ipv4)

        # Regression test for issue 19.
        ip1 = ipaddr.IPNetwork('10.1.2.128/25')
        self.assertFalse(ip1 < ip1)
        self.assertFalse(ip1 > ip1)
        ip2 = ipaddr.IPNetwork('10.1.3.0/24')
        self.assertTrue(ip1 < ip2)
        self.assertFalse(ip2 < ip1)
        self.assertFalse(ip1 > ip2)
        self.assertTrue(ip2 > ip1)
        ip3 = ipaddr.IPNetwork('10.1.3.0/25')
        self.assertTrue(ip2 < ip3)
        self.assertFalse(ip3 < ip2)
        self.assertFalse(ip2 > ip3)
        self.assertTrue(ip3 > ip2)

        # Regression test for issue 28.
        ip1 = ipaddr.IPNetwork('10.10.10.0/31')
        ip2 = ipaddr.IPNetwork('10.10.10.0')
        ip3 = ipaddr.IPNetwork('10.10.10.2/31')
        ip4 = ipaddr.IPNetwork('10.10.10.2')
        sorted = [ip1, ip2, ip3, ip4]
        unsorted = [ip2, ip4, ip1, ip3]
        unsorted.sort()
        self.assertEqual(sorted, unsorted)
        unsorted = [ip4, ip1, ip3, ip2]
        unsorted.sort()
        self.assertEqual(sorted, unsorted)
        self.assertRaises(TypeError, ip1.__lt__, ipaddr.IPAddress('10.10.10.0'))
        self.assertRaises(TypeError, ip2.__lt__, ipaddr.IPAddress('10.10.10.0'))

        # <=, >=
        self.assertTrue(ipaddr.IPNetwork('1.1.1.1') <=
                        ipaddr.IPNetwork('1.1.1.1'))
        self.assertTrue(ipaddr.IPNetwork('1.1.1.1') <=
                        ipaddr.IPNetwork('1.1.1.2'))
        self.assertFalse(ipaddr.IPNetwork('1.1.1.2') <=
                        ipaddr.IPNetwork('1.1.1.1'))
        self.assertTrue(ipaddr.IPNetwork('::1') <= ipaddr.IPNetwork('::1'))
        self.assertTrue(ipaddr.IPNetwork('::1') <= ipaddr.IPNetwork('::2'))
        self.assertFalse(ipaddr.IPNetwork('::2') <= ipaddr.IPNetwork('::1'))

    def testStrictNetworks(self):
        self.assertRaises(ValueError, ipaddr.IPNetwork, '192.168.1.1/24',
                          strict=True)
        self.assertRaises(ValueError, ipaddr.IPNetwork, '::1/120', strict=True)

    def testOverlaps(self):
        other = ipaddr.IPv4Network('1.2.3.0/30')
        other2 = ipaddr.IPv4Network('1.2.2.0/24')
        other3 = ipaddr.IPv4Network('1.2.2.64/26')
        self.assertTrue(self.ipv4.overlaps(other))
        self.assertFalse(self.ipv4.overlaps(other2))
        self.assertTrue(other2.overlaps(other3))

    def testEmbeddedIpv4(self):
        ipv4_string = '192.168.0.1'
        ipv4 = ipaddr.IPv4Network(ipv4_string)
        v4compat_ipv6 = ipaddr.IPv6Network('::%s' % ipv4_string)
        self.assertEqual(int(v4compat_ipv6.ip), int(ipv4.ip))
        v4mapped_ipv6 = ipaddr.IPv6Network('::ffff:%s' % ipv4_string)
        self.assertNotEqual(v4mapped_ipv6.ip, ipv4.ip)
        self.assertRaises(ipaddr.AddressValueError, ipaddr.IPv6Network,
                          '2001:1.1.1.1:1.1.1.1')

    # Issue 67: IPv6 with embedded IPv4 address not recognized.
    def testIPv6AddressTooLarge(self):
        # RFC4291 2.5.5.2
        self.assertEqual(ipaddr.IPAddress('::FFFF:192.0.2.1'),
                          ipaddr.IPAddress('::FFFF:c000:201'))
        # RFC4291 2.2 (part 3) x::d.d.d.d 
        self.assertEqual(ipaddr.IPAddress('FFFF::192.0.2.1'),
                          ipaddr.IPAddress('FFFF::c000:201'))

    def testIPVersion(self):
        self.assertEqual(self.ipv4.version, 4)
        self.assertEqual(self.ipv6.version, 6)

    def testMaxPrefixLength(self):
        self.assertEqual(self.ipv4.max_prefixlen, 32)
        self.assertEqual(self.ipv6.max_prefixlen, 128)

    def testPacked(self):
        self.assertEqual(self.ipv4.packed,
                         _cb('\x01\x02\x03\x04'))
        self.assertEqual(ipaddr.IPv4Network('255.254.253.252').packed,
                         _cb('\xff\xfe\xfd\xfc'))
        self.assertEqual(self.ipv6.packed,
                         _cb('\x20\x01\x06\x58\x02\x2a\xca\xfe'
                             '\x02\x00\x00\x00\x00\x00\x00\x01'))
        self.assertEqual(ipaddr.IPv6Network('ffff:2:3:4:ffff::').packed,
                         _cb('\xff\xff\x00\x02\x00\x03\x00\x04\xff\xff'
                            + '\x00' * 6))
        self.assertEqual(ipaddr.IPv6Network('::1:0:0:0:0').packed,
                         _cb('\x00' * 6 + '\x00\x01' + '\x00' * 8))

    def testIpStrFromPrefixlen(self):
        ipv4 = ipaddr.IPv4Network('1.2.3.4/24')
        self.assertEqual(ipv4._ip_string_from_prefix(), '255.255.255.0')
        self.assertEqual(ipv4._ip_string_from_prefix(28), '255.255.255.240')

    def testIpType(self):
        ipv4net = ipaddr.IPNetwork('1.2.3.4')
        ipv4addr = ipaddr.IPAddress('1.2.3.4')
        ipv6net = ipaddr.IPNetwork('::1.2.3.4')
        ipv6addr = ipaddr.IPAddress('::1.2.3.4')
        self.assertEqual(ipaddr.IPv4Network, type(ipv4net))
        self.assertEqual(ipaddr.IPv4Address, type(ipv4addr))
        self.assertEqual(ipaddr.IPv6Network, type(ipv6net))
        self.assertEqual(ipaddr.IPv6Address, type(ipv6addr))

    def testReservedIpv4(self):
        # test networks
        self.assertEqual(True, ipaddr.IPNetwork('224.1.1.1/31').is_multicast)
        self.assertEqual(False, ipaddr.IPNetwork('240.0.0.0').is_multicast)

        self.assertEqual(True, ipaddr.IPNetwork('192.168.1.1/17').is_private)
        self.assertEqual(False, ipaddr.IPNetwork('192.169.0.0').is_private)
        self.assertEqual(True, ipaddr.IPNetwork('10.255.255.255').is_private)
        self.assertEqual(False, ipaddr.IPNetwork('11.0.0.0').is_private)
        self.assertEqual(True, ipaddr.IPNetwork('172.31.255.255').is_private)
        self.assertEqual(False, ipaddr.IPNetwork('172.32.0.0').is_private)

        self.assertEqual(True,
                          ipaddr.IPNetwork('169.254.100.200/24').is_link_local)
        self.assertEqual(False,
                          ipaddr.IPNetwork('169.255.100.200/24').is_link_local)

        self.assertEqual(True,
                          ipaddr.IPNetwork('127.100.200.254/32').is_loopback)
        self.assertEqual(True, ipaddr.IPNetwork('127.42.0.0/16').is_loopback)
        self.assertEqual(False, ipaddr.IPNetwork('128.0.0.0').is_loopback)

        # test addresses
        self.assertEqual(True, ipaddr.IPAddress('224.1.1.1').is_multicast)
        self.assertEqual(False, ipaddr.IPAddress('240.0.0.0').is_multicast)

        self.assertEqual(True, ipaddr.IPAddress('192.168.1.1').is_private)
        self.assertEqual(False, ipaddr.IPAddress('192.169.0.0').is_private)
        self.assertEqual(True, ipaddr.IPAddress('10.255.255.255').is_private)
        self.assertEqual(False, ipaddr.IPAddress('11.0.0.0').is_private)
        self.assertEqual(True, ipaddr.IPAddress('172.31.255.255').is_private)
        self.assertEqual(False, ipaddr.IPAddress('172.32.0.0').is_private)

        self.assertEqual(True,
                          ipaddr.IPAddress('169.254.100.200').is_link_local)
        self.assertEqual(False,
                          ipaddr.IPAddress('169.255.100.200').is_link_local)

        self.assertEqual(True,
                          ipaddr.IPAddress('127.100.200.254').is_loopback)
        self.assertEqual(True, ipaddr.IPAddress('127.42.0.0').is_loopback)
        self.assertEqual(False, ipaddr.IPAddress('128.0.0.0').is_loopback)
        self.assertEqual(True, ipaddr.IPNetwork('0.0.0.0').is_unspecified)

    def testReservedIpv6(self):

        self.assertEqual(True, ipaddr.IPNetwork('ffff::').is_multicast)
        self.assertEqual(True, ipaddr.IPNetwork(2**128-1).is_multicast)
        self.assertEqual(True, ipaddr.IPNetwork('ff00::').is_multicast)
        self.assertEqual(False, ipaddr.IPNetwork('fdff::').is_multicast)

        self.assertEqual(True, ipaddr.IPNetwork('fecf::').is_site_local)
        self.assertEqual(True, ipaddr.IPNetwork(
                'feff:ffff:ffff:ffff::').is_site_local)
        self.assertEqual(False, ipaddr.IPNetwork('fbf:ffff::').is_site_local)
        self.assertEqual(False, ipaddr.IPNetwork('ff00::').is_site_local)

        self.assertEqual(True, ipaddr.IPNetwork('fc00::').is_private)
        self.assertEqual(True, ipaddr.IPNetwork(
                'fc00:ffff:ffff:ffff::').is_private)
        self.assertEqual(False, ipaddr.IPNetwork('fbff:ffff::').is_private)
        self.assertEqual(False, ipaddr.IPNetwork('fe00::').is_private)

        self.assertEqual(True, ipaddr.IPNetwork('fea0::').is_link_local)
        self.assertEqual(True, ipaddr.IPNetwork('febf:ffff::').is_link_local)
        self.assertEqual(False, ipaddr.IPNetwork('fe7f:ffff::').is_link_local)
        self.assertEqual(False, ipaddr.IPNetwork('fec0::').is_link_local)

        self.assertEqual(True, ipaddr.IPNetwork('0:0::0:01').is_loopback)
        self.assertEqual(False, ipaddr.IPNetwork('::1/127').is_loopback)
        self.assertEqual(False, ipaddr.IPNetwork('::').is_loopback)
        self.assertEqual(False, ipaddr.IPNetwork('::2').is_loopback)

        self.assertEqual(True, ipaddr.IPNetwork('0::0').is_unspecified)
        self.assertEqual(False, ipaddr.IPNetwork('::1').is_unspecified)
        self.assertEqual(False, ipaddr.IPNetwork('::/127').is_unspecified)

        # test addresses
        self.assertEqual(True, ipaddr.IPAddress('ffff::').is_multicast)
        self.assertEqual(True, ipaddr.IPAddress(2**128-1).is_multicast)
        self.assertEqual(True, ipaddr.IPAddress('ff00::').is_multicast)
        self.assertEqual(False, ipaddr.IPAddress('fdff::').is_multicast)

        self.assertEqual(True, ipaddr.IPAddress('fecf::').is_site_local)
        self.assertEqual(True, ipaddr.IPAddress(
                'feff:ffff:ffff:ffff::').is_site_local)
        self.assertEqual(False, ipaddr.IPAddress('fbf:ffff::').is_site_local)
        self.assertEqual(False, ipaddr.IPAddress('ff00::').is_site_local)

        self.assertEqual(True, ipaddr.IPAddress('fc00::').is_private)
        self.assertEqual(True, ipaddr.IPAddress(
                'fc00:ffff:ffff:ffff::').is_private)
        self.assertEqual(False, ipaddr.IPAddress('fbff:ffff::').is_private)
        self.assertEqual(False, ipaddr.IPAddress('fe00::').is_private)

        self.assertEqual(True, ipaddr.IPAddress('fea0::').is_link_local)
        self.assertEqual(True, ipaddr.IPAddress('febf:ffff::').is_link_local)
        self.assertEqual(False, ipaddr.IPAddress('fe7f:ffff::').is_link_local)
        self.assertEqual(False, ipaddr.IPAddress('fec0::').is_link_local)

        self.assertEqual(True, ipaddr.IPAddress('0:0::0:01').is_loopback)
        self.assertEqual(True, ipaddr.IPAddress('::1').is_loopback)
        self.assertEqual(False, ipaddr.IPAddress('::2').is_loopback)

        self.assertEqual(True, ipaddr.IPAddress('0::0').is_unspecified)
        self.assertEqual(False, ipaddr.IPAddress('::1').is_unspecified)

        # some generic IETF reserved addresses
        self.assertEqual(True, ipaddr.IPAddress('100::').is_reserved)
        self.assertEqual(True, ipaddr.IPNetwork('4000::1/128').is_reserved)

    def testIpv4Mapped(self):
        self.assertEqual(ipaddr.IPAddress('::ffff:192.168.1.1').ipv4_mapped,
                         ipaddr.IPAddress('192.168.1.1'))
        self.assertEqual(ipaddr.IPAddress('::c0a8:101').ipv4_mapped, None)
        self.assertEqual(ipaddr.IPAddress('::ffff:c0a8:101').ipv4_mapped,
                         ipaddr.IPAddress('192.168.1.1'))

    def testAddrExclude(self):
        addr1 = ipaddr.IPNetwork('10.1.1.0/24')
        addr2 = ipaddr.IPNetwork('10.1.1.0/26')
        addr3 = ipaddr.IPNetwork('10.2.1.0/24')
        addr4 = ipaddr.IPAddress('10.1.1.0')
        self.assertEqual(addr1.address_exclude(addr2),
                         [ipaddr.IPNetwork('10.1.1.64/26'),
                          ipaddr.IPNetwork('10.1.1.128/25')])
        self.assertRaises(ValueError, addr1.address_exclude, addr3)
        self.assertRaises(TypeError, addr1.address_exclude, addr4)
        self.assertEqual(addr1.address_exclude(addr1), [])

    def testHash(self):
        self.assertEqual(hash(ipaddr.IPNetwork('10.1.1.0/24')),
                          hash(ipaddr.IPNetwork('10.1.1.0/24')))
        self.assertEqual(hash(ipaddr.IPAddress('10.1.1.0')),
                          hash(ipaddr.IPAddress('10.1.1.0')))
        # i70
        self.assertEqual(hash(ipaddr.IPAddress('1.2.3.4')),
                          hash(ipaddr.IPAddress(
                    long(ipaddr.IPAddress('1.2.3.4')._ip))))
        ip1 = ipaddr.IPAddress('10.1.1.0')
        ip2 = ipaddr.IPAddress('1::')
        dummy = {}
        dummy[self.ipv4] = None
        dummy[self.ipv6] = None
        dummy[ip1] = None
        dummy[ip2] = None
        self.assertTrue(self.ipv4 in dummy)
        self.assertTrue(ip2 in dummy)

    def testCopyConstructor(self):
        addr1 = ipaddr.IPNetwork('10.1.1.0/24')
        addr2 = ipaddr.IPNetwork(addr1)
        addr3 = ipaddr.IPNetwork('2001:658:22a:cafe:200::1/64')
        addr4 = ipaddr.IPNetwork(addr3)
        addr5 = ipaddr.IPv4Address('1.1.1.1')
        addr6 = ipaddr.IPv6Address('2001:658:22a:cafe:200::1')

        self.assertEqual(addr1, addr2)
        self.assertEqual(addr3, addr4)
        self.assertEqual(addr5, ipaddr.IPv4Address(addr5))
        self.assertEqual(addr6, ipaddr.IPv6Address(addr6))

    def testCompressIPv6Address(self):
        test_addresses = {
            '1:2:3:4:5:6:7:8': '1:2:3:4:5:6:7:8/128',
            '2001:0:0:4:0:0:0:8': '2001:0:0:4::8/128',
            '2001:0:0:4:5:6:7:8': '2001::4:5:6:7:8/128',
            '2001:0:3:4:5:6:7:8': '2001:0:3:4:5:6:7:8/128',
            '2001:0:3:4:5:6:7:8': '2001:0:3:4:5:6:7:8/128',
            '0:0:3:0:0:0:0:ffff': '0:0:3::ffff/128',
            '0:0:0:4:0:0:0:ffff': '::4:0:0:0:ffff/128',
            '0:0:0:0:5:0:0:ffff': '::5:0:0:ffff/128',
            '1:0:0:4:0:0:7:8': '1::4:0:0:7:8/128',
            '0:0:0:0:0:0:0:0': '::/128',
            '0:0:0:0:0:0:0:0/0': '::/0',
            '0:0:0:0:0:0:0:1': '::1/128',
            '2001:0658:022a:cafe:0000:0000:0000:0000/66':
            '2001:658:22a:cafe::/66',
            '::1.2.3.4': '::102:304/128',
            '1:2:3:4:5:ffff:1.2.3.4': '1:2:3:4:5:ffff:102:304/128',
            '::7:6:5:4:3:2:1': '0:7:6:5:4:3:2:1/128',
            '::7:6:5:4:3:2:0': '0:7:6:5:4:3:2:0/128',
            '7:6:5:4:3:2:1::': '7:6:5:4:3:2:1:0/128',
            '0:6:5:4:3:2:1::': '0:6:5:4:3:2:1:0/128',
            }
        for uncompressed, compressed in test_addresses.items():
            self.assertEqual(compressed, str(ipaddr.IPv6Network(uncompressed)))

    def testExplodeShortHandIpStr(self):
        addr1 = ipaddr.IPv6Network('2001::1')
        addr2 = ipaddr.IPv6Address('2001:0:5ef5:79fd:0:59d:a0e5:ba1')
        self.assertEqual('2001:0000:0000:0000:0000:0000:0000:0001/128',
                         addr1.exploded)
        self.assertEqual('0000:0000:0000:0000:0000:0000:0000:0001/128',
                         ipaddr.IPv6Network('::1/128').exploded)
        # issue 77
        self.assertEqual('2001:0000:5ef5:79fd:0000:059d:a0e5:0ba1',
                         addr2.exploded)

    def testIntRepresentation(self):
        self.assertEqual(16909060, int(self.ipv4))
        self.assertEqual(42540616829182469433547762482097946625, int(self.ipv6))

    def testHexRepresentation(self):
        self.assertEqual(hex(0x1020304),
                         hex(self.ipv4))

        self.assertEqual(hex(0x20010658022ACAFE0200000000000001),
                         hex(self.ipv6))

    # backwards compatibility
    def testBackwardsCompability(self):
        self.assertEqual(ipaddr.CollapseAddrList(
            [ipaddr.IPNetwork('1.1.0.0/24'), ipaddr.IPNetwork('1.1.1.0/24')]),
                         [ipaddr.IPNetwork('1.1.0.0/23')])

        self.assertEqual(ipaddr.IPNetwork('::42:0/112').AddressExclude(
            ipaddr.IPNetwork('::42:8000/113')),
                         [ipaddr.IPNetwork('::42:0/113')])

        self.assertTrue(ipaddr.IPNetwork('1::/8').CompareNetworks(
            ipaddr.IPNetwork('2::/9')) < 0)

        self.assertEqual(ipaddr.IPNetwork('1::/16').Contains(
            ipaddr.IPNetwork('2::/16')), False)

        self.assertEqual(ipaddr.IPNetwork('0.0.0.0/0').Subnet(),
                         [ipaddr.IPNetwork('0.0.0.0/1'),
                          ipaddr.IPNetwork('128.0.0.0/1')])
        self.assertEqual(ipaddr.IPNetwork('::/127').Subnet(),
                         [ipaddr.IPNetwork('::/128'),
                          ipaddr.IPNetwork('::1/128')])

        self.assertEqual(ipaddr.IPNetwork('1.0.0.0/32').Supernet(),
                         ipaddr.IPNetwork('1.0.0.0/31'))
        self.assertEqual(ipaddr.IPNetwork('::/121').Supernet(),
                         ipaddr.IPNetwork('::/120'))

        self.assertEqual(ipaddr.IPNetwork('10.0.0.2').IsRFC1918(), True)
        self.assertEqual(ipaddr.IPNetwork('10.0.0.0').IsMulticast(), False)
        self.assertEqual(ipaddr.IPNetwork('127.255.255.255').IsLoopback(), True)
        self.assertEqual(ipaddr.IPNetwork('169.255.255.255').IsLinkLocal(),
                         False)

    def testForceVersion(self):
        self.assertEqual(ipaddr.IPNetwork(1).version, 4)
        self.assertEqual(ipaddr.IPNetwork(1, version=6).version, 6)

    def testWithStar(self):
        self.assertEqual(str(self.ipv4.with_prefixlen), "1.2.3.4/24")
        self.assertEqual(str(self.ipv4.with_netmask), "1.2.3.4/255.255.255.0")
        self.assertEqual(str(self.ipv4.with_hostmask), "1.2.3.4/0.0.0.255")

        self.assertEqual(str(self.ipv6.with_prefixlen),
                         '2001:658:22a:cafe:200::1/64')
        # rfc3513 sec 2.3 says that ipv6 only uses cidr notation for
        # subnets
        self.assertEqual(str(self.ipv6.with_netmask),
                         '2001:658:22a:cafe:200::1/64')
        # this probably don't make much sense, but it's included for
        # compatibility with ipv4
        self.assertEqual(str(self.ipv6.with_hostmask),
                         '2001:658:22a:cafe:200::1/::ffff:ffff:ffff:ffff')

    def testNetworkElementCaching(self):
        # V4 - make sure we're empty
        self.assertFalse(self.ipv4._cache.has_key('network'))
        self.assertFalse(self.ipv4._cache.has_key('broadcast'))
        self.assertFalse(self.ipv4._cache.has_key('hostmask'))

        # V4 - populate and test
        self.assertEqual(self.ipv4.network, ipaddr.IPv4Address('1.2.3.0'))
        self.assertEqual(self.ipv4.broadcast, ipaddr.IPv4Address('1.2.3.255'))
        self.assertEqual(self.ipv4.hostmask, ipaddr.IPv4Address('0.0.0.255'))

        # V4 - check we're cached
        self.assertTrue(self.ipv4._cache.has_key('network'))
        self.assertTrue(self.ipv4._cache.has_key('broadcast'))
        self.assertTrue(self.ipv4._cache.has_key('hostmask'))

        # V6 - make sure we're empty
        self.assertFalse(self.ipv6._cache.has_key('network'))
        self.assertFalse(self.ipv6._cache.has_key('broadcast'))
        self.assertFalse(self.ipv6._cache.has_key('hostmask'))

        # V6 - populate and test
        self.assertEqual(self.ipv6.network,
                         ipaddr.IPv6Address('2001:658:22a:cafe::'))
        self.assertEqual(self.ipv6.broadcast, ipaddr.IPv6Address(
            '2001:658:22a:cafe:ffff:ffff:ffff:ffff'))
        self.assertEqual(self.ipv6.hostmask,
                         ipaddr.IPv6Address('::ffff:ffff:ffff:ffff'))

        # V6 - check we're cached
        self.assertTrue(self.ipv6._cache.has_key('network'))
        self.assertTrue(self.ipv6._cache.has_key('broadcast'))
        self.assertTrue(self.ipv6._cache.has_key('hostmask'))

    def testTeredo(self):
        # stolen from wikipedia
        server = ipaddr.IPv4Address('65.54.227.120')
        client = ipaddr.IPv4Address('192.0.2.45')
        teredo_addr = '2001:0000:4136:e378:8000:63bf:3fff:fdd2'
        self.assertEqual((server, client),
                         ipaddr.IPAddress(teredo_addr).teredo)
        bad_addr = '2000::4136:e378:8000:63bf:3fff:fdd2'
        self.assertFalse(ipaddr.IPAddress(bad_addr).teredo)
        bad_addr = '2001:0001:4136:e378:8000:63bf:3fff:fdd2'
        self.assertFalse(ipaddr.IPAddress(bad_addr).teredo)

        # i77
        teredo_addr = ipaddr.IPv6Address('2001:0:5ef5:79fd:0:59d:a0e5:ba1')
        self.assertEqual((ipaddr.IPv4Address('94.245.121.253'),
                          ipaddr.IPv4Address('95.26.244.94')),
                         teredo_addr.teredo)


    def testsixtofour(self):
        sixtofouraddr = ipaddr.IPAddress('2002:ac1d:2d64::1')
        bad_addr = ipaddr.IPAddress('2000:ac1d:2d64::1')
        self.assertEqual(ipaddr.IPv4Address('172.29.45.100'),
                         sixtofouraddr.sixtofour)
        self.assertFalse(bad_addr.sixtofour)


if __name__ == '__main__':
    unittest.main()
