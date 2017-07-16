#!/usr/bin/python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import re
import sys
import argparse

from devil.utils import cmd_helper
from devil.utils import usb_hubs
from devil.utils import lsusb

# Note: In the documentation below, "virtual port" refers to the port number
# as observed by the system (e.g. by usb-devices) and "physical port" refers
# to the physical numerical label on the physical port e.g. on a USB hub.
# The mapping between virtual and physical ports is not always the identity
# (e.g. the port labeled "1" on a USB hub does not always show up as "port 1"
# when you plug something into it) but, as far as we are aware, the mapping
# between virtual and physical ports is always the same for a given
# model of USB hub. When "port number" is referenced without specifying, it
# means the virtual port number.


# Wrapper functions for system commands to get output. These are in wrapper
# functions so that they can be more easily mocked-out for tests.
def _GetParsedLSUSBOutput():
  return lsusb.lsusb()


def _GetUSBDevicesOutput():
  return cmd_helper.GetCmdOutput(['usb-devices'])


def _GetTtyUSBInfo(tty_string):
  cmd = ['udevadm', 'info', '--name=/dev/' + tty_string, '--attribute-walk']
  return cmd_helper.GetCmdOutput(cmd)


def _GetCommList():
  return cmd_helper.GetCmdOutput('ls /dev', shell=True)


def GetTTYList():
  return [x for x in _GetCommList().splitlines() if 'ttyUSB' in x]


# Class to identify nodes in the USB topology. USB topology is organized as
# a tree.
class USBNode(object):
  def __init__(self):
    self._port_to_node = {}

  @property
  def desc(self):
    raise NotImplementedError

  @property
  def info(self):
    raise NotImplementedError

  @property
  def device_num(self):
    raise NotImplementedError

  @property
  def bus_num(self):
    raise NotImplementedError

  def HasPort(self, port):
    """Determines if this device has a device connected to the given port."""
    return port in self._port_to_node

  def PortToDevice(self, port):
    """Gets the device connected to the given port on this device."""
    return self._port_to_node[port]

  def Display(self, port_chain='', info=False):
    """Displays information about this node and its descendants.

    Output format is, e.g. 1:3:3:Device 42 (ID 1234:5678 Some Device)
    meaning that from the bus, if you look at the device connected
    to port 1, then the device connected to port 3 of that,
    then the device connected to port 3 of that, you get the device
    assigned device number 42, which is Some Device. Note that device
    numbers will be reassigned whenever a connected device is powercycled
    or reinserted, but port numbers stay the same as long as the device
    is reinserted back into the same physical port.

    Args:
      port_chain: [string] Chain of ports from bus to this node (e.g. '2:4:')
      info: [bool] Whether to display detailed info as well.
    """
    raise NotImplementedError

  def AddChild(self, port, device):
    """Adds child to the device tree.

    Args:
      port: [int] Port number of the device.
      device: [USBDeviceNode] Device to add.

    Raises:
      ValueError: If device already has a child at the given port.
    """
    if self.HasPort(port):
      raise ValueError('Duplicate port number')
    else:
      self._port_to_node[port] = device

  def AllNodes(self):
    """Generator that yields this node and all of its descendants.

    Yields:
      [USBNode] First this node, then each of its descendants (recursively)
    """
    yield self
    for child_node in self._port_to_node.values():
      for descendant_node in child_node.AllNodes():
        yield descendant_node

  def FindDeviceNumber(self, findnum):
    """Find device with given number in tree

    Searches the portion of the device tree rooted at this node for
    a device with the given device number.

    Args:
      findnum: [int] Device number to search for.

    Returns:
      [USBDeviceNode] Node that is found.
    """
    for node in self.AllNodes():
      if node.device_num == findnum:
        return node
    return None


class USBDeviceNode(USBNode):
  def __init__(self, bus_num=0, device_num=0, serial=None, info=None):
    """Class that represents a device in USB tree.

    Args:
      bus_num: [int] Bus number that this node is attached to.
      device_num: [int] Device number of this device (or 0, if this is a bus)
      serial: [string] Serial number.
      info: [dict] Map giving detailed device info.
    """
    super(USBDeviceNode, self).__init__()
    self._bus_num = bus_num
    self._device_num = device_num
    self._serial = serial
    self._info = {} if info is None else info

  #override
  @property
  def desc(self):
    return self._info.get('desc')

  #override
  @property
  def info(self):
    return self._info

  #override
  @property
  def device_num(self):
    return self._device_num

  #override
  @property
  def bus_num(self):
    return self._bus_num

  @property
  def serial(self):
    return self._serial

  @serial.setter
  def serial(self, serial):
    self._serial = serial

  #override
  def Display(self, port_chain='', info=False):
    print '%s Device %d (%s)' % (port_chain, self.device_num, self.desc)
    if info:
      print self.info
    for (port, device) in self._port_to_node.iteritems():
      device.Display('%s%d:' % (port_chain, port), info=info)


class USBBusNode(USBNode):
  def __init__(self, bus_num=0):
    """Class that represents a node (either a bus or device) in USB tree.

    Args:
      is_bus: [bool] If true, node is bus; if not, node is device.
      bus_num: [int] Bus number that this node is attached to.
      device_num: [int] Device number of this device (or 0, if this is a bus)
      desc: [string] Short description of device.
      serial: [string] Serial number.
      info: [dict] Map giving detailed device info.
      port_to_dev: [dict(int:USBDeviceNode)]
          Maps port # to device connected to port.
    """
    super(USBBusNode, self).__init__()
    self._bus_num = bus_num

  #override
  @property
  def desc(self):
    return 'BUS %d' % self._bus_num

  #override
  @property
  def info(self):
    return {}

  #override
  @property
  def device_num(self):
    return -1

  #override
  @property
  def bus_num(self):
    return self._bus_num

  #override
  def Display(self, port_chain='', info=False):
    print "=== %s ===" % self.desc
    for (port, device) in self._port_to_node.iteritems():
      device.Display('%s%d:' % (port_chain, port), info=info)


_T_LINE_REGEX = re.compile(r'T:  Bus=(?P<bus>\d{2}) Lev=(?P<lev>\d{2}) '
                           r'Prnt=(?P<prnt>\d{2,3}) Port=(?P<port>\d{2}) '
                           r'Cnt=(?P<cnt>\d{2}) Dev#=(?P<dev>.{3}) .*')

_S_LINE_REGEX = re.compile(r'S:  SerialNumber=(?P<serial>.*)')
_LSUSB_BUS_DEVICE_RE = re.compile(r'^Bus (\d{3}) Device (\d{3}): (.*)')


def GetBusNumberToDeviceTreeMap(fast=True):
  """Gets devices currently attached.

  Args:
    fast [bool]: whether to do it fast (only get description, not
    the whole dictionary, from lsusb)

  Returns:
    map of {bus number: bus object}
    where the bus object has all the devices attached to it in a tree.
  """
  if fast:
    info_map = {}
    for line in lsusb.raw_lsusb().splitlines():
      match = _LSUSB_BUS_DEVICE_RE.match(line)
      if match:
        info_map[(int(match.group(1)), int(match.group(2)))] = (
          {'desc':match.group(3)})
  else:
    info_map = {((int(line['bus']), int(line['device']))): line
                for line in _GetParsedLSUSBOutput()}


  tree = {}
  bus_num = -1
  for line in _GetUSBDevicesOutput().splitlines():
    match = _T_LINE_REGEX.match(line)
    if match:
      bus_num = int(match.group('bus'))
      parent_num = int(match.group('prnt'))
      # usb-devices starts counting ports from 0, so add 1
      port_num = int(match.group('port')) + 1
      device_num = int(match.group('dev'))

      # create new bus if necessary
      if bus_num not in tree:
        tree[bus_num] = USBBusNode(bus_num=bus_num)

      # create the new device
      new_device = USBDeviceNode(bus_num=bus_num,
                                 device_num=device_num,
                                 info=info_map.get((bus_num, device_num),
                                                   {'desc': 'NOT AVAILABLE'}))

      # add device to bus
      if parent_num != 0:
        tree[bus_num].FindDeviceNumber(parent_num).AddChild(
            port_num, new_device)
      else:
        tree[bus_num].AddChild(port_num, new_device)

    match = _S_LINE_REGEX.match(line)
    if match:
      if bus_num == -1:
        raise ValueError('S line appears before T line in input file')
      # put the serial number in the device
      tree[bus_num].FindDeviceNumber(device_num).serial = match.group('serial')

  return tree


def GetHubsOnBus(bus, hub_types):
  """Scans for all hubs on a bus of given hub types.

  Args:
    bus: [USBNode] Bus object.
    hub_types: [iterable(usb_hubs.HubType)] Possible types of hubs.

  Yields:
    Sequence of tuples representing (hub, type of hub)
  """
  for device in bus.AllNodes():
    for hub_type in hub_types:
      if hub_type.IsType(device):
        yield (device, hub_type)


def GetPhysicalPortToNodeMap(hub, hub_type):
  """Gets physical-port:node mapping for a given hub.
  Args:
    hub: [USBNode] Hub to get map for.
    hub_type: [usb_hubs.HubType] Which type of hub it is.

  Returns:
    Dict of {physical port: node}
  """
  port_device = hub_type.GetPhysicalPortToNodeTuples(hub)
  return {port: device for (port, device) in port_device}


def GetPhysicalPortToBusDeviceMap(hub, hub_type):
  """Gets physical-port:(bus#, device#) mapping for a given hub.
  Args:
    hub: [USBNode] Hub to get map for.
    hub_type: [usb_hubs.HubType] Which type of hub it is.

  Returns:
    Dict of {physical port: (bus number, device number)}
  """
  port_device = hub_type.GetPhysicalPortToNodeTuples(hub)
  return {port: (device.bus_num, device.device_num)
          for (port, device) in port_device}


def GetPhysicalPortToSerialMap(hub, hub_type):
  """Gets physical-port:serial# mapping for a given hub.

  Args:
    hub: [USBNode] Hub to get map for.
    hub_type: [usb_hubs.HubType] Which type of hub it is.

  Returns:
    Dict of {physical port: serial number)}
  """
  port_device = hub_type.GetPhysicalPortToNodeTuples(hub)
  return {port: device.serial
          for (port, device) in port_device
          if device.serial}


def GetPhysicalPortToTTYMap(device, hub_type):
  """Gets physical-port:tty-string mapping for a given hub.
  Args:
    hub: [USBNode] Hub to get map for.
    hub_type: [usb_hubs.HubType] Which type of hub it is.

  Returns:
    Dict of {physical port: tty-string)}
  """
  port_device = hub_type.GetPhysicalPortToNodeTuples(device)
  bus_device_to_tty = GetBusDeviceToTTYMap()
  return {port: bus_device_to_tty[(device.bus_num, device.device_num)]
          for (port, device) in port_device
          if (device.bus_num, device.device_num) in bus_device_to_tty}


def CollectHubMaps(hub_types, map_func, device_tree_map=None, fast=False):
  """Runs a function on all hubs in the system and collects their output.

  Args:
    hub_types: [usb_hubs.HubType] List of possible hub types.
    map_func: [string] Function to run on each hub.
    device_tree: Previously constructed device tree map, if any.
    fast: Whether to construct device tree fast, if not already provided

  Yields:
    Sequence of dicts of {physical port: device} where the type of
    device depends on the ident keyword. Each dict is a separate hub.
  """
  if device_tree_map is None:
    device_tree_map = GetBusNumberToDeviceTreeMap(fast=fast)
  for bus in device_tree_map.values():
    for (hub, hub_type) in GetHubsOnBus(bus, hub_types):
      yield map_func(hub, hub_type)


def GetAllPhysicalPortToNodeMaps(hub_types, **kwargs):
  return CollectHubMaps(hub_types, GetPhysicalPortToNodeMap, **kwargs)


def GetAllPhysicalPortToBusDeviceMaps(hub_types, **kwargs):
  return CollectHubMaps(hub_types, GetPhysicalPortToBusDeviceMap, **kwargs)


def GetAllPhysicalPortToSerialMaps(hub_types, **kwargs):
  return CollectHubMaps(hub_types, GetPhysicalPortToSerialMap, **kwargs)


def GetAllPhysicalPortToTTYMaps(hub_types, **kwargs):
  return CollectHubMaps(hub_types, GetPhysicalPortToTTYMap, **kwargs)


_BUS_NUM_REGEX = re.compile(r'.*ATTRS{busnum}=="(\d*)".*')
_DEVICE_NUM_REGEX = re.compile(r'.*ATTRS{devnum}=="(\d*)".*')


def GetBusDeviceFromTTY(tty_string):
  """Gets bus and device number connected to a ttyUSB port.

  Args:
    tty_string: [String] Identifier for ttyUSB (e.g. 'ttyUSB0')

  Returns:
    Tuple (bus, device) giving device connected to that ttyUSB.

  Raises:
    ValueError: If bus and device information could not be found.
  """
  bus_num = None
  device_num = None
  # Expected output of GetCmdOutput should be something like:
  # looking at device /devices/something/.../.../...
  # KERNELS="ttyUSB0"
  # SUBSYSTEMS=...
  # DRIVERS=...
  # ATTRS{foo}=...
  # ATTRS{bar}=...
  # ...
  for line in _GetTtyUSBInfo(tty_string).splitlines():
    bus_match = _BUS_NUM_REGEX.match(line)
    device_match = _DEVICE_NUM_REGEX.match(line)
    if bus_match and bus_num == None:
      bus_num = int(bus_match.group(1))
    if device_match and device_num == None:
      device_num = int(device_match.group(1))
  if bus_num is None or device_num is None:
    raise ValueError('Info not found')
  return (bus_num, device_num)


def GetBusDeviceToTTYMap():
  """Gets all mappings from (bus, device) to ttyUSB string.

  Gets mapping from (bus, device) to ttyUSB string (e.g. 'ttyUSB0'),
  for all ttyUSB strings currently active.

  Returns:
    [dict] Dict that maps (bus, device) to ttyUSB string
  """
  result = {}
  for tty in GetTTYList():
    result[GetBusDeviceFromTTY(tty)] = tty
  return result


# This dictionary described the mapping between physical and
# virtual ports on a Plugable 7-Port Hub (model USB2-HUB7BC).
# Keys are the virtual ports, values are the physical port.
# The entry 4:{1:4, 2:3, 3:2, 4:1} indicates that virtual port
# 4 connects to another 'virtual' hub that itself has the
# virtual-to-physical port mapping {1:4, 2:3, 3:2, 4:1}.


def TestUSBTopologyScript():
  """Test display and hub identification."""
  # Identification criteria for Plugable 7-Port Hub
  print '==== USB TOPOLOGY SCRIPT TEST ===='

  # Display devices
  print '==== DEVICE DISPLAY ===='
  device_trees = GetBusNumberToDeviceTreeMap()
  for device_tree in device_trees.values():
    device_tree.Display()
  print

  # Display TTY information about devices plugged into hubs.
  print '==== TTY INFORMATION ===='
  for port_map in GetAllPhysicalPortToTTYMaps(
      usb_hubs.ALL_HUBS, device_tree_map=device_trees):
    print port_map
  print

  # Display serial number information about devices plugged into hubs.
  print '==== SERIAL NUMBER INFORMATION ===='
  for port_map in GetAllPhysicalPortToSerialMaps(
      usb_hubs.ALL_HUBS, device_tree_map=device_trees):
    print port_map


  return 0


def parse_options(argv):
  """Parses and checks the command-line options.

  Returns:
    A tuple containing the options structure and a list of categories to
    be traced.
  """
  USAGE = '''./find_usb_devices [--help]
    This script shows the mapping between USB devices and port numbers.
    Clients are not intended to call this script from the command line.
    Clients are intended to call the functions in this script directly.
    For instance, GetAllPhysicalPortToSerialMaps(...)
    Running this script with --help will display this message.
    Running this script without --help will display information about
    devices attached, TTY mapping, and serial number mapping,
    for testing purposes. See design document for API documentation.
  '''
  parser = argparse.ArgumentParser(usage=USAGE)
  return parser.parse_args(argv[1:])

def main():
  parse_options(sys.argv)
  TestUSBTopologyScript()

if __name__ == "__main__":
  sys.exit(main())
