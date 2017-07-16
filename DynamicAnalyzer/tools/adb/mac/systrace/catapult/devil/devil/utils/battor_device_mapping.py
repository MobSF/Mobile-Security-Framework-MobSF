#!/usr/bin/python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


'''
This script provides tools to map BattOrs to phones.

Phones are identified by the following string:

"Phone serial number" - Serial number of the phone. This can be
obtained via 'adb devices' or 'usb-devices', and is not expected
to change for a given phone.

BattOrs are identified by the following two strings:

"BattOr serial number" - Serial number of the BattOr. This can be
obtained via 'usb-devices', and is not expected to change for
a given BattOr.

"BattOr path" - The path of the form '/dev/ttyUSB*' that is used
to communicate with the BattOr (the battor_agent binary takes
this BattOr path as a parameter). The BattOr path is frequently
reassigned by the OS, most often when the device is disconnected
and then reconnected. Thus, the BattOr path cannot be expected
to be stable.

In a typical application, the user will require the BattOr path
for the BattOr that is plugged into a given phone. For instance,
the user will be running tracing on a particular phone, and will
need to know which BattOr path to use to communicate with the BattOr
to get the corresponding power trace.

Getting this mapping requires two steps: (1) determining the
mapping between phone serial numbers and BattOr serial numbers, and
(2) getting the BattOr path corresponding to a given BattOr serial
number.

For step (1), we generate a JSON file giving this mapping. This
JSON file consists of a list of items of the following form:
[{'phone': <phone serial 1>, 'battor': <battor serial 1>},
{'phone': <phone serial 2>, 'battor': <battor serial 2>}, ...]

The default way to generate this JSON file is using the function
GenerateSerialMapFile, which generates a mapping based on assuming
that the system has two identical USB hubs connected to it, and
the phone plugged into physical port number 1 on one hub corresponds
to the BattOr plugged into physical port number 1 on the other hub,
and similarly with physical port numbers 2, 3, etc. This generates
the map file based on the structure at the time GenerateSerialMapFile called.
Note that after the map file is generated, port numbers are no longer used;
the user could move around the devices in the ports without affecting
which phone goes with which BattOr. (Thus, if the user wanted to update the
mapping to match the new port connections, the user would have to
re-generate this file.)

The script update_mapping.py will do this updating from the command line.

If the user wanted to specify a custom mapping, the user could instead
create the JSON file manually. (In this case, hubs would not be necessary
and the physical ports connected would be irrelevant.)

Step (2) is conducted through the function GetBattOrPathFromPhoneSerial,
which takes a serial number mapping generated via step (1) and a phone
serial number, then gets the corresponding BattOr serial number from the
map and determines its BattOr path (e.g. /dev/ttyUSB0). Since BattOr paths
can change if devices are connected and disconnected (even if connected
or disconnected via the same port) this function should be called to
determine the BattOr path every time before connecting to the BattOr.

Note that if there is only one BattOr connected to the system, then
GetBattOrPathFromPhoneSerial will always return that BattOr and will ignore
the mapping file. Thus, if the user never has more than one BattOr connected
to the system, the user will not need to generate mapping files.
'''


import json
import collections

from battor import battor_error
from devil.utils import find_usb_devices
from devil.utils import usb_hubs


def GetBattOrList(device_tree_map):
  return [x for x in find_usb_devices.GetTTYList()
          if IsBattOr(x, device_tree_map)]


def IsBattOr(tty_string, device_tree_map):
  (bus, device) = find_usb_devices.GetBusDeviceFromTTY(tty_string)
  node = device_tree_map[bus].FindDeviceNumber(device)
  return '0403:6001' in node.desc


def GetBattOrSerialNumbers(device_tree_map):
  for x in find_usb_devices.GetTTYList():
    if IsBattOr(x, device_tree_map):
      (bus, device) = find_usb_devices.GetBusDeviceFromTTY(x)
      devnode = device_tree_map[bus].FindDeviceNumber(device)
      yield devnode.serial


def ReadSerialMapFile(filename):
  """Reads JSON file giving phone-to-battor serial number map.

  Parses a JSON file consisting of a list of items of the following form:
  [{'phone': <phone serial 1>, 'battor': <battor serial 1>},
  {'phone': <phone serial 2>, 'battor': <battor serial 2>}, ...]

  indicating which phone serial numbers should be matched with
  which BattOr serial numbers. Returns dictionary of the form:

  {<phone serial 1>: <BattOr serial 1>,
   <phone serial 2>: <BattOr serial 2>}

  Args:
      filename: Name of file to read.
  """
  result = {}
  with open(filename, 'r') as infile:
    in_dict = json.load(infile)
  for x in in_dict:
    result[x['phone']] = x['battor']
  return result

def WriteSerialMapFile(filename, serial_map):
  """Writes a map of phone serial numbers to BattOr serial numbers to file.

  Writes a JSON file consisting of a list of items of the following form:
  [{'phone': <phone serial 1>, 'battor': <battor serial 1>},
  {'phone': <phone serial 2>, 'battor': <battor serial 2>}, ...]

  indicating which phone serial numbers should be matched with
  which BattOr serial numbers. Mapping is based on the physical port numbers
  of the hubs that the BattOrs and phones are connected to.

  Args:
      filename: Name of file to write.
      serial_map: Serial map {phone: battor}
  """
  result = []
  for (phone, battor) in serial_map.iteritems():
    result.append({'phone': phone, 'battor': battor})
  with open(filename, 'w') as outfile:
    json.dump(result, outfile)

def GenerateSerialMap(hub_types=None):
  """Generates a map of phone serial numbers to BattOr serial numbers.

  Generates a dict of:
  {<phone serial 1>: <battor serial 1>,
   <phone serial 2>: <battor serial 2>}
  indicating which phone serial numbers should be matched with
  which BattOr serial numbers. Mapping is based on the physical port numbers
  of the hubs that the BattOrs and phones are connected to.

  Args:
      hub_types: List of hub types to check for. If not specified, checks
      for all defined hub types. (see usb_hubs.py for details)
  """
  if hub_types:
    hub_types = [usb_hubs.GetHubType(x) for x in hub_types]
  else:
    hub_types = usb_hubs.ALL_HUBS

  devtree = find_usb_devices.GetBusNumberToDeviceTreeMap()

  # List of serial numbers in the system that represent BattOrs.
  battor_serials = list(GetBattOrSerialNumbers(devtree))

  # If there's only one BattOr in the system, then a serial number ma
  # is not necessary.
  if len(battor_serials) == 1:
    return {}

  # List of dictionaries, one for each hub, that maps the physical
  # port number to the serial number of that hub. For instance, in a 2
  # hub system, this could return [{1:'ab', 2:'cd'}, {1:'jkl', 2:'xyz'}]
  # where 'ab' and 'cd' are the phone serial numbers and 'jkl' and 'xyz'
  # are the BattOr serial numbers.
  port_to_serial = find_usb_devices.GetAllPhysicalPortToSerialMaps(
      hub_types, device_tree_map=devtree)

  class serials(object):
    def __init__(self):
      self.phone = None
      self.battor = None

  # Map of {physical port number: [phone serial #, BattOr serial #]. This
  # map is populated by executing the code below. For instance, in the above
  # example, after the code below is executed, port_to_devices would equal
  # {1: ['ab', 'jkl'], 2: ['cd', 'xyz']}
  port_to_devices = collections.defaultdict(serials)
  for hub in port_to_serial:
    for (port, serial) in hub.iteritems():
      if serial in battor_serials:
        if port_to_devices[port].battor is not None:
          raise battor_error.BattOrError('Multiple BattOrs on same port number')
        else:
          port_to_devices[port].battor = serial
      else:
        if port_to_devices[port].phone is not None:
          raise battor_error.BattOrError('Multiple phones on same port number')
        else:
          port_to_devices[port].phone = serial

  # Turn the port_to_devices map into a map of the form
  # {phone serial number: BattOr serial number}.
  result = {}
  for pair in port_to_devices.values():
    if pair.phone is None:
      continue
    if pair.battor is None:
      raise battor_error.BattOrError(
          'Phone detected with no corresponding BattOr')
    result[pair.phone] = pair.battor
  return result

def GenerateSerialMapFile(filename, hub_types=None):
  """Generates a serial map file and writes it."""
  WriteSerialMapFile(filename, GenerateSerialMap(hub_types))

def _PhoneToPathMap(serial, serial_map, devtree):
  """Maps phone serial number to TTY path, assuming serial map is provided."""
  try:
    battor_serial = serial_map[serial]
  except KeyError:
    raise battor_error.BattOrError('Serial number not found in serial map.')
  for tree in devtree.values():
    for node in tree.AllNodes():
      if isinstance(node, find_usb_devices.USBDeviceNode):
        if node.serial == battor_serial:
          bus_device_to_tty = find_usb_devices.GetBusDeviceToTTYMap()
          bus_device = (node.bus_num, node.device_num)
          try:
            return bus_device_to_tty[bus_device]
          except KeyError:
            raise battor_error.BattOrError(
                'Device with given serial number not a BattOr '
                '(does not have TTY path)')


def GetBattOrPathFromPhoneSerial(serial, serial_map=None,
                                 serial_map_file=None):
  """Gets the TTY path (e.g. '/dev/ttyUSB0')  to communicate with the BattOr.

  (1) If serial_map is given, it is treated as a dictionary mapping
  phone serial numbers to BattOr serial numbers. This function will get the
  TTY path for the given BattOr serial number.

  (2) If serial_map_file is given, it is treated as the name of a
  phone-to-BattOr mapping file (generated with GenerateSerialMapFile)
  and this will be loaded and used as the dict to map port numbers to
  BattOr serial numbers.

  You can only give one of serial_map and serial_map_file.

  Args:
    serial: Serial number of phone connected on the same physical port that
    the BattOr is connected to.
    serial_map: Map of phone serial numbers to BattOr serial numbers, given
    as a dictionary.
    serial_map_file: Map of phone serial numbers to BattOr serial numbers,
    given as a file.
    hub_types: List of hub types to check for. Used only if serial_map_file
    is None.

  Returns:
    Device string used to communicate with device.

  Raises:
    ValueError: If serial number is not given.
    BattOrError: If BattOr not found or unexpected USB topology.
  """
  # If there's only one BattOr connected to the system, just use that one.
  # This allows for use on, e.g., a developer's workstation with no hubs.
  devtree = find_usb_devices.GetBusNumberToDeviceTreeMap()
  all_battors = GetBattOrList(devtree)
  if len(all_battors) == 1:
    return '/dev/' + all_battors[0]

  if not serial:
    raise battor_error.BattOrError(
        'Two or more BattOrs connected, no serial provided')

  if serial_map and serial_map_file:
    raise ValueError('Cannot specify both serial_map and serial_map_file')

  if serial_map_file:
    serial_map = ReadSerialMapFile(serial_map_file)

  tty_string = _PhoneToPathMap(serial, serial_map, devtree)

  if not tty_string:
    raise battor_error.BattOrError(
        'No device with given serial number detected.')

  if IsBattOr(tty_string, devtree):
    return '/dev/' + tty_string
  else:
    raise battor_error.BattOrError(
        'Device with given serial number is not a BattOr.')

if __name__ == '__main__':
  # Main function for testing purposes
  print GenerateSerialMap()
