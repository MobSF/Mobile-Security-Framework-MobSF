#!/usr/bin/env python

# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import sys

from devil.utils import battor_device_mapping

def parse_options():
  """Parses and checks the command-line options.

  Returns:
    A tuple containing the options structure.
  """
  usage = 'Usage: ./update_mapping.py [options]'
  desc = ('Example: ./update_mapping.py -o mapping.json.\n'
  'This script generates and stores a file that gives the\n'
  'mapping between phone serial numbers and BattOr serial numbers\n'
  'Mapping is based on which physical ports on the USB hubs the\n'
  'devices are plugged in to. For instance, if there are two hubs,\n'
  'the phone connected to port N on the first hub is mapped to the\n'
  'BattOr connected to port N on the second hub, for each N.')
  parser = argparse.ArgumentParser(usage=usage, description=desc)
  parser.add_argument('-o', '--output', dest='out_file',
                      default='mapping.json', type=str,
                      action='store', help='mapping file name')
  parser.add_argument('-u', '--hub', dest='hub_types',
                      action='append', choices=['plugable_7port',
                                                'plugable_7port_usb3_part2',
                                                'plugable_7port_usb3_part3'],
                      help='USB hub types.')
  options = parser.parse_args()
  if not options.hub_types:
    options.hub_types = ['plugable_7port', 'plugable_7port_usb3_part2',
                         'plugable_7port_usb3_part3']
  return options

def main():
  options = parse_options()
  battor_device_mapping.GenerateSerialMapFile(options.out_file,
                                              options.hub_types)

if __name__ == "__main__":
  sys.exit(main())
