#!/usr/bin/env python

# portable serial port access with python
#
# This is a module that gathers a list of serial ports including details on
# GNU/Linux systems
#
# (C) 2011-2013 Chris Liechti <cliechti@gmx.net>
# this is distributed under a free software license, see license.txt

import glob
import sys
import os
import re

try:
    import subprocess
except ImportError:
    def popen(argv):
        try:
            si, so =  os.popen4(' '.join(argv))
            return so.read().strip()
        except:
            raise IOError('lsusb failed')
else:
    def popen(argv):
        try:
            return subprocess.check_output(argv, stderr=subprocess.STDOUT).strip()
        except:
            raise IOError('lsusb failed')


# The comports function is expected to return an iterable that yields tuples of
# 3 strings: port name, human readable description and a hardware ID.
#
# as currently no method is known to get the second two strings easily, they
# are currently just identical to the port name.

# try to detect the OS so that a device can be selected...
plat = sys.platform.lower()

def read_line(filename):
    """help function to read a single line from a file. returns none"""
    try:
        f = open(filename)
        line = f.readline().strip()
        f.close()
        return line
    except IOError:
        return None

def re_group(regexp, text):
    """search for regexp in text, return 1st group on match"""
    if sys.version < '3':
        m = re.search(regexp, text)
    else:
        # text is bytes-like
        m = re.search(regexp, text.decode('ascii', 'replace'))
    if m: return m.group(1)


# try to extract descriptions from sysfs. this was done by experimenting,
# no guarantee that it works for all devices or in the future...

def usb_sysfs_hw_string(sysfs_path):
    """given a path to a usb device in sysfs, return a string describing it"""
    bus, dev = os.path.basename(os.path.realpath(sysfs_path)).split('-')
    snr = read_line(sysfs_path+'/serial')
    if snr:
        snr_txt = ' SNR=%s' % (snr,)
    else:
        snr_txt = ''
    return 'USB VID:PID=%s:%s%s' % (
            read_line(sysfs_path+'/idVendor'),
            read_line(sysfs_path+'/idProduct'),
            snr_txt
            )

def usb_lsusb_string(sysfs_path):
    base = os.path.basename(os.path.realpath(sysfs_path))
    bus = base.split('-')[0]
    try:
        dev = int(read_line(os.path.join(sysfs_path, 'devnum')))
        desc = popen(['lsusb', '-v', '-s', '%s:%s' % (bus, dev)])
        # descriptions from device
        iManufacturer = re_group('iManufacturer\s+\w+ (.+)', desc)
        iProduct = re_group('iProduct\s+\w+ (.+)', desc)
        iSerial = re_group('iSerial\s+\w+ (.+)', desc) or ''
        # descriptions from kernel
        idVendor = re_group('idVendor\s+0x\w+ (.+)', desc)
        idProduct = re_group('idProduct\s+0x\w+ (.+)', desc)
        # create descriptions. prefer text from device, fall back to the others
        return '%s %s %s' % (iManufacturer or idVendor, iProduct or idProduct, iSerial)
    except IOError:
        return base

def describe(device):
    """\
    Get a human readable description.
    For USB-Serial devices try to run lsusb to get a human readable description.
    For USB-CDC devices read the description from sysfs.
    """
    base = os.path.basename(device)
    # USB-Serial devices
    sys_dev_path = '/sys/class/tty/%s/device/driver/%s' % (base, base)
    if os.path.exists(sys_dev_path):
        sys_usb = os.path.dirname(os.path.dirname(os.path.realpath(sys_dev_path)))
        return usb_lsusb_string(sys_usb)
    # USB-CDC devices
    sys_dev_path = '/sys/class/tty/%s/device/interface' % (base,)
    if os.path.exists(sys_dev_path):
        return read_line(sys_dev_path)

    # USB Product Information
    sys_dev_path = '/sys/class/tty/%s/device' % (base,)
    if os.path.exists(sys_dev_path):
        product_name_file = os.path.dirname(os.path.realpath(sys_dev_path)) + "/product"
        if os.path.exists(product_name_file):
            return read_line(product_name_file)

    return base

def hwinfo(device):
    """Try to get a HW identification using sysfs"""
    base = os.path.basename(device)
    if os.path.exists('/sys/class/tty/%s/device' % (base,)):
        # PCI based devices
        sys_id_path = '/sys/class/tty/%s/device/id' % (base,)
        if os.path.exists(sys_id_path):
            return read_line(sys_id_path)
        # USB-Serial devices
        sys_dev_path = '/sys/class/tty/%s/device/driver/%s' % (base, base)
        if os.path.exists(sys_dev_path):
            sys_usb = os.path.dirname(os.path.dirname(os.path.realpath(sys_dev_path)))
            return usb_sysfs_hw_string(sys_usb)
        # USB-CDC devices
        if base.startswith('ttyACM'):
            sys_dev_path = '/sys/class/tty/%s/device' % (base,)
            if os.path.exists(sys_dev_path):
                return usb_sysfs_hw_string(sys_dev_path + '/..')
    return 'n/a'    # XXX directly remove these from the list?

def comports():
    devices = glob.glob('/dev/ttyS*') + glob.glob('/dev/ttyUSB*') + glob.glob('/dev/ttyACM*')
    return [(d, describe(d), hwinfo(d)) for d in devices]

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# test
if __name__ == '__main__':
    for port, desc, hwid in sorted(comports()):
        print "%s: %s [%s]" % (port, desc, hwid)
