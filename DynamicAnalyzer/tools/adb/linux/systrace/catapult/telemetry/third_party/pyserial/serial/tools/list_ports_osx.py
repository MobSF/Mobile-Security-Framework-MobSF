#!/usr/bin/env python

# portable serial port access with python
#
# This is a module that gathers a list of serial ports including details on OSX
#
# code originally from https://github.com/makerbot/pyserial/tree/master/serial/tools
# with contributions from cibomahto, dgs3, FarMcKon, tedbrandston
# and modifications by cliechti
#
# this is distributed under a free software license, see license.txt



# List all of the callout devices in OS/X by querying IOKit.

# See the following for a reference of how to do this:
# http://developer.apple.com/library/mac/#documentation/DeviceDrivers/Conceptual/WorkingWSerial/WWSerial_SerialDevs/SerialDevices.html#//apple_ref/doc/uid/TP30000384-CIHGEAFD

# More help from darwin_hid.py

# Also see the 'IORegistryExplorer' for an idea of what we are actually searching

import ctypes
from ctypes import util
import re

iokit = ctypes.cdll.LoadLibrary(ctypes.util.find_library('IOKit'))
cf = ctypes.cdll.LoadLibrary(ctypes.util.find_library('CoreFoundation'))

kIOMasterPortDefault = ctypes.c_void_p.in_dll(iokit, "kIOMasterPortDefault")
kCFAllocatorDefault = ctypes.c_void_p.in_dll(cf, "kCFAllocatorDefault")

kCFStringEncodingMacRoman = 0

iokit.IOServiceMatching.restype = ctypes.c_void_p

iokit.IOServiceGetMatchingServices.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
iokit.IOServiceGetMatchingServices.restype = ctypes.c_void_p

iokit.IORegistryEntryGetParentEntry.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

iokit.IORegistryEntryCreateCFProperty.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32]
iokit.IORegistryEntryCreateCFProperty.restype = ctypes.c_void_p

iokit.IORegistryEntryGetPath.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
iokit.IORegistryEntryGetPath.restype = ctypes.c_void_p

iokit.IORegistryEntryGetName.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
iokit.IORegistryEntryGetName.restype = ctypes.c_void_p

iokit.IOObjectGetClass.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
iokit.IOObjectGetClass.restype = ctypes.c_void_p

iokit.IOObjectRelease.argtypes = [ctypes.c_void_p]


cf.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int32]
cf.CFStringCreateWithCString.restype = ctypes.c_void_p

cf.CFStringGetCStringPtr.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
cf.CFStringGetCStringPtr.restype = ctypes.c_char_p

cf.CFNumberGetValue.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
cf.CFNumberGetValue.restype = ctypes.c_void_p

def get_string_property(device_t, property):
    """ Search the given device for the specified string property

    @param device_t Device to search
    @param property String to search for.
    @return Python string containing the value, or None if not found.
    """
    key = cf.CFStringCreateWithCString(
        kCFAllocatorDefault,
        property.encode("mac_roman"),
        kCFStringEncodingMacRoman
    )

    CFContainer = iokit.IORegistryEntryCreateCFProperty(
        device_t,
        key,
        kCFAllocatorDefault,
        0
    );

    output = None

    if CFContainer:
        output = cf.CFStringGetCStringPtr(CFContainer, 0)

    return output

def get_int_property(device_t, property):
    """ Search the given device for the specified string property

    @param device_t Device to search
    @param property String to search for.
    @return Python string containing the value, or None if not found.
    """
    key = cf.CFStringCreateWithCString(
        kCFAllocatorDefault,
        property.encode("mac_roman"),
        kCFStringEncodingMacRoman
    )

    CFContainer = iokit.IORegistryEntryCreateCFProperty(
        device_t,
        key,
        kCFAllocatorDefault,
        0
    );

    number = ctypes.c_uint16()

    if CFContainer:
        output = cf.CFNumberGetValue(CFContainer, 2, ctypes.byref(number))

    return number.value

def IORegistryEntryGetName(device):
    pathname = ctypes.create_string_buffer(100) # TODO: Is this ok?
    iokit.IOObjectGetClass(
        device,
        ctypes.byref(pathname)
    )

    return pathname.value

def GetParentDeviceByType(device, parent_type):
    """ Find the first parent of a device that implements the parent_type
        @param IOService Service to inspect
        @return Pointer to the parent type, or None if it was not found.
    """
    # First, try to walk up the IOService tree to find a parent of this device that is a IOUSBDevice.
    while IORegistryEntryGetName(device) != parent_type:
        parent = ctypes.c_void_p()
        response = iokit.IORegistryEntryGetParentEntry(
            device,
            "IOService".encode("mac_roman"),
            ctypes.byref(parent)
        )

        # If we weren't able to find a parent for the device, we're done.
        if response != 0:
            return None

        device = parent

    return device

def GetIOServicesByType(service_type):
    """
    """
    serial_port_iterator = ctypes.c_void_p()

    response = iokit.IOServiceGetMatchingServices(
        kIOMasterPortDefault,
        iokit.IOServiceMatching(service_type),
        ctypes.byref(serial_port_iterator)
    )

    services = []
    while iokit.IOIteratorIsValid(serial_port_iterator):
        service = iokit.IOIteratorNext(serial_port_iterator)
        if not service:
            break
        services.append(service)

    iokit.IOObjectRelease(serial_port_iterator)

    return services

def comports():
    # Scan for all iokit serial ports
    services = GetIOServicesByType('IOSerialBSDClient')

    ports = []
    for service in services:
        info = []

        # First, add the callout device file.
        info.append(get_string_property(service, "IOCalloutDevice"))

        # If the serial port is implemented by a
        usb_device = GetParentDeviceByType(service, "IOUSBDevice")
        if usb_device != None:
            info.append(get_string_property(usb_device, "USB Product Name"))

            info.append(
                "USB VID:PID=%x:%x SNR=%s"%(
                get_int_property(usb_device, "idVendor"),
                get_int_property(usb_device, "idProduct"),
                get_string_property(usb_device, "USB Serial Number"))
            )
        else:
           info.append('n/a')
           info.append('n/a')

        ports.append(info)

    return ports

# test
if __name__ == '__main__':
    for port, desc, hwid in sorted(comports()):
        print "%s: %s [%s]" % (port, desc, hwid)

