import ctypes
import re

def ValidHandle(value, func, arguments):
    if value == 0:
        raise ctypes.WinError()
    return value

import serial
from serial.win32 import ULONG_PTR, is_64bit
from ctypes.wintypes import HANDLE
from ctypes.wintypes import BOOL
from ctypes.wintypes import HWND
from ctypes.wintypes import DWORD
from ctypes.wintypes import WORD
from ctypes.wintypes import LONG
from ctypes.wintypes import ULONG
from ctypes.wintypes import LPCSTR
from ctypes.wintypes import HKEY
from ctypes.wintypes import BYTE

NULL = 0
HDEVINFO = ctypes.c_void_p
PCTSTR = ctypes.c_char_p
PTSTR = ctypes.c_void_p
CHAR = ctypes.c_char
LPDWORD = PDWORD = ctypes.POINTER(DWORD)
#~ LPBYTE = PBYTE = ctypes.POINTER(BYTE)
LPBYTE = PBYTE = ctypes.c_void_p        # XXX avoids error about types

ACCESS_MASK = DWORD
REGSAM = ACCESS_MASK


def byte_buffer(length):
    """Get a buffer for a string"""
    return (BYTE*length)()

def string(buffer):
    s = []
    for c in buffer:
        if c == 0: break
        s.append(chr(c & 0xff)) # "& 0xff": hack to convert signed to unsigned
    return ''.join(s)


class GUID(ctypes.Structure):
    _fields_ = [
        ('Data1', DWORD),
        ('Data2', WORD),
        ('Data3', WORD),
        ('Data4', BYTE*8),
    ]
    def __str__(self):
        return "{%08x-%04x-%04x-%s-%s}" % (
            self.Data1,
            self.Data2,
            self.Data3,
            ''.join(["%02x" % d for d in self.Data4[:2]]),
            ''.join(["%02x" % d for d in self.Data4[2:]]),
        )

class SP_DEVINFO_DATA(ctypes.Structure):
    _fields_ = [
        ('cbSize', DWORD),
        ('ClassGuid', GUID),
        ('DevInst', DWORD),
        ('Reserved', ULONG_PTR),
    ]
    def __str__(self):
        return "ClassGuid:%s DevInst:%s" % (self.ClassGuid, self.DevInst)
PSP_DEVINFO_DATA = ctypes.POINTER(SP_DEVINFO_DATA)

PSP_DEVICE_INTERFACE_DETAIL_DATA = ctypes.c_void_p

setupapi = ctypes.windll.LoadLibrary("setupapi")
SetupDiDestroyDeviceInfoList = setupapi.SetupDiDestroyDeviceInfoList
SetupDiDestroyDeviceInfoList.argtypes = [HDEVINFO]
SetupDiDestroyDeviceInfoList.restype = BOOL

SetupDiClassGuidsFromName = setupapi.SetupDiClassGuidsFromNameA
SetupDiClassGuidsFromName.argtypes = [PCTSTR, ctypes.POINTER(GUID), DWORD, PDWORD]
SetupDiClassGuidsFromName.restype = BOOL

SetupDiEnumDeviceInfo = setupapi.SetupDiEnumDeviceInfo
SetupDiEnumDeviceInfo.argtypes = [HDEVINFO, DWORD, PSP_DEVINFO_DATA]
SetupDiEnumDeviceInfo.restype = BOOL

SetupDiGetClassDevs = setupapi.SetupDiGetClassDevsA
SetupDiGetClassDevs.argtypes = [ctypes.POINTER(GUID), PCTSTR, HWND, DWORD]
SetupDiGetClassDevs.restype = HDEVINFO
SetupDiGetClassDevs.errcheck = ValidHandle

SetupDiGetDeviceRegistryProperty = setupapi.SetupDiGetDeviceRegistryPropertyA
SetupDiGetDeviceRegistryProperty.argtypes = [HDEVINFO, PSP_DEVINFO_DATA, DWORD, PDWORD, PBYTE, DWORD, PDWORD]
SetupDiGetDeviceRegistryProperty.restype = BOOL

SetupDiGetDeviceInstanceId = setupapi.SetupDiGetDeviceInstanceIdA
SetupDiGetDeviceInstanceId.argtypes = [HDEVINFO, PSP_DEVINFO_DATA, PTSTR, DWORD, PDWORD]
SetupDiGetDeviceInstanceId.restype = BOOL

SetupDiOpenDevRegKey = setupapi.SetupDiOpenDevRegKey
SetupDiOpenDevRegKey.argtypes = [HDEVINFO, PSP_DEVINFO_DATA, DWORD, DWORD, DWORD, REGSAM]
SetupDiOpenDevRegKey.restype = HKEY

advapi32 = ctypes.windll.LoadLibrary("Advapi32")
RegCloseKey = advapi32.RegCloseKey
RegCloseKey.argtypes = [HKEY]
RegCloseKey.restype = LONG

RegQueryValueEx = advapi32.RegQueryValueExA
RegQueryValueEx.argtypes = [HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD]
RegQueryValueEx.restype = LONG


DIGCF_PRESENT = 2
DIGCF_DEVICEINTERFACE = 16
INVALID_HANDLE_VALUE = 0
ERROR_INSUFFICIENT_BUFFER = 122
SPDRP_HARDWAREID = 1
SPDRP_FRIENDLYNAME = 12
DICS_FLAG_GLOBAL = 1
DIREG_DEV = 0x00000001
KEY_READ = 0x20019

# workaround for compatibility between Python 2.x and 3.x
Ports = serial.to_bytes([80, 111, 114, 116, 115]) # "Ports"
PortName = serial.to_bytes([80, 111, 114, 116, 78, 97, 109, 101]) # "PortName"

def comports():
    GUIDs = (GUID*8)() # so far only seen one used, so hope 8 are enough...
    guids_size = DWORD()
    if not SetupDiClassGuidsFromName(
            Ports,
            GUIDs,
            ctypes.sizeof(GUIDs),
            ctypes.byref(guids_size)):
        raise ctypes.WinError()

    # repeat for all possible GUIDs
    for index in range(guids_size.value):
        g_hdi = SetupDiGetClassDevs(
                ctypes.byref(GUIDs[index]),
                None,
                NULL,
                DIGCF_PRESENT) # was DIGCF_PRESENT|DIGCF_DEVICEINTERFACE which misses CDC ports

        devinfo = SP_DEVINFO_DATA()
        devinfo.cbSize = ctypes.sizeof(devinfo)
        index = 0
        while SetupDiEnumDeviceInfo(g_hdi, index, ctypes.byref(devinfo)):
            index += 1

            # get the real com port name
            hkey = SetupDiOpenDevRegKey(
                    g_hdi,
                    ctypes.byref(devinfo),
                    DICS_FLAG_GLOBAL,
                    0,
                    DIREG_DEV,  # DIREG_DRV for SW info
                    KEY_READ)
            port_name_buffer = byte_buffer(250)
            port_name_length = ULONG(ctypes.sizeof(port_name_buffer))
            RegQueryValueEx(
                    hkey,
                    PortName,
                    None,
                    None,
                    ctypes.byref(port_name_buffer),
                    ctypes.byref(port_name_length))
            RegCloseKey(hkey)

            # unfortunately does this method also include parallel ports.
            # we could check for names starting with COM or just exclude LPT
            # and hope that other "unknown" names are serial ports...
            if string(port_name_buffer).startswith('LPT'):
                continue

            # hardware ID
            szHardwareID = byte_buffer(250)
            # try to get ID that includes serial number
            if not SetupDiGetDeviceInstanceId(
                    g_hdi,
                    ctypes.byref(devinfo),
                    ctypes.byref(szHardwareID),
                    ctypes.sizeof(szHardwareID) - 1,
                    None):
                # fall back to more generic hardware ID if that would fail
                if not SetupDiGetDeviceRegistryProperty(
                        g_hdi,
                        ctypes.byref(devinfo),
                        SPDRP_HARDWAREID,
                        None,
                        ctypes.byref(szHardwareID),
                        ctypes.sizeof(szHardwareID) - 1,
                        None):
                    # Ignore ERROR_INSUFFICIENT_BUFFER
                    if ctypes.GetLastError() != ERROR_INSUFFICIENT_BUFFER:
                        raise ctypes.WinError()
            # stringify
            szHardwareID_str = string(szHardwareID)

            # in case of USB, make a more readable string, similar to that form
            # that we also generate on other platforms
            if szHardwareID_str.startswith('USB'):
                m = re.search(r'VID_([0-9a-f]{4})&PID_([0-9a-f]{4})(\\(\w+))?', szHardwareID_str, re.I)
                if m:
                    if m.group(4):
                        szHardwareID_str = 'USB VID:PID=%s:%s SNR=%s' % (m.group(1), m.group(2), m.group(4))
                    else:
                        szHardwareID_str = 'USB VID:PID=%s:%s' % (m.group(1), m.group(2))

            # friendly name
            szFriendlyName = byte_buffer(250)
            if not SetupDiGetDeviceRegistryProperty(
                    g_hdi,
                    ctypes.byref(devinfo),
                    SPDRP_FRIENDLYNAME,
                    #~ SPDRP_DEVICEDESC,
                    None,
                    ctypes.byref(szFriendlyName),
                    ctypes.sizeof(szFriendlyName) - 1,
                    None):
                # Ignore ERROR_INSUFFICIENT_BUFFER
                #~ if ctypes.GetLastError() != ERROR_INSUFFICIENT_BUFFER:
                    #~ raise IOError("failed to get details for %s (%s)" % (devinfo, szHardwareID.value))
                # ignore errors and still include the port in the list, friendly name will be same as port name
                yield string(port_name_buffer), 'n/a', szHardwareID_str
            else:
                yield string(port_name_buffer), string(szFriendlyName), szHardwareID_str

        SetupDiDestroyDeviceInfoList(g_hdi)

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# test
if __name__ == '__main__':
    import serial

    for port, desc, hwid in sorted(comports()):
        print "%s: %s [%s]" % (port, desc, hwid)
