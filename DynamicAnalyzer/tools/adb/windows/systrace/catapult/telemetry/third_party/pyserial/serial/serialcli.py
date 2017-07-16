#! python
# Python Serial Port Extension for Win32, Linux, BSD, Jython and .NET/Mono
# serial driver for .NET/Mono (IronPython), .NET >= 2
# see __init__.py
#
# (C) 2008 Chris Liechti <cliechti@gmx.net>
# this is distributed under a free software license, see license.txt

import clr
import System
import System.IO.Ports
from serial.serialutil import *


def device(portnum):
    """Turn a port number into a device name"""
    return System.IO.Ports.SerialPort.GetPortNames()[portnum]


# must invoke function with byte array, make a helper to convert strings
# to byte arrays
sab = System.Array[System.Byte]
def as_byte_array(string):
    return sab([ord(x) for x in string])  # XXX will require adaption when run with a 3.x compatible IronPython

class IronSerial(SerialBase):
    """Serial port implementation for .NET/Mono."""

    BAUDRATES = (50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800,
                9600, 19200, 38400, 57600, 115200)

    def open(self):
        """Open port with current settings. This may throw a SerialException
           if the port cannot be opened."""
        if self._port is None:
            raise SerialException("Port must be configured before it can be used.")
        if self._isOpen:
            raise SerialException("Port is already open.")
        try:
            self._port_handle = System.IO.Ports.SerialPort(self.portstr)
        except Exception, msg:
            self._port_handle = None
            raise SerialException("could not open port %s: %s" % (self.portstr, msg))

        self._reconfigurePort()
        self._port_handle.Open()
        self._isOpen = True
        if not self._rtscts:
            self.setRTS(True)
            self.setDTR(True)
        self.flushInput()
        self.flushOutput()

    def _reconfigurePort(self):
        """Set communication parameters on opened port."""
        if not self._port_handle:
            raise SerialException("Can only operate on a valid port handle")

        #~ self._port_handle.ReceivedBytesThreshold = 1

        if self._timeout is None:
            self._port_handle.ReadTimeout = System.IO.Ports.SerialPort.InfiniteTimeout
        else:
            self._port_handle.ReadTimeout = int(self._timeout*1000)

        # if self._timeout != 0 and self._interCharTimeout is not None:
            # timeouts = (int(self._interCharTimeout * 1000),) + timeouts[1:]

        if self._writeTimeout is None:
            self._port_handle.WriteTimeout = System.IO.Ports.SerialPort.InfiniteTimeout
        else:
            self._port_handle.WriteTimeout = int(self._writeTimeout*1000)


        # Setup the connection info.
        try:
            self._port_handle.BaudRate = self._baudrate
        except IOError, e:
            # catch errors from illegal baudrate settings
            raise ValueError(str(e))

        if self._bytesize == FIVEBITS:
            self._port_handle.DataBits     = 5
        elif self._bytesize == SIXBITS:
            self._port_handle.DataBits     = 6
        elif self._bytesize == SEVENBITS:
            self._port_handle.DataBits     = 7
        elif self._bytesize == EIGHTBITS:
            self._port_handle.DataBits     = 8
        else:
            raise ValueError("Unsupported number of data bits: %r" % self._bytesize)

        if self._parity == PARITY_NONE:
            self._port_handle.Parity       = getattr(System.IO.Ports.Parity, 'None') # reserved keyword in Py3k
        elif self._parity == PARITY_EVEN:
            self._port_handle.Parity       = System.IO.Ports.Parity.Even
        elif self._parity == PARITY_ODD:
            self._port_handle.Parity       = System.IO.Ports.Parity.Odd
        elif self._parity == PARITY_MARK:
            self._port_handle.Parity       = System.IO.Ports.Parity.Mark
        elif self._parity == PARITY_SPACE:
            self._port_handle.Parity       = System.IO.Ports.Parity.Space
        else:
            raise ValueError("Unsupported parity mode: %r" % self._parity)

        if self._stopbits == STOPBITS_ONE:
            self._port_handle.StopBits     = System.IO.Ports.StopBits.One
        elif self._stopbits == STOPBITS_ONE_POINT_FIVE:
            self._port_handle.StopBits     = System.IO.Ports.StopBits.OnePointFive
        elif self._stopbits == STOPBITS_TWO:
            self._port_handle.StopBits     = System.IO.Ports.StopBits.Two
        else:
            raise ValueError("Unsupported number of stop bits: %r" % self._stopbits)

        if self._rtscts and self._xonxoff:
            self._port_handle.Handshake  = System.IO.Ports.Handshake.RequestToSendXOnXOff
        elif self._rtscts:
            self._port_handle.Handshake  = System.IO.Ports.Handshake.RequestToSend
        elif self._xonxoff:
            self._port_handle.Handshake  = System.IO.Ports.Handshake.XOnXOff
        else:
            self._port_handle.Handshake  = getattr(System.IO.Ports.Handshake, 'None')   # reserved keyword in Py3k

    #~ def __del__(self):
        #~ self.close()

    def close(self):
        """Close port"""
        if self._isOpen:
            if self._port_handle:
                try:
                    self._port_handle.Close()
                except System.IO.Ports.InvalidOperationException:
                    # ignore errors. can happen for unplugged USB serial devices
                    pass
                self._port_handle = None
            self._isOpen = False

    def makeDeviceName(self, port):
        try:
            return device(port)
        except TypeError, e:
            raise SerialException(str(e))

    #  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -

    def inWaiting(self):
        """Return the number of characters currently in the input buffer."""
        if not self._port_handle: raise portNotOpenError
        return self._port_handle.BytesToRead

    def read(self, size=1):
        """Read size bytes from the serial port. If a timeout is set it may
           return less characters as requested. With no timeout it will block
           until the requested number of bytes is read."""
        if not self._port_handle: raise portNotOpenError
        # must use single byte reads as this is the only way to read
        # without applying encodings
        data = bytearray()
        while size:
            try:
                data.append(self._port_handle.ReadByte())
            except System.TimeoutException, e:
                break
            else:
                size -= 1
        return bytes(data)

    def write(self, data):
        """Output the given string over the serial port."""
        if not self._port_handle: raise portNotOpenError
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError('expected %s or bytearray, got %s' % (bytes, type(data)))
        try:
            # must call overloaded method with byte array argument
            # as this is the only one not applying encodings
            self._port_handle.Write(as_byte_array(data), 0, len(data))
        except System.TimeoutException, e:
            raise writeTimeoutError
        return len(data)

    def flushInput(self):
        """Clear input buffer, discarding all that is in the buffer."""
        if not self._port_handle: raise portNotOpenError
        self._port_handle.DiscardInBuffer()

    def flushOutput(self):
        """Clear output buffer, aborting the current output and
        discarding all that is in the buffer."""
        if not self._port_handle: raise portNotOpenError
        self._port_handle.DiscardOutBuffer()

    def sendBreak(self, duration=0.25):
        """Send break condition. Timed, returns to idle state after given duration."""
        if not self._port_handle: raise portNotOpenError
        import time
        self._port_handle.BreakState = True
        time.sleep(duration)
        self._port_handle.BreakState = False

    def setBreak(self, level=True):
        """Set break: Controls TXD. When active, to transmitting is possible."""
        if not self._port_handle: raise portNotOpenError
        self._port_handle.BreakState = bool(level)

    def setRTS(self, level=True):
        """Set terminal status line: Request To Send"""
        if not self._port_handle: raise portNotOpenError
        self._port_handle.RtsEnable = bool(level)

    def setDTR(self, level=True):
        """Set terminal status line: Data Terminal Ready"""
        if not self._port_handle: raise portNotOpenError
        self._port_handle.DtrEnable = bool(level)

    def getCTS(self):
        """Read terminal status line: Clear To Send"""
        if not self._port_handle: raise portNotOpenError
        return self._port_handle.CtsHolding

    def getDSR(self):
        """Read terminal status line: Data Set Ready"""
        if not self._port_handle: raise portNotOpenError
        return self._port_handle.DsrHolding

    def getRI(self):
        """Read terminal status line: Ring Indicator"""
        if not self._port_handle: raise portNotOpenError
        #~ return self._port_handle.XXX
        return False #XXX an error would be better

    def getCD(self):
        """Read terminal status line: Carrier Detect"""
        if not self._port_handle: raise portNotOpenError
        return self._port_handle.CDHolding

    # - - platform specific - - - -
    # none


# assemble Serial class with the platform specific implementation and the base
# for file-like behavior. for Python 2.6 and newer, that provide the new I/O
# library, derive from io.RawIOBase
try:
    import io
except ImportError:
    # classic version with our own file-like emulation
    class Serial(IronSerial, FileLike):
        pass
else:
    # io library present
    class Serial(IronSerial, io.RawIOBase):
        pass


# Nur Testfunktion!!
if __name__ == '__main__':
    import sys

    s = Serial(0)
    sys.stdio.write('%s\n' % s)

    s = Serial()
    sys.stdio.write('%s\n' % s)


    s.baudrate = 19200
    s.databits = 7
    s.close()
    s.port = 0
    s.open()
    sys.stdio.write('%s\n' % s)

