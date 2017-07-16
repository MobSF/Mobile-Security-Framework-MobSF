#! python
# Python Serial Port Extension for Win32, Linux, BSD, Jython
# serial driver for win32
# see __init__.py
#
# (C) 2001-2011 Chris Liechti <cliechti@gmx.net>
# this is distributed under a free software license, see license.txt
#
# Initial patch to use ctypes by Giovanni Bajo <rasky@develer.com>

import ctypes
from serial import win32

from serial.serialutil import *


def device(portnum):
    """Turn a port number into a device name"""
    return 'COM%d' % (portnum+1) # numbers are transformed to a string


class Win32Serial(SerialBase):
    """Serial port implementation for Win32 based on ctypes."""

    BAUDRATES = (50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800,
                 9600, 19200, 38400, 57600, 115200)

    def __init__(self, *args, **kwargs):
        self.hComPort = None
        self._overlappedRead = None
        self._overlappedWrite = None
        self._rtsToggle = False

        self._rtsState = win32.RTS_CONTROL_ENABLE
        self._dtrState = win32.DTR_CONTROL_ENABLE


        SerialBase.__init__(self, *args, **kwargs)

    def open(self):
        """Open port with current settings. This may throw a SerialException
           if the port cannot be opened."""
        if self._port is None:
            raise SerialException("Port must be configured before it can be used.")
        if self._isOpen:
            raise SerialException("Port is already open.")
        # the "\\.\COMx" format is required for devices other than COM1-COM8
        # not all versions of windows seem to support this properly
        # so that the first few ports are used with the DOS device name
        port = self.portstr
        try:
            if port.upper().startswith('COM') and int(port[3:]) > 8:
                port = '\\\\.\\' + port
        except ValueError:
            # for like COMnotanumber
            pass
        self.hComPort = win32.CreateFile(port,
               win32.GENERIC_READ | win32.GENERIC_WRITE,
               0, # exclusive access
               None, # no security
               win32.OPEN_EXISTING,
               win32.FILE_ATTRIBUTE_NORMAL | win32.FILE_FLAG_OVERLAPPED,
               0)
        if self.hComPort == win32.INVALID_HANDLE_VALUE:
            self.hComPort = None    # 'cause __del__ is called anyway
            raise SerialException("could not open port %r: %r" % (self.portstr, ctypes.WinError()))

        try:
            self._overlappedRead = win32.OVERLAPPED()
            self._overlappedRead.hEvent = win32.CreateEvent(None, 1, 0, None)
            self._overlappedWrite = win32.OVERLAPPED()
            #~ self._overlappedWrite.hEvent = win32.CreateEvent(None, 1, 0, None)
            self._overlappedWrite.hEvent = win32.CreateEvent(None, 0, 0, None)

            # Setup a 4k buffer
            win32.SetupComm(self.hComPort, 4096, 4096)

            # Save original timeout values:
            self._orgTimeouts = win32.COMMTIMEOUTS()
            win32.GetCommTimeouts(self.hComPort, ctypes.byref(self._orgTimeouts))

            self._reconfigurePort()

            # Clear buffers:
            # Remove anything that was there
            win32.PurgeComm(self.hComPort,
                    win32.PURGE_TXCLEAR | win32.PURGE_TXABORT |
                    win32.PURGE_RXCLEAR | win32.PURGE_RXABORT)
        except:
            try:
                self._close()
            except:
                # ignore any exception when closing the port
                # also to keep original exception that happened when setting up
                pass
            self.hComPort = None
            raise
        else:
            self._isOpen = True


    def _reconfigurePort(self):
        """Set communication parameters on opened port."""
        if not self.hComPort:
            raise SerialException("Can only operate on a valid port handle")

        # Set Windows timeout values
        # timeouts is a tuple with the following items:
        # (ReadIntervalTimeout,ReadTotalTimeoutMultiplier,
        #  ReadTotalTimeoutConstant,WriteTotalTimeoutMultiplier,
        #  WriteTotalTimeoutConstant)
        if self._timeout is None:
            timeouts = (0, 0, 0, 0, 0)
        elif self._timeout == 0:
            timeouts = (win32.MAXDWORD, 0, 0, 0, 0)
        else:
            timeouts = (0, 0, int(self._timeout*1000), 0, 0)
        if self._timeout != 0 and self._interCharTimeout is not None:
            timeouts = (int(self._interCharTimeout * 1000),) + timeouts[1:]

        if self._writeTimeout is None:
            pass
        elif self._writeTimeout == 0:
            timeouts = timeouts[:-2] + (0, win32.MAXDWORD)
        else:
            timeouts = timeouts[:-2] + (0, int(self._writeTimeout*1000))
        win32.SetCommTimeouts(self.hComPort, ctypes.byref(win32.COMMTIMEOUTS(*timeouts)))

        win32.SetCommMask(self.hComPort, win32.EV_ERR)

        # Setup the connection info.
        # Get state and modify it:
        comDCB = win32.DCB()
        win32.GetCommState(self.hComPort, ctypes.byref(comDCB))
        comDCB.BaudRate = self._baudrate

        if self._bytesize == FIVEBITS:
            comDCB.ByteSize     = 5
        elif self._bytesize == SIXBITS:
            comDCB.ByteSize     = 6
        elif self._bytesize == SEVENBITS:
            comDCB.ByteSize     = 7
        elif self._bytesize == EIGHTBITS:
            comDCB.ByteSize     = 8
        else:
            raise ValueError("Unsupported number of data bits: %r" % self._bytesize)

        if self._parity == PARITY_NONE:
            comDCB.Parity       = win32.NOPARITY
            comDCB.fParity      = 0 # Disable Parity Check
        elif self._parity == PARITY_EVEN:
            comDCB.Parity       = win32.EVENPARITY
            comDCB.fParity      = 1 # Enable Parity Check
        elif self._parity == PARITY_ODD:
            comDCB.Parity       = win32.ODDPARITY
            comDCB.fParity      = 1 # Enable Parity Check
        elif self._parity == PARITY_MARK:
            comDCB.Parity       = win32.MARKPARITY
            comDCB.fParity      = 1 # Enable Parity Check
        elif self._parity == PARITY_SPACE:
            comDCB.Parity       = win32.SPACEPARITY
            comDCB.fParity      = 1 # Enable Parity Check
        else:
            raise ValueError("Unsupported parity mode: %r" % self._parity)

        if self._stopbits == STOPBITS_ONE:
            comDCB.StopBits     = win32.ONESTOPBIT
        elif self._stopbits == STOPBITS_ONE_POINT_FIVE:
            comDCB.StopBits     = win32.ONE5STOPBITS
        elif self._stopbits == STOPBITS_TWO:
            comDCB.StopBits     = win32.TWOSTOPBITS
        else:
            raise ValueError("Unsupported number of stop bits: %r" % self._stopbits)

        comDCB.fBinary          = 1 # Enable Binary Transmission
        # Char. w/ Parity-Err are replaced with 0xff (if fErrorChar is set to TRUE)
        if self._rtscts:
            comDCB.fRtsControl  = win32.RTS_CONTROL_HANDSHAKE
        elif self._rtsToggle:
            comDCB.fRtsControl  = win32.RTS_CONTROL_TOGGLE
        else:
            comDCB.fRtsControl  = self._rtsState
        if self._dsrdtr:
            comDCB.fDtrControl  = win32.DTR_CONTROL_HANDSHAKE
        else:
            comDCB.fDtrControl  = self._dtrState

        if self._rtsToggle:
            comDCB.fOutxCtsFlow     = 0
        else:
            comDCB.fOutxCtsFlow     = self._rtscts
        comDCB.fOutxDsrFlow     = self._dsrdtr
        comDCB.fOutX            = self._xonxoff
        comDCB.fInX             = self._xonxoff
        comDCB.fNull            = 0
        comDCB.fErrorChar       = 0
        comDCB.fAbortOnError    = 0
        comDCB.XonChar          = XON
        comDCB.XoffChar         = XOFF

        if not win32.SetCommState(self.hComPort, ctypes.byref(comDCB)):
            raise ValueError("Cannot configure port, some setting was wrong. Original message: %r" % ctypes.WinError())

    #~ def __del__(self):
        #~ self.close()


    def _close(self):
        """internal close port helper"""
        if self.hComPort:
            # Restore original timeout values:
            win32.SetCommTimeouts(self.hComPort, self._orgTimeouts)
            # Close COM-Port:
            win32.CloseHandle(self.hComPort)
            if self._overlappedRead is not None:
                win32.CloseHandle(self._overlappedRead.hEvent)
                self._overlappedRead = None
            if self._overlappedWrite is not None:
                win32.CloseHandle(self._overlappedWrite.hEvent)
                self._overlappedWrite = None
            self.hComPort = None

    def close(self):
        """Close port"""
        if self._isOpen:
            self._close()
            self._isOpen = False

    def makeDeviceName(self, port):
        return device(port)

    #  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -

    def inWaiting(self):
        """Return the number of characters currently in the input buffer."""
        flags = win32.DWORD()
        comstat = win32.COMSTAT()
        if not win32.ClearCommError(self.hComPort, ctypes.byref(flags), ctypes.byref(comstat)):
            raise SerialException('call to ClearCommError failed')
        return comstat.cbInQue

    def read(self, size=1):
        """Read size bytes from the serial port. If a timeout is set it may
           return less characters as requested. With no timeout it will block
           until the requested number of bytes is read."""
        if not self.hComPort: raise portNotOpenError
        if size > 0:
            win32.ResetEvent(self._overlappedRead.hEvent)
            flags = win32.DWORD()
            comstat = win32.COMSTAT()
            if not win32.ClearCommError(self.hComPort, ctypes.byref(flags), ctypes.byref(comstat)):
                raise SerialException('call to ClearCommError failed')
            if self.timeout == 0:
                n = min(comstat.cbInQue, size)
                if n > 0:
                    buf = ctypes.create_string_buffer(n)
                    rc = win32.DWORD()
                    err = win32.ReadFile(self.hComPort, buf, n, ctypes.byref(rc), ctypes.byref(self._overlappedRead))
                    if not err and win32.GetLastError() != win32.ERROR_IO_PENDING:
                        raise SerialException("ReadFile failed (%r)" % ctypes.WinError())
                    err = win32.WaitForSingleObject(self._overlappedRead.hEvent, win32.INFINITE)
                    read = buf.raw[:rc.value]
                else:
                    read = bytes()
            else:
                buf = ctypes.create_string_buffer(size)
                rc = win32.DWORD()
                err = win32.ReadFile(self.hComPort, buf, size, ctypes.byref(rc), ctypes.byref(self._overlappedRead))
                if not err and win32.GetLastError() != win32.ERROR_IO_PENDING:
                    raise SerialException("ReadFile failed (%r)" % ctypes.WinError())
                err = win32.GetOverlappedResult(self.hComPort, ctypes.byref(self._overlappedRead), ctypes.byref(rc), True)
                read = buf.raw[:rc.value]
        else:
            read = bytes()
        return bytes(read)

    def write(self, data):
        """Output the given string over the serial port."""
        if not self.hComPort: raise portNotOpenError
        #~ if not isinstance(data, (bytes, bytearray)):
            #~ raise TypeError('expected %s or bytearray, got %s' % (bytes, type(data)))
        # convert data (needed in case of memoryview instance: Py 3.1 io lib), ctypes doesn't like memoryview
        data = to_bytes(data)
        if data:
            #~ win32event.ResetEvent(self._overlappedWrite.hEvent)
            n = win32.DWORD()
            err = win32.WriteFile(self.hComPort, data, len(data), ctypes.byref(n), self._overlappedWrite)
            if not err and win32.GetLastError() != win32.ERROR_IO_PENDING:
                raise SerialException("WriteFile failed (%r)" % ctypes.WinError())
            if self._writeTimeout != 0: # if blocking (None) or w/ write timeout (>0)
                # Wait for the write to complete.
                #~ win32.WaitForSingleObject(self._overlappedWrite.hEvent, win32.INFINITE)
                err = win32.GetOverlappedResult(self.hComPort, self._overlappedWrite, ctypes.byref(n), True)
                if n.value != len(data):
                    raise writeTimeoutError
            return n.value
        else:
            return 0

    def flush(self):
        """Flush of file like objects. In this case, wait until all data
           is written."""
        while self.outWaiting():
            time.sleep(0.05)
        # XXX could also use WaitCommEvent with mask EV_TXEMPTY, but it would
        # require overlapped IO and its also only possible to set a single mask
        # on the port---

    def flushInput(self):
        """Clear input buffer, discarding all that is in the buffer."""
        if not self.hComPort: raise portNotOpenError
        win32.PurgeComm(self.hComPort, win32.PURGE_RXCLEAR | win32.PURGE_RXABORT)

    def flushOutput(self):
        """Clear output buffer, aborting the current output and
        discarding all that is in the buffer."""
        if not self.hComPort: raise portNotOpenError
        win32.PurgeComm(self.hComPort, win32.PURGE_TXCLEAR | win32.PURGE_TXABORT)

    def sendBreak(self, duration=0.25):
        """Send break condition. Timed, returns to idle state after given duration."""
        if not self.hComPort: raise portNotOpenError
        import time
        win32.SetCommBreak(self.hComPort)
        time.sleep(duration)
        win32.ClearCommBreak(self.hComPort)

    def setBreak(self, level=1):
        """Set break: Controls TXD. When active, to transmitting is possible."""
        if not self.hComPort: raise portNotOpenError
        if level:
            win32.SetCommBreak(self.hComPort)
        else:
            win32.ClearCommBreak(self.hComPort)

    def setRTS(self, level=1):
        """Set terminal status line: Request To Send"""
        # remember level for reconfigure
        if level:
            self._rtsState = win32.RTS_CONTROL_ENABLE
        else:
            self._rtsState = win32.RTS_CONTROL_DISABLE
        # also apply now if port is open
        if self.hComPort:
            if level:
                win32.EscapeCommFunction(self.hComPort, win32.SETRTS)
            else:
                win32.EscapeCommFunction(self.hComPort, win32.CLRRTS)

    def setDTR(self, level=1):
        """Set terminal status line: Data Terminal Ready"""
        # remember level for reconfigure
        if level:
            self._dtrState = win32.DTR_CONTROL_ENABLE
        else:
            self._dtrState = win32.DTR_CONTROL_DISABLE
        # also apply now if port is open
        if self.hComPort:
            if level:
                win32.EscapeCommFunction(self.hComPort, win32.SETDTR)
            else:
                win32.EscapeCommFunction(self.hComPort, win32.CLRDTR)

    def _GetCommModemStatus(self):
        stat = win32.DWORD()
        win32.GetCommModemStatus(self.hComPort, ctypes.byref(stat))
        return stat.value

    def getCTS(self):
        """Read terminal status line: Clear To Send"""
        if not self.hComPort: raise portNotOpenError
        return win32.MS_CTS_ON & self._GetCommModemStatus() != 0

    def getDSR(self):
        """Read terminal status line: Data Set Ready"""
        if not self.hComPort: raise portNotOpenError
        return win32.MS_DSR_ON & self._GetCommModemStatus() != 0

    def getRI(self):
        """Read terminal status line: Ring Indicator"""
        if not self.hComPort: raise portNotOpenError
        return win32.MS_RING_ON & self._GetCommModemStatus() != 0

    def getCD(self):
        """Read terminal status line: Carrier Detect"""
        if not self.hComPort: raise portNotOpenError
        return win32.MS_RLSD_ON & self._GetCommModemStatus() != 0

    # - - platform specific - - - -

    def setBufferSize(self, rx_size=4096, tx_size=None):
        """\
        Recommend a buffer size to the driver (device driver can ignore this
        vlaue). Must be called before the port is opended.
        """
        if tx_size is None: tx_size = rx_size
        win32.SetupComm(self.hComPort, rx_size, tx_size)

    def setXON(self, level=True):
        """\
        Manually control flow - when software flow control is enabled.
        This will send XON (true) and XOFF (false) to the other device.
        WARNING: this function is not portable to different platforms!
        """
        if not self.hComPort: raise portNotOpenError
        if level:
            win32.EscapeCommFunction(self.hComPort, win32.SETXON)
        else:
            win32.EscapeCommFunction(self.hComPort, win32.SETXOFF)

    def outWaiting(self):
        """return how many characters the in the outgoing buffer"""
        flags = win32.DWORD()
        comstat = win32.COMSTAT()
        if not win32.ClearCommError(self.hComPort, ctypes.byref(flags), ctypes.byref(comstat)):
            raise SerialException('call to ClearCommError failed')
        return comstat.cbOutQue

    # functions useful for RS-485 adapters
    def setRtsToggle(self, rtsToggle):
        """Change RTS toggle control setting."""
        self._rtsToggle = rtsToggle
        if self._isOpen: self._reconfigurePort()

    def getRtsToggle(self):
        """Get the current RTS toggle control setting."""
        return self._rtsToggle

    rtsToggle = property(getRtsToggle, setRtsToggle, doc="RTS toggle control setting")


# assemble Serial class with the platform specific implementation and the base
# for file-like behavior. for Python 2.6 and newer, that provide the new I/O
# library, derive from io.RawIOBase
try:
    import io
except ImportError:
    # classic version with our own file-like emulation
    class Serial(Win32Serial, FileLike):
        pass
else:
    # io library present
    class Serial(Win32Serial, io.RawIOBase):
        pass


# Nur Testfunktion!!
if __name__ == '__main__':
    s = Serial(0)
    sys.stdout.write("%s\n" % s)

    s = Serial()
    sys.stdout.write("%s\n" % s)

    s.baudrate = 19200
    s.databits = 7
    s.close()
    s.port = 0
    s.open()
    sys.stdout.write("%s\n" % s)

