#!/usr/bin/env python
#
# Python Serial Port Extension for Win32, Linux, BSD, Jython
# module for serial IO for POSIX compatible systems, like Linux
# see __init__.py
#
# (C) 2001-2010 Chris Liechti <cliechti@gmx.net>
# this is distributed under a free software license, see license.txt
#
# parts based on code from Grant B. Edwards  <grante@visi.com>:
#  ftp://ftp.visi.com/users/grante/python/PosixSerial.py
#
# references: http://www.easysw.com/~mike/serial/serial.html

import sys, os, fcntl, termios, struct, select, errno, time
from serial.serialutil import *

# Do check the Python version as some constants have moved.
if (sys.hexversion < 0x020100f0):
    import TERMIOS
else:
    TERMIOS = termios

if (sys.hexversion < 0x020200f0):
    import FCNTL
else:
    FCNTL = fcntl

# try to detect the OS so that a device can be selected...
# this code block should supply a device() and set_special_baudrate() function
# for the platform
plat = sys.platform.lower()

if   plat[:5] == 'linux':    # Linux (confirmed)

    def device(port):
        return '/dev/ttyS%d' % port

    TCGETS2 = 0x802C542A
    TCSETS2 = 0x402C542B
    BOTHER = 0o010000

    def set_special_baudrate(port, baudrate):
        # right size is 44 on x86_64, allow for some growth
        import array
        buf = array.array('i', [0] * 64)

        try:
            # get serial_struct
            FCNTL.ioctl(port.fd, TCGETS2, buf)
            # set custom speed
            buf[2] &= ~TERMIOS.CBAUD
            buf[2] |= BOTHER
            buf[9] = buf[10] = baudrate

            # set serial_struct
            res = FCNTL.ioctl(port.fd, TCSETS2, buf)
        except IOError, e:
            raise ValueError('Failed to set custom baud rate (%s): %s' % (baudrate, e))

    baudrate_constants = {
        0:       0000000,  # hang up
        50:      0000001,
        75:      0000002,
        110:     0000003,
        134:     0000004,
        150:     0000005,
        200:     0000006,
        300:     0000007,
        600:     0000010,
        1200:    0000011,
        1800:    0000012,
        2400:    0000013,
        4800:    0000014,
        9600:    0000015,
        19200:   0000016,
        38400:   0000017,
        57600:   0010001,
        115200:  0010002,
        230400:  0010003,
        460800:  0010004,
        500000:  0010005,
        576000:  0010006,
        921600:  0010007,
        1000000: 0010010,
        1152000: 0010011,
        1500000: 0010012,
        2000000: 0010013,
        2500000: 0010014,
        3000000: 0010015,
        3500000: 0010016,
        4000000: 0010017
    }

elif plat == 'cygwin':       # cygwin/win32 (confirmed)

    def device(port):
        return '/dev/com%d' % (port + 1)

    def set_special_baudrate(port, baudrate):
        raise ValueError("sorry don't know how to handle non standard baud rate on this platform")

    baudrate_constants = {
        128000: 0x01003,
        256000: 0x01005,
        500000: 0x01007,
        576000: 0x01008,
        921600: 0x01009,
        1000000: 0x0100a,
        1152000: 0x0100b,
        1500000: 0x0100c,
        2000000: 0x0100d,
        2500000: 0x0100e,
        3000000: 0x0100f
    }

elif plat[:7] == 'openbsd':    # OpenBSD

    def device(port):
        return '/dev/cua%02d' % port

    def set_special_baudrate(port, baudrate):
        raise ValueError("sorry don't know how to handle non standard baud rate on this platform")

    baudrate_constants = {}

elif plat[:3] == 'bsd' or  \
    plat[:7] == 'freebsd':

    def device(port):
        return '/dev/cuad%d' % port

    def set_special_baudrate(port, baudrate):
        raise ValueError("sorry don't know how to handle non standard baud rate on this platform")

    baudrate_constants = {}

elif plat[:6] == 'darwin':   # OS X

    version = os.uname()[2].split('.')
    # Tiger or above can support arbitrary serial speeds
    if int(version[0]) >= 8:
        def set_special_baudrate(port, baudrate):
            # use IOKit-specific call to set up high speeds
            import array, fcntl
            buf = array.array('i', [baudrate])
            IOSSIOSPEED = 0x80045402 #_IOW('T', 2, speed_t)
            fcntl.ioctl(port.fd, IOSSIOSPEED, buf, 1)
    else: # version < 8
        def set_special_baudrate(port, baudrate):
            raise ValueError("baud rate not supported")

    def device(port):
        return '/dev/cuad%d' % port

    baudrate_constants = {}


elif plat[:6] == 'netbsd':   # NetBSD 1.6 testing by Erk

    def device(port):
        return '/dev/dty%02d' % port

    def set_special_baudrate(port, baudrate):
        raise ValueError("sorry don't know how to handle non standard baud rate on this platform")

    baudrate_constants = {}

elif plat[:4] == 'irix':     # IRIX (partially tested)

    def device(port):
        return '/dev/ttyf%d' % (port+1) #XXX different device names depending on flow control

    def set_special_baudrate(port, baudrate):
        raise ValueError("sorry don't know how to handle non standard baud rate on this platform")

    baudrate_constants = {}

elif plat[:2] == 'hp':       # HP-UX (not tested)

    def device(port):
        return '/dev/tty%dp0' % (port+1)

    def set_special_baudrate(port, baudrate):
        raise ValueError("sorry don't know how to handle non standard baud rate on this platform")

    baudrate_constants = {}

elif plat[:5] == 'sunos':    # Solaris/SunOS (confirmed)

    def device(port):
        return '/dev/tty%c' % (ord('a')+port)

    def set_special_baudrate(port, baudrate):
        raise ValueError("sorry don't know how to handle non standard baud rate on this platform")

    baudrate_constants = {}

elif plat[:3] == 'aix':      # AIX

    def device(port):
        return '/dev/tty%d' % (port)

    def set_special_baudrate(port, baudrate):
        raise ValueError("sorry don't know how to handle non standard baud rate on this platform")

    baudrate_constants = {}

else:
    # platform detection has failed...
    sys.stderr.write("""\
don't know how to number ttys on this system.
! Use an explicit path (eg /dev/ttyS1) or send this information to
! the author of this module:

sys.platform = %r
os.name = %r
serialposix.py version = %s

also add the device name of the serial port and where the
counting starts for the first serial port.
e.g. 'first serial port: /dev/ttyS0'
and with a bit luck you can get this module running...
""" % (sys.platform, os.name, VERSION))
    # no exception, just continue with a brave attempt to build a device name
    # even if the device name is not correct for the platform it has chances
    # to work using a string with the real device name as port parameter.
    def device(portum):
        return '/dev/ttyS%d' % portnum
    def set_special_baudrate(port, baudrate):
        raise SerialException("sorry don't know how to handle non standard baud rate on this platform")
    baudrate_constants = {}
    #~ raise Exception, "this module does not run on this platform, sorry."

# whats up with "aix", "beos", ....
# they should work, just need to know the device names.


# load some constants for later use.
# try to use values from TERMIOS, use defaults from linux otherwise
TIOCMGET  = hasattr(TERMIOS, 'TIOCMGET') and TERMIOS.TIOCMGET or 0x5415
TIOCMBIS  = hasattr(TERMIOS, 'TIOCMBIS') and TERMIOS.TIOCMBIS or 0x5416
TIOCMBIC  = hasattr(TERMIOS, 'TIOCMBIC') and TERMIOS.TIOCMBIC or 0x5417
TIOCMSET  = hasattr(TERMIOS, 'TIOCMSET') and TERMIOS.TIOCMSET or 0x5418

#TIOCM_LE = hasattr(TERMIOS, 'TIOCM_LE') and TERMIOS.TIOCM_LE or 0x001
TIOCM_DTR = hasattr(TERMIOS, 'TIOCM_DTR') and TERMIOS.TIOCM_DTR or 0x002
TIOCM_RTS = hasattr(TERMIOS, 'TIOCM_RTS') and TERMIOS.TIOCM_RTS or 0x004
#TIOCM_ST = hasattr(TERMIOS, 'TIOCM_ST') and TERMIOS.TIOCM_ST or 0x008
#TIOCM_SR = hasattr(TERMIOS, 'TIOCM_SR') and TERMIOS.TIOCM_SR or 0x010

TIOCM_CTS = hasattr(TERMIOS, 'TIOCM_CTS') and TERMIOS.TIOCM_CTS or 0x020
TIOCM_CAR = hasattr(TERMIOS, 'TIOCM_CAR') and TERMIOS.TIOCM_CAR or 0x040
TIOCM_RNG = hasattr(TERMIOS, 'TIOCM_RNG') and TERMIOS.TIOCM_RNG or 0x080
TIOCM_DSR = hasattr(TERMIOS, 'TIOCM_DSR') and TERMIOS.TIOCM_DSR or 0x100
TIOCM_CD  = hasattr(TERMIOS, 'TIOCM_CD') and TERMIOS.TIOCM_CD or TIOCM_CAR
TIOCM_RI  = hasattr(TERMIOS, 'TIOCM_RI') and TERMIOS.TIOCM_RI or TIOCM_RNG
#TIOCM_OUT1 = hasattr(TERMIOS, 'TIOCM_OUT1') and TERMIOS.TIOCM_OUT1 or 0x2000
#TIOCM_OUT2 = hasattr(TERMIOS, 'TIOCM_OUT2') and TERMIOS.TIOCM_OUT2 or 0x4000
if hasattr(TERMIOS, 'TIOCINQ'):
    TIOCINQ = TERMIOS.TIOCINQ
else:
    TIOCINQ = hasattr(TERMIOS, 'FIONREAD') and TERMIOS.FIONREAD or 0x541B
TIOCOUTQ   = hasattr(TERMIOS, 'TIOCOUTQ') and TERMIOS.TIOCOUTQ or 0x5411

TIOCM_zero_str = struct.pack('I', 0)
TIOCM_RTS_str = struct.pack('I', TIOCM_RTS)
TIOCM_DTR_str = struct.pack('I', TIOCM_DTR)

TIOCSBRK  = hasattr(TERMIOS, 'TIOCSBRK') and TERMIOS.TIOCSBRK or 0x5427
TIOCCBRK  = hasattr(TERMIOS, 'TIOCCBRK') and TERMIOS.TIOCCBRK or 0x5428


class PosixSerial(SerialBase):
    """Serial port class POSIX implementation. Serial port configuration is 
    done with termios and fcntl. Runs on Linux and many other Un*x like
    systems."""

    def open(self):
        """Open port with current settings. This may throw a SerialException
           if the port cannot be opened."""
        if self._port is None:
            raise SerialException("Port must be configured before it can be used.")
        if self._isOpen:
            raise SerialException("Port is already open.")
        self.fd = None
        # open
        try:
            self.fd = os.open(self.portstr, os.O_RDWR|os.O_NOCTTY|os.O_NONBLOCK)
        except IOError, msg:
            self.fd = None
            raise SerialException(msg.errno, "could not open port %s: %s" % (self._port, msg))
        #~ fcntl.fcntl(self.fd, FCNTL.F_SETFL, 0)  # set blocking

        try:
            self._reconfigurePort()
        except:
            try:
                os.close(self.fd)
            except:
                # ignore any exception when closing the port
                # also to keep original exception that happened when setting up
                pass
            self.fd = None
            raise
        else:
            self._isOpen = True
        self.flushInput()


    def _reconfigurePort(self):
        """Set communication parameters on opened port."""
        if self.fd is None:
            raise SerialException("Can only operate on a valid file descriptor")
        custom_baud = None

        vmin = vtime = 0                # timeout is done via select
        if self._interCharTimeout is not None:
            vmin = 1
            vtime = int(self._interCharTimeout * 10)
        try:
            orig_attr = termios.tcgetattr(self.fd)
            iflag, oflag, cflag, lflag, ispeed, ospeed, cc = orig_attr
        except termios.error, msg:      # if a port is nonexistent but has a /dev file, it'll fail here
            raise SerialException("Could not configure port: %s" % msg)
        # set up raw mode / no echo / binary
        cflag |=  (TERMIOS.CLOCAL|TERMIOS.CREAD)
        lflag &= ~(TERMIOS.ICANON|TERMIOS.ECHO|TERMIOS.ECHOE|TERMIOS.ECHOK|TERMIOS.ECHONL|
                     TERMIOS.ISIG|TERMIOS.IEXTEN) #|TERMIOS.ECHOPRT
        for flag in ('ECHOCTL', 'ECHOKE'): # netbsd workaround for Erk
            if hasattr(TERMIOS, flag):
                lflag &= ~getattr(TERMIOS, flag)

        oflag &= ~(TERMIOS.OPOST)
        iflag &= ~(TERMIOS.INLCR|TERMIOS.IGNCR|TERMIOS.ICRNL|TERMIOS.IGNBRK)
        if hasattr(TERMIOS, 'IUCLC'):
            iflag &= ~TERMIOS.IUCLC
        if hasattr(TERMIOS, 'PARMRK'):
            iflag &= ~TERMIOS.PARMRK

        # setup baud rate
        try:
            ispeed = ospeed = getattr(TERMIOS, 'B%s' % (self._baudrate))
        except AttributeError:
            try:
                ispeed = ospeed = baudrate_constants[self._baudrate]
            except KeyError:
                #~ raise ValueError('Invalid baud rate: %r' % self._baudrate)
                # may need custom baud rate, it isn't in our list.
                ispeed = ospeed = getattr(TERMIOS, 'B38400')
                try:
                    custom_baud = int(self._baudrate) # store for later
                except ValueError:
                    raise ValueError('Invalid baud rate: %r' % self._baudrate)
                else:
                    if custom_baud < 0:
                        raise ValueError('Invalid baud rate: %r' % self._baudrate)

        # setup char len
        cflag &= ~TERMIOS.CSIZE
        if self._bytesize == 8:
            cflag |= TERMIOS.CS8
        elif self._bytesize == 7:
            cflag |= TERMIOS.CS7
        elif self._bytesize == 6:
            cflag |= TERMIOS.CS6
        elif self._bytesize == 5:
            cflag |= TERMIOS.CS5
        else:
            raise ValueError('Invalid char len: %r' % self._bytesize)
        # setup stopbits
        if self._stopbits == STOPBITS_ONE:
            cflag &= ~(TERMIOS.CSTOPB)
        elif self._stopbits == STOPBITS_ONE_POINT_FIVE:
            cflag |=  (TERMIOS.CSTOPB)  # XXX same as TWO.. there is no POSIX support for 1.5
        elif self._stopbits == STOPBITS_TWO:
            cflag |=  (TERMIOS.CSTOPB)
        else:
            raise ValueError('Invalid stop bit specification: %r' % self._stopbits)
        # setup parity
        iflag &= ~(TERMIOS.INPCK|TERMIOS.ISTRIP)
        if self._parity == PARITY_NONE:
            cflag &= ~(TERMIOS.PARENB|TERMIOS.PARODD)
        elif self._parity == PARITY_EVEN:
            cflag &= ~(TERMIOS.PARODD)
            cflag |=  (TERMIOS.PARENB)
        elif self._parity == PARITY_ODD:
            cflag |=  (TERMIOS.PARENB|TERMIOS.PARODD)
        else:
            raise ValueError('Invalid parity: %r' % self._parity)
        # setup flow control
        # xonxoff
        if hasattr(TERMIOS, 'IXANY'):
            if self._xonxoff:
                iflag |=  (TERMIOS.IXON|TERMIOS.IXOFF) #|TERMIOS.IXANY)
            else:
                iflag &= ~(TERMIOS.IXON|TERMIOS.IXOFF|TERMIOS.IXANY)
        else:
            if self._xonxoff:
                iflag |=  (TERMIOS.IXON|TERMIOS.IXOFF)
            else:
                iflag &= ~(TERMIOS.IXON|TERMIOS.IXOFF)
        # rtscts
        if hasattr(TERMIOS, 'CRTSCTS'):
            if self._rtscts:
                cflag |=  (TERMIOS.CRTSCTS)
            else:
                cflag &= ~(TERMIOS.CRTSCTS)
        elif hasattr(TERMIOS, 'CNEW_RTSCTS'):   # try it with alternate constant name
            if self._rtscts:
                cflag |=  (TERMIOS.CNEW_RTSCTS)
            else:
                cflag &= ~(TERMIOS.CNEW_RTSCTS)
        # XXX should there be a warning if setting up rtscts (and xonxoff etc) fails??

        # buffer
        # vmin "minimal number of characters to be read. = for non blocking"
        if vmin < 0 or vmin > 255:
            raise ValueError('Invalid vmin: %r ' % vmin)
        cc[TERMIOS.VMIN] = vmin
        # vtime
        if vtime < 0 or vtime > 255:
            raise ValueError('Invalid vtime: %r' % vtime)
        cc[TERMIOS.VTIME] = vtime
        # activate settings
        if [iflag, oflag, cflag, lflag, ispeed, ospeed, cc] != orig_attr:
            termios.tcsetattr(self.fd, TERMIOS.TCSANOW, [iflag, oflag, cflag, lflag, ispeed, ospeed, cc])

        # apply custom baud rate, if any
        if custom_baud is not None:
            set_special_baudrate(self, custom_baud)

    def close(self):
        """Close port"""
        if self._isOpen:
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None
            self._isOpen = False

    def makeDeviceName(self, port):
        return device(port)

    #  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -

    def inWaiting(self):
        """Return the number of characters currently in the input buffer."""
        #~ s = fcntl.ioctl(self.fd, TERMIOS.FIONREAD, TIOCM_zero_str)
        s = fcntl.ioctl(self.fd, TIOCINQ, TIOCM_zero_str)
        return struct.unpack('I',s)[0]

    # select based implementation, proved to work on many systems
    def read(self, size=1):
        """Read size bytes from the serial port. If a timeout is set it may
           return less characters as requested. With no timeout it will block
           until the requested number of bytes is read."""
        if not self._isOpen: raise portNotOpenError
        read = bytearray()
        while len(read) < size:
            try:
                ready,_,_ = select.select([self.fd],[],[], self._timeout)
                # If select was used with a timeout, and the timeout occurs, it
                # returns with empty lists -> thus abort read operation.
                # For timeout == 0 (non-blocking operation) also abort when there
                # is nothing to read.
                if not ready:
                    break   # timeout
                buf = os.read(self.fd, size-len(read))
                # read should always return some data as select reported it was
                # ready to read when we get to this point.
                if not buf:
                    # Disconnected devices, at least on Linux, show the
                    # behavior that they are always ready to read immediately
                    # but reading returns nothing.
                    raise SerialException('device reports readiness to read but returned no data (device disconnected or multiple access on port?)')
                read.extend(buf)
            except select.error, e:
                # ignore EAGAIN errors. all other errors are shown
                # see also http://www.python.org/dev/peps/pep-3151/#select
                if e[0] != errno.EAGAIN:
                    raise SerialException('read failed: %s' % (e,))
            except OSError, e:
                # ignore EAGAIN errors. all other errors are shown
                if e.errno != errno.EAGAIN:
                    raise SerialException('read failed: %s' % (e,))
        return bytes(read)

    def write(self, data):
        """Output the given string over the serial port."""
        if not self._isOpen: raise portNotOpenError
        d = to_bytes(data)
        tx_len = len(d)
        if self._writeTimeout is not None and self._writeTimeout > 0:
            timeout = time.time() + self._writeTimeout
        else:
            timeout = None
        while tx_len > 0:
            try:
                n = os.write(self.fd, d)
                if timeout:
                    # when timeout is set, use select to wait for being ready
                    # with the time left as timeout
                    timeleft = timeout - time.time()
                    if timeleft < 0:
                        raise writeTimeoutError
                    _, ready, _ = select.select([], [self.fd], [], timeleft)
                    if not ready:
                        raise writeTimeoutError
                else:
                    # wait for write operation
                    _, ready, _ = select.select([], [self.fd], [], None)
                    if not ready:
                        raise SerialException('write failed (select)')
                d = d[n:]
                tx_len -= n
            except OSError, v:
                if v.errno != errno.EAGAIN:
                    raise SerialException('write failed: %s' % (v,))
        return len(data)

    def flush(self):
        """Flush of file like objects. In this case, wait until all data
           is written."""
        self.drainOutput()

    def flushInput(self):
        """Clear input buffer, discarding all that is in the buffer."""
        if not self._isOpen: raise portNotOpenError
        termios.tcflush(self.fd, TERMIOS.TCIFLUSH)

    def flushOutput(self):
        """Clear output buffer, aborting the current output and
        discarding all that is in the buffer."""
        if not self._isOpen: raise portNotOpenError
        termios.tcflush(self.fd, TERMIOS.TCOFLUSH)

    def sendBreak(self, duration=0.25):
        """Send break condition. Timed, returns to idle state after given duration."""
        if not self._isOpen: raise portNotOpenError
        termios.tcsendbreak(self.fd, int(duration/0.25))

    def setBreak(self, level=1):
        """Set break: Controls TXD. When active, no transmitting is possible."""
        if self.fd is None: raise portNotOpenError
        if level:
            fcntl.ioctl(self.fd, TIOCSBRK)
        else:
            fcntl.ioctl(self.fd, TIOCCBRK)

    def setRTS(self, level=1):
        """Set terminal status line: Request To Send"""
        if not self._isOpen: raise portNotOpenError
        if level:
            fcntl.ioctl(self.fd, TIOCMBIS, TIOCM_RTS_str)
        else:
            fcntl.ioctl(self.fd, TIOCMBIC, TIOCM_RTS_str)

    def setDTR(self, level=1):
        """Set terminal status line: Data Terminal Ready"""
        if not self._isOpen: raise portNotOpenError
        if level:
            fcntl.ioctl(self.fd, TIOCMBIS, TIOCM_DTR_str)
        else:
            fcntl.ioctl(self.fd, TIOCMBIC, TIOCM_DTR_str)

    def getCTS(self):
        """Read terminal status line: Clear To Send"""
        if not self._isOpen: raise portNotOpenError
        s = fcntl.ioctl(self.fd, TIOCMGET, TIOCM_zero_str)
        return struct.unpack('I',s)[0] & TIOCM_CTS != 0

    def getDSR(self):
        """Read terminal status line: Data Set Ready"""
        if not self._isOpen: raise portNotOpenError
        s = fcntl.ioctl(self.fd, TIOCMGET, TIOCM_zero_str)
        return struct.unpack('I',s)[0] & TIOCM_DSR != 0

    def getRI(self):
        """Read terminal status line: Ring Indicator"""
        if not self._isOpen: raise portNotOpenError
        s = fcntl.ioctl(self.fd, TIOCMGET, TIOCM_zero_str)
        return struct.unpack('I',s)[0] & TIOCM_RI != 0

    def getCD(self):
        """Read terminal status line: Carrier Detect"""
        if not self._isOpen: raise portNotOpenError
        s = fcntl.ioctl(self.fd, TIOCMGET, TIOCM_zero_str)
        return struct.unpack('I',s)[0] & TIOCM_CD != 0

    # - - platform specific - - - -

    def outWaiting(self):
        """Return the number of characters currently in the output buffer."""
        #~ s = fcntl.ioctl(self.fd, TERMIOS.FIONREAD, TIOCM_zero_str)
        s = fcntl.ioctl(self.fd, TIOCOUTQ, TIOCM_zero_str)
        return struct.unpack('I',s)[0]

    def drainOutput(self):
        """internal - not portable!"""
        if not self._isOpen: raise portNotOpenError
        termios.tcdrain(self.fd)

    def nonblocking(self):
        """internal - not portable!"""
        if not self._isOpen: raise portNotOpenError
        fcntl.fcntl(self.fd, FCNTL.F_SETFL, os.O_NONBLOCK)

    def fileno(self):
        """\
        For easier use of the serial port instance with select.
        WARNING: this function is not portable to different platforms!
        """
        if not self._isOpen: raise portNotOpenError
        return self.fd

    def setXON(self, level=True):
        """\
        Manually control flow - when software flow control is enabled.
        This will send XON (true) and XOFF (false) to the other device.
        WARNING: this function is not portable to different platforms!
        """
        if not self.hComPort: raise portNotOpenError
        if enable:
            termios.tcflow(self.fd, TERMIOS.TCION)
        else:
            termios.tcflow(self.fd, TERMIOS.TCIOFF)

    def flowControlOut(self, enable):
        """\
        Manually control flow of outgoing data - when hardware or software flow
        control is enabled.
        WARNING: this function is not portable to different platforms!
        """
        if not self._isOpen: raise portNotOpenError
        if enable:
            termios.tcflow(self.fd, TERMIOS.TCOON)
        else:
            termios.tcflow(self.fd, TERMIOS.TCOOFF)


# assemble Serial class with the platform specifc implementation and the base
# for file-like behavior. for Python 2.6 and newer, that provide the new I/O
# library, derrive from io.RawIOBase
try:
    import io
except ImportError:
    # classic version with our own file-like emulation
    class Serial(PosixSerial, FileLike):
        pass
else:
    # io library present
    class Serial(PosixSerial, io.RawIOBase):
        pass

class PosixPollSerial(Serial):
    """poll based read implementation. not all systems support poll properly.
    however this one has better handling of errors, such as a device
    disconnecting while it's in use (e.g. USB-serial unplugged)"""

    def read(self, size=1):
        """Read size bytes from the serial port. If a timeout is set it may
           return less characters as requested. With no timeout it will block
           until the requested number of bytes is read."""
        if self.fd is None: raise portNotOpenError
        read = bytearray()
        poll = select.poll()
        poll.register(self.fd, select.POLLIN|select.POLLERR|select.POLLHUP|select.POLLNVAL)
        if size > 0:
            while len(read) < size:
                # print "\tread(): size",size, "have", len(read)    #debug
                # wait until device becomes ready to read (or something fails)
                for fd, event in poll.poll(self._timeout*1000):
                    if event & (select.POLLERR|select.POLLHUP|select.POLLNVAL):
                        raise SerialException('device reports error (poll)')
                    #  we don't care if it is select.POLLIN or timeout, that's
                    #  handled below
                buf = os.read(self.fd, size - len(read))
                read.extend(buf)
                if ((self._timeout is not None and self._timeout >= 0) or 
                    (self._interCharTimeout is not None and self._interCharTimeout > 0)) and not buf:
                    break   # early abort on timeout
        return bytes(read)


if __name__ == '__main__':
    s = Serial(0,
                 baudrate=19200,        # baud rate
                 bytesize=EIGHTBITS,    # number of data bits
                 parity=PARITY_EVEN,    # enable parity checking
                 stopbits=STOPBITS_ONE, # number of stop bits
                 timeout=3,             # set a timeout value, None for waiting forever
                 xonxoff=0,             # enable software flow control
                 rtscts=0,              # enable RTS/CTS flow control
               )
    s.setRTS(1)
    s.setDTR(1)
    s.flushInput()
    s.flushOutput()
    s.write('hello')
    sys.stdout.write('%r\n' % s.read(5))
    sys.stdout.write('%s\n' % s.inWaiting())
    del s

