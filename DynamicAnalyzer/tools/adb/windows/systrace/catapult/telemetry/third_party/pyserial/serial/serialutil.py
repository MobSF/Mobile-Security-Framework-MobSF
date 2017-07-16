#! python
# Python Serial Port Extension for Win32, Linux, BSD, Jython
# see __init__.py
#
# (C) 2001-2010 Chris Liechti <cliechti@gmx.net>
# this is distributed under a free software license, see license.txt

# compatibility for older Python < 2.6
try:
    bytes
    bytearray
except (NameError, AttributeError):
    # Python older than 2.6 do not have these types. Like for Python 2.6 they
    # should behave like str. For Python older than 3.0 we want to work with
    # strings anyway, only later versions have a true bytes type.
    bytes = str
    # bytearray is a mutable type that is easily turned into an instance of
    # bytes
    class bytearray(list):
        # for bytes(bytearray()) usage
        def __str__(self): return ''.join(self)
        def __repr__(self): return 'bytearray(%r)' % ''.join(self)
        # append automatically converts integers to characters
        def append(self, item):
            if isinstance(item, str):
                list.append(self, item)
            else:
                list.append(self, chr(item))
        # +=
        def __iadd__(self, other):
            for byte in other:
                self.append(byte)
            return self

        def __getslice__(self, i, j):
            return bytearray(list.__getslice__(self, i, j))

        def __getitem__(self, item):
            if isinstance(item, slice):
                return bytearray(list.__getitem__(self, item))
            else:
                return ord(list.__getitem__(self, item))

        def __eq__(self, other):
            if isinstance(other, basestring):
                other = bytearray(other)
            return list.__eq__(self, other)

# ``memoryview`` was introduced in Python 2.7 and ``bytes(some_memoryview)``
# isn't returning the contents (very unfortunate). Therefore we need special
# cases and test for it. Ensure that there is a ``memoryview`` object for older
# Python versions. This is easier than making every test dependent on its
# existence.
try:
    memoryview
except (NameError, AttributeError):
    # implementation does not matter as we do not realy use it.
    # it just must not inherit from something else we might care for.
    class memoryview:
        pass


# all Python versions prior 3.x convert ``str([17])`` to '[17]' instead of '\x11'
# so a simple ``bytes(sequence)`` doesn't work for all versions
def to_bytes(seq):
    """convert a sequence to a bytes type"""
    if isinstance(seq, bytes):
        return seq
    elif isinstance(seq, bytearray):
        return bytes(seq)
    elif isinstance(seq, memoryview):
        return seq.tobytes()
    else:
        b = bytearray()
        for item in seq:
            b.append(item)  # this one handles int and str for our emulation and ints for Python 3.x
        return bytes(b)

# create control bytes
XON  = to_bytes([17])
XOFF = to_bytes([19])

CR = to_bytes([13])
LF = to_bytes([10])


PARITY_NONE, PARITY_EVEN, PARITY_ODD, PARITY_MARK, PARITY_SPACE = 'N', 'E', 'O', 'M', 'S'
STOPBITS_ONE, STOPBITS_ONE_POINT_FIVE, STOPBITS_TWO = (1, 1.5, 2)
FIVEBITS, SIXBITS, SEVENBITS, EIGHTBITS = (5, 6, 7, 8)

PARITY_NAMES = {
    PARITY_NONE:  'None',
    PARITY_EVEN:  'Even',
    PARITY_ODD:   'Odd',
    PARITY_MARK:  'Mark',
    PARITY_SPACE: 'Space',
}


class SerialException(IOError):
    """Base class for serial port related exceptions."""


class SerialTimeoutException(SerialException):
    """Write timeouts give an exception"""


writeTimeoutError = SerialTimeoutException('Write timeout')
portNotOpenError = SerialException('Attempting to use a port that is not open')


class FileLike(object):
    """An abstract file like class.

    This class implements readline and readlines based on read and
    writelines based on write.
    This class is used to provide the above functions for to Serial
    port objects.

    Note that when the serial port was opened with _NO_ timeout that
    readline blocks until it sees a newline (or the specified size is
    reached) and that readlines would never return and therefore
    refuses to work (it raises an exception in this case)!
    """

    def __init__(self):
        self.closed = True

    def close(self):
        self.closed = True

    # so that ports are closed when objects are discarded
    def __del__(self):
        """Destructor.  Calls close()."""
        # The try/except block is in case this is called at program
        # exit time, when it's possible that globals have already been
        # deleted, and then the close() call might fail.  Since
        # there's nothing we can do about such failures and they annoy
        # the end users, we suppress the traceback.
        try:
            self.close()
        except:
            pass

    def writelines(self, sequence):
        for line in sequence:
            self.write(line)

    def flush(self):
        """flush of file like objects"""
        pass

    # iterator for e.g. "for line in Serial(0): ..." usage
    def next(self):
        line = self.readline()
        if not line: raise StopIteration
        return line

    def __iter__(self):
        return self

    def readline(self, size=None, eol=LF):
        """read a line which is terminated with end-of-line (eol) character
        ('\n' by default) or until timeout."""
        leneol = len(eol)
        line = bytearray()
        while True:
            c = self.read(1)
            if c:
                line += c
                if line[-leneol:] == eol:
                    break
                if size is not None and len(line) >= size:
                    break
            else:
                break
        return bytes(line)

    def readlines(self, sizehint=None, eol=LF):
        """read a list of lines, until timeout.
        sizehint is ignored."""
        if self.timeout is None:
            raise ValueError("Serial port MUST have enabled timeout for this function!")
        leneol = len(eol)
        lines = []
        while True:
            line = self.readline(eol=eol)
            if line:
                lines.append(line)
                if line[-leneol:] != eol:    # was the line received with a timeout?
                    break
            else:
                break
        return lines

    def xreadlines(self, sizehint=None):
        """Read lines, implemented as generator. It will raise StopIteration on
        timeout (empty read). sizehint is ignored."""
        while True:
            line = self.readline()
            if not line: break
            yield line

    # other functions of file-likes - not used by pySerial

    #~ readinto(b)

    def seek(self, pos, whence=0):
        raise IOError("file is not seekable")

    def tell(self):
        raise IOError("file is not seekable")

    def truncate(self, n=None):
        raise IOError("file is not seekable")

    def isatty(self):
        return False


class SerialBase(object):
    """Serial port base class. Provides __init__ function and properties to
       get/set port settings."""

    # default values, may be overridden in subclasses that do not support all values
    BAUDRATES = (50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800,
                 9600, 19200, 38400, 57600, 115200, 230400, 460800, 500000,
                 576000, 921600, 1000000, 1152000, 1500000, 2000000, 2500000,
                 3000000, 3500000, 4000000)
    BYTESIZES = (FIVEBITS, SIXBITS, SEVENBITS, EIGHTBITS)
    PARITIES  = (PARITY_NONE, PARITY_EVEN, PARITY_ODD, PARITY_MARK, PARITY_SPACE)
    STOPBITS  = (STOPBITS_ONE, STOPBITS_ONE_POINT_FIVE, STOPBITS_TWO)

    def __init__(self,
                 port = None,           # number of device, numbering starts at
                                        # zero. if everything fails, the user
                                        # can specify a device string, note
                                        # that this isn't portable anymore
                                        # port will be opened if one is specified
                 baudrate=9600,         # baud rate
                 bytesize=EIGHTBITS,    # number of data bits
                 parity=PARITY_NONE,    # enable parity checking
                 stopbits=STOPBITS_ONE, # number of stop bits
                 timeout=None,          # set a timeout value, None to wait forever
                 xonxoff=False,         # enable software flow control
                 rtscts=False,          # enable RTS/CTS flow control
                 writeTimeout=None,     # set a timeout for writes
                 dsrdtr=False,          # None: use rtscts setting, dsrdtr override if True or False
                 interCharTimeout=None  # Inter-character timeout, None to disable
                 ):
        """Initialize comm port object. If a port is given, then the port will be
           opened immediately. Otherwise a Serial port object in closed state
           is returned."""

        self._isOpen   = False
        self._port     = None           # correct value is assigned below through properties
        self._baudrate = None           # correct value is assigned below through properties
        self._bytesize = None           # correct value is assigned below through properties
        self._parity   = None           # correct value is assigned below through properties
        self._stopbits = None           # correct value is assigned below through properties
        self._timeout  = None           # correct value is assigned below through properties
        self._writeTimeout = None       # correct value is assigned below through properties
        self._xonxoff  = None           # correct value is assigned below through properties
        self._rtscts   = None           # correct value is assigned below through properties
        self._dsrdtr   = None           # correct value is assigned below through properties
        self._interCharTimeout = None   # correct value is assigned below through properties

        # assign values using get/set methods using the properties feature
        self.port     = port
        self.baudrate = baudrate
        self.bytesize = bytesize
        self.parity   = parity
        self.stopbits = stopbits
        self.timeout  = timeout
        self.writeTimeout = writeTimeout
        self.xonxoff  = xonxoff
        self.rtscts   = rtscts
        self.dsrdtr   = dsrdtr
        self.interCharTimeout = interCharTimeout

        if port is not None:
            self.open()

    def isOpen(self):
        """Check if the port is opened."""
        return self._isOpen

    #  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -

    # TODO: these are not really needed as the is the BAUDRATES etc. attribute...
    # maybe i remove them before the final release...

    def getSupportedBaudrates(self):
        return [(str(b), b) for b in self.BAUDRATES]

    def getSupportedByteSizes(self):
        return [(str(b), b) for b in self.BYTESIZES]

    def getSupportedStopbits(self):
        return [(str(b), b) for b in self.STOPBITS]

    def getSupportedParities(self):
        return [(PARITY_NAMES[b], b) for b in self.PARITIES]

    #  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -

    def setPort(self, port):
        """Change the port. The attribute portstr is set to a string that
           contains the name of the port."""

        was_open = self._isOpen
        if was_open: self.close()
        if port is not None:
            if isinstance(port, basestring):
                self.portstr = port
            else:
                self.portstr = self.makeDeviceName(port)
        else:
            self.portstr = None
        self._port = port
        self.name = self.portstr
        if was_open: self.open()

    def getPort(self):
        """Get the current port setting. The value that was passed on init or using
           setPort() is passed back. See also the attribute portstr which contains
           the name of the port as a string."""
        return self._port

    port = property(getPort, setPort, doc="Port setting")


    def setBaudrate(self, baudrate):
        """Change baud rate. It raises a ValueError if the port is open and the
        baud rate is not possible. If the port is closed, then the value is
        accepted and the exception is raised when the port is opened."""
        try:
            b = int(baudrate)
        except TypeError:
            raise ValueError("Not a valid baudrate: %r" % (baudrate,))
        else:
            if b <= 0:
                raise ValueError("Not a valid baudrate: %r" % (baudrate,))
            self._baudrate = b
            if self._isOpen:  self._reconfigurePort()

    def getBaudrate(self):
        """Get the current baud rate setting."""
        return self._baudrate

    baudrate = property(getBaudrate, setBaudrate, doc="Baud rate setting")


    def setByteSize(self, bytesize):
        """Change byte size."""
        if bytesize not in self.BYTESIZES: raise ValueError("Not a valid byte size: %r" % (bytesize,))
        self._bytesize = bytesize
        if self._isOpen: self._reconfigurePort()

    def getByteSize(self):
        """Get the current byte size setting."""
        return self._bytesize

    bytesize = property(getByteSize, setByteSize, doc="Byte size setting")


    def setParity(self, parity):
        """Change parity setting."""
        if parity not in self.PARITIES: raise ValueError("Not a valid parity: %r" % (parity,))
        self._parity = parity
        if self._isOpen: self._reconfigurePort()

    def getParity(self):
        """Get the current parity setting."""
        return self._parity

    parity = property(getParity, setParity, doc="Parity setting")


    def setStopbits(self, stopbits):
        """Change stop bits size."""
        if stopbits not in self.STOPBITS: raise ValueError("Not a valid stop bit size: %r" % (stopbits,))
        self._stopbits = stopbits
        if self._isOpen: self._reconfigurePort()

    def getStopbits(self):
        """Get the current stop bits setting."""
        return self._stopbits

    stopbits = property(getStopbits, setStopbits, doc="Stop bits setting")


    def setTimeout(self, timeout):
        """Change timeout setting."""
        if timeout is not None:
            try:
                timeout + 1     # test if it's a number, will throw a TypeError if not...
            except TypeError:
                raise ValueError("Not a valid timeout: %r" % (timeout,))
            if timeout < 0: raise ValueError("Not a valid timeout: %r" % (timeout,))
        self._timeout = timeout
        if self._isOpen: self._reconfigurePort()

    def getTimeout(self):
        """Get the current timeout setting."""
        return self._timeout

    timeout = property(getTimeout, setTimeout, doc="Timeout setting for read()")


    def setWriteTimeout(self, timeout):
        """Change timeout setting."""
        if timeout is not None:
            if timeout < 0: raise ValueError("Not a valid timeout: %r" % (timeout,))
            try:
                timeout + 1     #test if it's a number, will throw a TypeError if not...
            except TypeError:
                raise ValueError("Not a valid timeout: %r" % timeout)

        self._writeTimeout = timeout
        if self._isOpen: self._reconfigurePort()

    def getWriteTimeout(self):
        """Get the current timeout setting."""
        return self._writeTimeout

    writeTimeout = property(getWriteTimeout, setWriteTimeout, doc="Timeout setting for write()")


    def setXonXoff(self, xonxoff):
        """Change XON/XOFF setting."""
        self._xonxoff = xonxoff
        if self._isOpen: self._reconfigurePort()

    def getXonXoff(self):
        """Get the current XON/XOFF setting."""
        return self._xonxoff

    xonxoff = property(getXonXoff, setXonXoff, doc="XON/XOFF setting")

    def setRtsCts(self, rtscts):
        """Change RTS/CTS flow control setting."""
        self._rtscts = rtscts
        if self._isOpen: self._reconfigurePort()

    def getRtsCts(self):
        """Get the current RTS/CTS flow control setting."""
        return self._rtscts

    rtscts = property(getRtsCts, setRtsCts, doc="RTS/CTS flow control setting")

    def setDsrDtr(self, dsrdtr=None):
        """Change DsrDtr flow control setting."""
        if dsrdtr is None:
            # if not set, keep backwards compatibility and follow rtscts setting
            self._dsrdtr = self._rtscts
        else:
            # if defined independently, follow its value
            self._dsrdtr = dsrdtr
        if self._isOpen: self._reconfigurePort()

    def getDsrDtr(self):
        """Get the current DSR/DTR flow control setting."""
        return self._dsrdtr

    dsrdtr = property(getDsrDtr, setDsrDtr, "DSR/DTR flow control setting")

    def setInterCharTimeout(self, interCharTimeout):
        """Change inter-character timeout setting."""
        if interCharTimeout is not None:
            if interCharTimeout < 0: raise ValueError("Not a valid timeout: %r" % interCharTimeout)
            try:
                interCharTimeout + 1     # test if it's a number, will throw a TypeError if not...
            except TypeError:
                raise ValueError("Not a valid timeout: %r" % interCharTimeout)

        self._interCharTimeout = interCharTimeout
        if self._isOpen: self._reconfigurePort()

    def getInterCharTimeout(self):
        """Get the current inter-character timeout setting."""
        return self._interCharTimeout

    interCharTimeout = property(getInterCharTimeout, setInterCharTimeout, doc="Inter-character timeout setting for read()")

    #  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -

    _SETTINGS = ('baudrate', 'bytesize', 'parity', 'stopbits', 'xonxoff',
            'dsrdtr', 'rtscts', 'timeout', 'writeTimeout', 'interCharTimeout')

    def getSettingsDict(self):
        """Get current port settings as a dictionary. For use with
        applySettingsDict"""
        return dict([(key, getattr(self, '_'+key)) for key in self._SETTINGS])

    def applySettingsDict(self, d):
        """apply stored settings from a dictionary returned from
        getSettingsDict. it's allowed to delete keys from the dictionary. these
        values will simply left unchanged."""
        for key in self._SETTINGS:
            if d[key] != getattr(self, '_'+key):   # check against internal "_" value
                setattr(self, key, d[key])          # set non "_" value to use properties write function

    #  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -

    def __repr__(self):
        """String representation of the current port settings and its state."""
        return "%s<id=0x%x, open=%s>(port=%r, baudrate=%r, bytesize=%r, parity=%r, stopbits=%r, timeout=%r, xonxoff=%r, rtscts=%r, dsrdtr=%r)" % (
            self.__class__.__name__,
            id(self),
            self._isOpen,
            self.portstr,
            self.baudrate,
            self.bytesize,
            self.parity,
            self.stopbits,
            self.timeout,
            self.xonxoff,
            self.rtscts,
            self.dsrdtr,
        )


    #  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -
    # compatibility with io library

    def readable(self): return True
    def writable(self): return True
    def seekable(self): return False
    def readinto(self, b):
        data = self.read(len(b))
        n = len(data)
        try:
            b[:n] = data
        except TypeError, err:
            import array
            if not isinstance(b, array.array):
                raise err
            b[:n] = array.array('b', data)
        return n


if __name__ == '__main__':
    import sys
    s = SerialBase()
    sys.stdout.write('port name:  %s\n' % s.portstr)
    sys.stdout.write('baud rates: %s\n' % s.getSupportedBaudrates())
    sys.stdout.write('byte sizes: %s\n' % s.getSupportedByteSizes())
    sys.stdout.write('parities:   %s\n' % s.getSupportedParities())
    sys.stdout.write('stop bits:  %s\n' % s.getSupportedStopbits())
    sys.stdout.write('%s\n' % s)
