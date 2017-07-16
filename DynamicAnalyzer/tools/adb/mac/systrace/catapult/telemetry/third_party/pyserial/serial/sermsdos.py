# sermsdos.py
#
# History:
#
#   3rd September 2002                      Dave Haynes
#   1. First defined
#
# Although this code should run under the latest versions of
# Python, on DOS-based platforms such as Windows 95 and 98,
# it has been specifically written to be compatible with
# PyDOS, available at:
# http://www.python.org/ftp/python/wpy/dos.html
#
# PyDOS is a stripped-down version of Python 1.5.2 for
# DOS machines. Therefore, in making changes to this file,
# please respect Python 1.5.2 syntax. In addition, please
# limit the width of this file to 60 characters.
#
# Note also that the modules in PyDOS contain fewer members
# than other versions, so we are restricted to using the
# following:
#
# In module os:
# -------------
# environ, chdir, getcwd, getpid, umask, fdopen, close,
# dup, dup2, fstat, lseek, open, read, write, O_RDONLY,
# O_WRONLY, O_RDWR, O_APPEND, O_CREAT, O_EXCL, O_TRUNC,
# access, F_OK, R_OK, W_OK, X_OK, chmod, listdir, mkdir,
# remove, rename, renames, rmdir, stat, unlink, utime,
# execl, execle, execlp, execlpe, execvp, execvpe, _exit,
# system.
#
# In module os.path:
# ------------------
# curdir, pardir, sep, altsep, pathsep, defpath, linesep.
#

import os
import sys
import string
import serial.serialutil

BAUD_RATES = {
                110: "11",
                150: "15",
                300: "30",
                600: "60",
                1200: "12",
                2400: "24",
                4800: "48",
                9600: "96",
                19200: "19"}

(PARITY_NONE, PARITY_EVEN, PARITY_ODD, PARITY_MARK,
PARITY_SPACE) = (0, 1, 2, 3, 4)
(STOPBITS_ONE, STOPBITS_ONEANDAHALF,
STOPBITS_TWO) = (1, 1.5, 2)
FIVEBITS, SIXBITS, SEVENBITS, EIGHTBITS = (5, 6, 7, 8)
(RETURN_ERROR, RETURN_BUSY, RETURN_RETRY, RETURN_READY,
RETURN_NONE) = ('E', 'B', 'P', 'R', 'N')
portNotOpenError = ValueError('port not open')

def device(portnum):
    return 'COM%d' % (portnum+1)

class Serial(serialutil.FileLike):
    """
       port: number of device; numbering starts at
            zero. if everything fails, the user can
            specify a device string, note that this
            isn't portable any more
       baudrate: baud rate
       bytesize: number of databits
       parity: enable parity checking
       stopbits: number of stopbits
       timeout: set a timeout (None for waiting forever)
       xonxoff: enable software flow control
       rtscts: enable RTS/CTS flow control
       retry: DOS retry mode
    """
    def __init__(self,
                 port,
                 baudrate = 9600,
                 bytesize = EIGHTBITS,
                 parity = PARITY_NONE,
                 stopbits = STOPBITS_ONE,
                 timeout = None,
                 xonxoff = 0,
                 rtscts = 0,
                 retry = RETURN_RETRY
                 ):

        if type(port) == type(''):
        # strings are taken directly
            self.portstr = port
        else:
        # numbers are transformed to a string
            self.portstr = device(port+1)

        self.baud = BAUD_RATES[baudrate]
        self.bytesize = str(bytesize)

        if parity == PARITY_NONE:
            self.parity = 'N'
        elif parity == PARITY_EVEN:
            self.parity = 'E'
        elif parity == PARITY_ODD:
            self.parity = 'O'
        elif parity == PARITY_MARK:
            self.parity = 'M'
        elif parity == PARITY_SPACE:
            self.parity = 'S'

        self.stop = str(stopbits)
        self.retry = retry
        self.filename = "sermsdos.tmp"

        self._config(self.portstr, self.baud, self.parity,
        self.bytesize, self.stop, self.retry, self.filename)

    def __del__(self):
        self.close()

    def close(self):
        pass

    def _config(self, port, baud, parity, data, stop, retry,
        filename):
        comString = string.join(("MODE ", port, ":"
        , " BAUD= ", baud, " PARITY= ", parity
        , " DATA= ", data, " STOP= ", stop, " RETRY= ",
        retry, " > ", filename ), '')
        os.system(comString)

    def setBaudrate(self, baudrate):
        self._config(self.portstr, BAUD_RATES[baudrate],
        self.parity, self.bytesize, self.stop, self.retry,
        self.filename)

    def inWaiting(self):
        """returns the number of bytes waiting to be read"""
        raise NotImplementedError

    def read(self, num = 1):
        """Read num bytes from serial port"""
        handle = os.open(self.portstr,
        os.O_RDONLY | os.O_BINARY)
        rv = os.read(handle, num)
        os.close(handle)
        return rv

    def write(self, s):
        """Write string to serial port"""
        handle = os.open(self.portstr,
        os.O_WRONLY | os.O_BINARY)
        rv = os.write(handle, s)
        os.close(handle)
        return rv

    def flushInput(self):
        raise NotImplementedError

    def flushOutput(self):
        raise NotImplementedError

    def sendBreak(self):
        raise NotImplementedError

    def setRTS(self,level=1):
        """Set terminal status line"""
        raise NotImplementedError

    def setDTR(self,level=1):
        """Set terminal status line"""
        raise NotImplementedError

    def getCTS(self):
        """Eead terminal status line"""
        raise NotImplementedError

    def getDSR(self):
        """Eead terminal status line"""
        raise NotImplementedError

    def getRI(self):
        """Eead terminal status line"""
        raise NotImplementedError

    def getCD(self):
        """Eead terminal status line"""
        raise NotImplementedError

    def __repr__(self):
        return string.join(( "<Serial>: ", self.portstr
        , self.baud, self.parity, self.bytesize, self.stop,
        self.retry , self.filename), ' ')

if __name__ == '__main__':
    s = Serial(0)
    sys.stdio.write('%s %s\n' % (__name__, s))
