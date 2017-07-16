#! python
#
# Python Serial Port Extension for Win32, Linux, BSD, Jython
# see __init__.py
#
# This module implements a simple socket based client.
# It does not support changing any port parameters and will silently ignore any
# requests to do so.
#
# The purpose of this module is that applications using pySerial can connect to
# TCP/IP to serial port converters that do not support RFC 2217.
#
# (C) 2001-2011 Chris Liechti <cliechti@gmx.net>
# this is distributed under a free software license, see license.txt
#
# URL format:    socket://<host>:<port>[/option[/option...]]
# options:
# - "debug" print diagnostic messages

from serial.serialutil import *
import time
import socket
import logging

# map log level names to constants. used in fromURL()
LOGGER_LEVELS = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    }

POLL_TIMEOUT = 2

class SocketSerial(SerialBase):
    """Serial port implementation for plain sockets."""

    BAUDRATES = (50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800,
                 9600, 19200, 38400, 57600, 115200)

    def open(self):
        """Open port with current settings. This may throw a SerialException
           if the port cannot be opened."""
        self.logger = None
        if self._port is None:
            raise SerialException("Port must be configured before it can be used.")
        if self._isOpen:
            raise SerialException("Port is already open.")
        try:
            # XXX in future replace with create_connection (py >=2.6)
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.connect(self.fromURL(self.portstr))
        except Exception, msg:
            self._socket = None
            raise SerialException("Could not open port %s: %s" % (self.portstr, msg))

        self._socket.settimeout(POLL_TIMEOUT) # used for write timeout support :/

        # not that there anything to configure...
        self._reconfigurePort()
        # all things set up get, now a clean start
        self._isOpen = True
        if not self._rtscts:
            self.setRTS(True)
            self.setDTR(True)
        self.flushInput()
        self.flushOutput()

    def _reconfigurePort(self):
        """Set communication parameters on opened port. for the socket://
        protocol all settings are ignored!"""
        if self._socket is None:
            raise SerialException("Can only operate on open ports")
        if self.logger:
            self.logger.info('ignored port configuration change')

    def close(self):
        """Close port"""
        if self._isOpen:
            if self._socket:
                try:
                    self._socket.shutdown(socket.SHUT_RDWR)
                    self._socket.close()
                except:
                    # ignore errors.
                    pass
                self._socket = None
            self._isOpen = False
            # in case of quick reconnects, give the server some time
            time.sleep(0.3)

    def makeDeviceName(self, port):
        raise SerialException("there is no sensible way to turn numbers into URLs")

    def fromURL(self, url):
        """extract host and port from an URL string"""
        if url.lower().startswith("socket://"): url = url[9:]
        try:
            # is there a "path" (our options)?
            if '/' in url:
                # cut away options
                url, options = url.split('/', 1)
                # process options now, directly altering self
                for option in options.split('/'):
                    if '=' in option:
                        option, value = option.split('=', 1)
                    else:
                        value = None
                    if option == 'logging':
                        logging.basicConfig()   # XXX is that good to call it here?
                        self.logger = logging.getLogger('pySerial.socket')
                        self.logger.setLevel(LOGGER_LEVELS[value])
                        self.logger.debug('enabled logging')
                    else:
                        raise ValueError('unknown option: %r' % (option,))
            # get host and port
            host, port = url.split(':', 1) # may raise ValueError because of unpacking
            port = int(port)               # and this if it's not a number
            if not 0 <= port < 65536: raise ValueError("port not in range 0...65535")
        except ValueError, e:
            raise SerialException('expected a string in the form "[rfc2217://]<host>:<port>[/option[/option...]]": %s' % e)
        return (host, port)

    #  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -

    def inWaiting(self):
        """Return the number of characters currently in the input buffer."""
        if not self._isOpen: raise portNotOpenError
        if self.logger:
            # set this one to debug as the function could be called often...
            self.logger.debug('WARNING: inWaiting returns dummy value')
        return 0 # hmmm, see comment in read()

    def read(self, size=1):
        """Read size bytes from the serial port. If a timeout is set it may
        return less characters as requested. With no timeout it will block
        until the requested number of bytes is read."""
        if not self._isOpen: raise portNotOpenError
        data = bytearray()
        if self._timeout is not None:
            timeout = time.time() + self._timeout
        else:
            timeout = None
        while len(data) < size and (timeout is None or time.time() < timeout):
            try:
                # an implementation with internal buffer would be better
                # performing...
                t = time.time()
                block = self._socket.recv(size - len(data))
                duration = time.time() - t
                if block:
                    data.extend(block)
                else:
                    # no data -> EOF (connection probably closed)
                    break
            except socket.timeout:
                # just need to get out of recv from time to time to check if
                # still alive
                continue
            except socket.error, e:
                # connection fails -> terminate loop
                raise SerialException('connection failed (%s)' % e)
        return bytes(data)

    def write(self, data):
        """Output the given string over the serial port. Can block if the
        connection is blocked. May raise SerialException if the connection is
        closed."""
        if not self._isOpen: raise portNotOpenError
        try:
            self._socket.sendall(to_bytes(data))
        except socket.error, e:
            # XXX what exception if socket connection fails
            raise SerialException("socket connection failed: %s" % e)
        return len(data)

    def flushInput(self):
        """Clear input buffer, discarding all that is in the buffer."""
        if not self._isOpen: raise portNotOpenError
        if self.logger:
            self.logger.info('ignored flushInput')

    def flushOutput(self):
        """Clear output buffer, aborting the current output and
        discarding all that is in the buffer."""
        if not self._isOpen: raise portNotOpenError
        if self.logger:
            self.logger.info('ignored flushOutput')

    def sendBreak(self, duration=0.25):
        """Send break condition. Timed, returns to idle state after given
        duration."""
        if not self._isOpen: raise portNotOpenError
        if self.logger:
            self.logger.info('ignored sendBreak(%r)' % (duration,))

    def setBreak(self, level=True):
        """Set break: Controls TXD. When active, to transmitting is
        possible."""
        if not self._isOpen: raise portNotOpenError
        if self.logger:
            self.logger.info('ignored setBreak(%r)' % (level,))

    def setRTS(self, level=True):
        """Set terminal status line: Request To Send"""
        if not self._isOpen: raise portNotOpenError
        if self.logger:
            self.logger.info('ignored setRTS(%r)' % (level,))

    def setDTR(self, level=True):
        """Set terminal status line: Data Terminal Ready"""
        if not self._isOpen: raise portNotOpenError
        if self.logger:
            self.logger.info('ignored setDTR(%r)' % (level,))

    def getCTS(self):
        """Read terminal status line: Clear To Send"""
        if not self._isOpen: raise portNotOpenError
        if self.logger:
            self.logger.info('returning dummy for getCTS()')
        return True

    def getDSR(self):
        """Read terminal status line: Data Set Ready"""
        if not self._isOpen: raise portNotOpenError
        if self.logger:
            self.logger.info('returning dummy for getDSR()')
        return True

    def getRI(self):
        """Read terminal status line: Ring Indicator"""
        if not self._isOpen: raise portNotOpenError
        if self.logger:
            self.logger.info('returning dummy for getRI()')
        return False

    def getCD(self):
        """Read terminal status line: Carrier Detect"""
        if not self._isOpen: raise portNotOpenError
        if self.logger:
            self.logger.info('returning dummy for getCD()')
        return True

    # - - - platform specific - - -
    # None so far


# assemble Serial class with the platform specific implementation and the base
# for file-like behavior. for Python 2.6 and newer, that provide the new I/O
# library, derive from io.RawIOBase
try:
    import io
except ImportError:
    # classic version with our own file-like emulation
    class Serial(SocketSerial, FileLike):
        pass
else:
    # io library present
    class Serial(SocketSerial, io.RawIOBase):
        pass


# simple client test
if __name__ == '__main__':
    import sys
    s = Serial('socket://localhost:7000')
    sys.stdout.write('%s\n' % s)

    sys.stdout.write("write...\n")
    s.write("hello\n")
    s.flush()
    sys.stdout.write("read: %s\n" % s.read(5))

    s.close()
