#! python
#
# Python Serial Port Extension for Win32, Linux, BSD, Jython
# see __init__.py
#
# This module implements a special URL handler that uses the port listing to
# find ports by searching the string descriptions.
#
# (C) 2011 Chris Liechti <cliechti@gmx.net>
# this is distributed under a free software license, see license.txt
#
# URL format:    hwgrep://regexp

import serial
import serial.tools.list_ports

class Serial(serial.Serial):
    """Just inherit the native Serial port implementation and patch the open function."""

    def setPort(self, value):
        """translate port name before storing it"""
        if isinstance(value, basestring) and value.startswith('hwgrep://'):
            serial.Serial.setPort(self, self.fromURL(value))
        else:
            serial.Serial.setPort(self, value)

    def fromURL(self, url):
        """extract host and port from an URL string"""
        if url.lower().startswith("hwgrep://"): url = url[9:]
        # use a for loop to get the 1st element from the generator
        for port, desc, hwid in serial.tools.list_ports.grep(url):
            return port
        else:
            raise serial.SerialException('no ports found matching regexp %r' % (url,))

    # override property
    port = property(serial.Serial.getPort, setPort, doc="Port setting")

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
if __name__ == '__main__':
    #~ s = Serial('hwgrep://ttyS0')
    s = Serial(None)
    s.port = 'hwgrep://ttyS0'
    print s

