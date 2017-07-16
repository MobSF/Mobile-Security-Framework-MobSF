#!/usr/bin/env python 

# portable serial port access with python
# this is a wrapper module for different platform implementations
#
# (C) 2001-2010 Chris Liechti <cliechti@gmx.net>
# this is distributed under a free software license, see license.txt

VERSION = '2.7'

import sys

if sys.platform == 'cli':
    from serial.serialcli import *
else:
    import os
    # chose an implementation, depending on os
    if os.name == 'nt': #sys.platform == 'win32':
        from serial.serialwin32 import *
    elif os.name == 'posix':
        from serial.serialposix import *
    elif os.name == 'java':
        from serial.serialjava import *
    else:
        raise ImportError("Sorry: no implementation for your platform ('%s') available" % (os.name,))


protocol_handler_packages = [
        'serial.urlhandler',
        ]

def serial_for_url(url, *args, **kwargs):
    """\
    Get an instance of the Serial class, depending on port/url. The port is not
    opened when the keyword parameter 'do_not_open' is true, by default it
    is. All other parameters are directly passed to the __init__ method when
    the port is instantiated.

    The list of package names that is searched for protocol handlers is kept in
    ``protocol_handler_packages``.

    e.g. we want to support a URL ``foobar://``. A module
    ``my_handlers.protocol_foobar`` is provided by the user. Then
    ``protocol_handler_packages.append("my_handlers")`` would extend the search
    path so that ``serial_for_url("foobar://"))`` would work.
    """
    # check remove extra parameter to not confuse the Serial class
    do_open = 'do_not_open' not in kwargs or not kwargs['do_not_open']
    if 'do_not_open' in kwargs: del kwargs['do_not_open']
    # the default is to use the native version
    klass = Serial   # 'native' implementation
    # check port type and get class
    try:
        url_nocase = url.lower()
    except AttributeError:
        # it's not a string, use default
        pass
    else:
        if '://' in url_nocase:
            protocol = url_nocase.split('://', 1)[0]
            for package_name in protocol_handler_packages:
                module_name = '%s.protocol_%s' % (package_name, protocol,)
                try:
                    handler_module = __import__(module_name)
                except ImportError:
                    pass
                else:
                    klass = sys.modules[module_name].Serial
                    break
            else:
                raise ValueError('invalid URL, protocol %r not known' % (protocol,))
        else:
            klass = Serial   # 'native' implementation
    # instantiate and open when desired
    instance = klass(None, *args, **kwargs)
    instance.port = url
    if do_open:
        instance.open()
    return instance
