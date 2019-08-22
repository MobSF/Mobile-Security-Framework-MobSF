# -*- coding: utf_8 -*-
"""Frida tests."""
import sys
import time

import frida


def frida_response(message, data):
    """Function to handle frida responses."""
    print('message')
    print(message)
    print('data')
    print(data)


def frida_connection(identifier, package, tscript):
    """Connect to Frida Server."""
    scripts_dir = ('/Users/ajinabraham/Code/'
                   'Mobile-Security-Framework-'
                   'MobSF/DynamicAnalyzer/tools/frida_scripts/')
    frida_script = scripts_dir + tscript
    session = None
    try:
        device = frida.get_device(identifier, 3)
        process = device.spawn([package])
        device.resume(process)
        time.sleep(1)
        session = device.attach(process)
    except frida.ServerNotRunningError:
        print('Frida Server is not Running')
    except frida.TimedOutError:
        print('timed out while waiting for device to appear')
    try:
        if session:
            script = session.create_script(open(frida_script).read())
            script.on('message', frida_response)
            script.load()
            sys.stdin.read()
    except Exception as exp:
        print(exp)
    except KeyboardInterrupt:
        print('Clean')
        if script:
            script.unload()
        session.detach()


frida_connection('192.168.56.113:5555',
                 'com.droid4you.application.wallet',
                 'test.js')
