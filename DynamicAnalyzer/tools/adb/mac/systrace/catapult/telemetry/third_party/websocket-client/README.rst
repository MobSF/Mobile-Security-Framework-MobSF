=================
websocket-client
=================

**Our repository has moved to https://github.com/websocket-client/websocket-client**

websocket-client module  is WebSocket client for python. This provide the low level APIs for WebSocket. All APIs are the synchronous functions.

websocket-client supports only hybi-13.


License
============

 - LGPL

Installation
=============

This module is tested on Python 2.7 and Python 3.x.

Type "python setup.py install" or "pip install websocket-client" to install.

.. CAUTION::

  from v0.16.0, we can install by "pip install websocket-client" for python 3.

This module depend on

 - six
 - backports.ssl_match_hostname for Python 2.x

How about Python 3
===========================

Now, we support python 3 on  single source code from version 0.14.0. Thanks, @battlemidget and @ralphbean.

HTTP Proxy
=============

Support websocket access via http proxy.
The proxy server must allow "CONNECT" method to websocket port.
Default squid setting is "ALLOWED TO CONNECT ONLY HTTPS PORT".

Current implementation of websocket-client is using "CONNECT" method via proxy.


example

.. code:: python

    import websocket
    ws = websocket.WebSocket()
    ws.connect("ws://example.com/websocket", http_proxy_host="proxy_host_name", http_proxy_port=3128)
    :



Examples
========

Long-lived connection
---------------------
This example is similar to how WebSocket code looks in browsers using JavaScript.

.. code:: python

    import websocket
    import thread
    import time

    def on_message(ws, message):
        print message

    def on_error(ws, error):
        print error

    def on_close(ws):
        print "### closed ###"

    def on_open(ws):
        def run(*args):
            for i in range(3):
                time.sleep(1)
                ws.send("Hello %d" % i)
            time.sleep(1)
            ws.close()
            print "thread terminating..."
        thread.start_new_thread(run, ())


    if __name__ == "__main__":
        websocket.enableTrace(True)
        ws = websocket.WebSocketApp("ws://echo.websocket.org/",
                                  on_message = on_message,
                                  on_error = on_error,
                                  on_close = on_close)
        ws.on_open = on_open
        ws.run_forever()


Short-lived one-off send-receive
--------------------------------
This is if you want to communicate a short message and disconnect immediately when done.

.. code:: python

    from websocket import create_connection
    ws = create_connection("ws://echo.websocket.org/")
    print "Sending 'Hello, World'..."
    ws.send("Hello, World")
    print "Sent"
    print "Receiving..."
    result =  ws.recv()
    print "Received '%s'" % result
    ws.close()

If you want to customize socket options, set sockopt.

sockopt example

.. code:: python

    from websocket import create_connection
    ws = create_connection("ws://echo.websocket.org/",
                            sockopt=((socket.IPPROTO_TCP, socket.TCP_NODELAY),))


More advanced: Custom class
---------------------------
You can also write your own class for the connection, if you want to handle the nitty-gritty details yourself.

.. code:: python

    from websocket import create_connection, WebSocket
    class MyWebSocket(WebSocket):
        def recv_frame(self):
            frame = super().recv_frame()
            print('yay! I got this frame: ', frame)
            return frame

    ws = create_connection("ws://echo.websocket.org/",
                            sockopt=((socket.IPPROTO_TCP, socket.TCP_NODELAY),), class_=MyWebSocket)


FAQ
============

How to disable ssl cert verification?
----------------------------------------

Please set sslopt to {"cert_reqs": ssl.CERT_NONE}.

WebSocketApp sample

.. code:: python

    ws = websocket.WebSocketApp("wss://echo.websocket.org")
    ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})

create_connection sample

.. code:: python

    ws = websocket.create_connection("wss://echo.websocket.org",
      sslopt={"cert_reqs": ssl.CERT_NONE})

WebSocket sample

.. code:: python

    ws = websocket.WebSocket(sslopt={"cert_reqs": ssl.CERT_NONE})
    ws.connect("wss://echo.websocket.org")


How to disable hostname verification.
----------------------------------------

Please set sslopt to {"check_hostname": False}.
(since v0.18.0)

WebSocketApp sample

.. code:: python

    ws = websocket.WebSocketApp("wss://echo.websocket.org")
    ws.run_forever(sslopt={"check_hostname": False})

create_connection sample

.. code:: python

    ws = websocket.create_connection("wss://echo.websocket.org",
      sslopt={"check_hostname": False})

WebSocket sample

.. code:: python

    ws = websocket.WebSocket(sslopt={"check_hostname": False})
    ws.connect("wss://echo.websocket.org")


How to enable `SNI <http://en.wikipedia.org/wiki/Server_Name_Indication>`_?
---------------------------------------------------------------------------

SNI support is available for Python 2.7.9+ and 3.2+. It will be enabled automatically whenever possible.


Sub Protocols.
----------------------------------------

The server needs to support sub protocols, please set the subprotocol like this.


Subprotocol sample

.. code:: python

    ws = websocket.create_connection("ws://exapmle.com/websocket", subprotocols=["binary", "base64"])



wsdump.py
============

wsdump.py is simple WebSocket test(debug) tool.

sample for echo.websocket.org::

  $ wsdump.py ws://echo.websocket.org/
  Press Ctrl+C to quit
  > Hello, WebSocket
  < Hello, WebSocket
  > How are you?
  < How are you?

Usage
---------

usage::

  wsdump.py [-h] [-v [VERBOSE]] ws_url

WebSocket Simple Dump Tool

positional arguments:
  ws_url                websocket url. ex. ws://echo.websocket.org/

optional arguments:
  -h, --help                           show this help message and exit
WebSocketApp
  -v VERBOSE, --verbose VERBOSE    set verbose mode. If set to 1, show opcode. If set to 2, enable to trace websocket module

example::

  $ wsdump.py ws://echo.websocket.org/
  $ wsdump.py ws://echo.websocket.org/ -v
  $ wsdump.py ws://echo.websocket.org/ -vv

