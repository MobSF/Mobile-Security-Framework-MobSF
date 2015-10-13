#!/usr/bin/env python
'''
owtf is an OWASP+PTES-focused try to unite great tools & facilitate pentesting
Copyright (c) 2013, Abraham Aranguren <name.surname@gmail.com>  http://7-a.org
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the copyright owner nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Inbound Proxy Module developed by Bharadwaj Machiraju (blog.tunnelshade.in)
#                     as a part of Google Summer of Code 2013
'''
import tornado.httpserver
import tornado.ioloop
import tornado.iostream
import tornado.web
import tornado.httpclient

import tornado.escape
import tornado.httputil
import tornado.options
import tornado.template
import tornado.websocket
import tornado.gen
import socket
import ssl
import os
import datetime
import uuid
import re,sys
from multiprocessing import Process, Value, Lock
from socket_wrapper import wrap_socket
LOG=''
 #This function create logs
def Logz(request,response,log):
    TRAFFIC=''
    rdat=''
    dat=response.request.body if response.request.body else ''
    TRAFFIC+= "\n\nREQUEST: " + str(response.request.method)+ " " + str(response.request.url) + '\n'
    for header, value in list(request.headers.items()):
        TRAFFIC+= header + ": " + value +"\n"
    TRAFFIC+= "\n\n" + str(dat) + "\n"
    TRAFFIC+= "\n\nRESPONSE: " +str(response.code) + " " + str(response.reason) + "\n"
    for header, value in list(response.headers.items()):
        TRAFFIC+= header + ": " + value + "\n"
        if "content-type" in header.lower():
            if re.findall("json|xml|application\/javascript",value.lower()):
                rdat=request.response_buffer
        else:
            rdat=''
    TRAFFIC+= "\n\n" +str(rdat) + "\n"
    #print TRAFFIC
    with open(log,'a') as f:
        f.write(TRAFFIC)



class ProxyHandler(tornado.web.RequestHandler):
    """
    This RequestHandler processes all the requests that the application received
    """
    SUPPORTED_METHODS = ['GET', 'POST', 'CONNECT', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'TRACE']

    def __new__(cls, application, request, **kwargs):
        # http://stackoverflow.com/questions/3209233/how-to-replace-an-instance-in-init-with-a-different-object
        # Based on upgrade header, websocket request handler must be used
        try:
            if request.headers['Upgrade'].lower() == 'websocket':
                return CustomWebSocketHandler(application, request, **kwargs)
        except KeyError:
            pass
        return tornado.web.RequestHandler.__new__(cls, application, request, **kwargs)

    def set_default_headers(self):
        # This is automatically called by Tornado :P
        # XD Using this to remove "Server" header set by tornado
        del self._headers["Server"]

    def set_status(self, status_code, reason=None):
        """
        Sets the status code for our response.
        Overriding is done so as to handle unknown
        response codes gracefully.
        """
        self._status_code = status_code
        if reason is not None:
            self._reason = tornado.escape.native_str(reason)
        else:
            try:
                self._reason = tornado.httputil.responses[status_code]
            except KeyError:
                self._reason = tornado.escape.native_str("Server Not Found")
    # This function writes a new response & caches it
    def finish_response(self, response):
        Logz(self.request,response,LOG)
        self.set_status(response.code)
        for header, value in list(response.headers.items()):
            if header == "Set-Cookie":
                self.add_header(header, value)
            else:
                if header not in restricted_response_headers:
                    self.set_header(header, value)
        self.finish()

    # This function is a callback when a small chunk is received
    def handle_data_chunk(self, data):
        if data:
            self.write(data)
            self.request.response_buffer += data

    @tornado.web.asynchronous
    @tornado.gen.coroutine
    def get(self):
        """
        * This function handles all requests except the connect request.
        * Once ssl stream is formed between browser and proxy, the requests are
          then processed by this function
        """
        # The flow starts here
        self.request.response_buffer = ''

        # The requests that come through ssl streams are relative requests, so transparent
        # proxying is required. The following snippet decides the url that should be passed
        # to the async client
        if self.request.uri.startswith(self.request.protocol,0): # Normal Proxy Request
            self.request.url = self.request.uri
        else:  # Transparent Proxy Request
            self.request.url = self.request.protocol + "://" + self.request.host
            if self.request.uri != '/':  # Add uri only if needed
                self.request.url += self.request.uri


        # Request header cleaning
        for header in restricted_request_headers:
            try:
                del self.request.headers[header]
            except:
                continue

        #  httprequest object is created and then passed to async client with a callback
        request = tornado.httpclient.HTTPRequest(
                url=self.request.url,
                method=self.request.method,
                body=self.request.body if self.request.body else None,
                headers=self.request.headers,
                follow_redirects=False,
                use_gzip=True,
                streaming_callback=self.handle_data_chunk,
                header_callback=None,
                proxy_host=self.application.outbound_ip,
                proxy_port=self.application.outbound_port,
                proxy_username=self.application.outbound_username,
                proxy_password=self.application.outbound_password,
                allow_nonstandard_methods=True,
                validate_cert=False)
        response = yield tornado.gen.Task(self.application.async_client.fetch, request)
        self.finish_response(response)


    # The following 5 methods can be handled through the above implementation
    @tornado.web.asynchronous
    def post(self):
        return self.get()

    @tornado.web.asynchronous
    def head(self):
        return self.get()

    @tornado.web.asynchronous
    def put(self):
        return self.get()

    @tornado.web.asynchronous
    def delete(self):
        return self.get()

    @tornado.web.asynchronous
    def options(self):
        return self.get()

    @tornado.web.asynchronous
    def trace(self):
        return self.get()

    @tornado.web.asynchronous
    def connect(self):
        """
        This function gets called when a connect request is received.
        * The host and port are obtained from the request uri
        * A socket is created, wrapped in ssl and then added to SSLIOStream
        * This stream is used to connect to speak to the remote host on given port
        * If the server speaks ssl on that port, callback start_tunnel is called
        * An OK response is written back to client
        * The client side socket is wrapped in ssl
        * If the wrapping is successful, a new SSLIOStream is made using that socket
        * The stream is added back to the server for monitoring
        """
        host, port = self.request.uri.split(':')
        def start_tunnel():
            try:
                base=os.path.dirname(os.path.realpath(__file__))
                ca_crt=os.path.join(base,"ca.crt")
                ca_key=os.path.join(base,"ca.key")
                self.request.connection.stream.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                wrap_socket(
                            self.request.connection.stream.socket,
                            host,
                            ca_crt,
                            ca_key,
                            "mobsec-yso",
                            "logs",
                            success=ssl_success
                           )
            except tornado.iostream.StreamClosedError:
                pass

        def ssl_success(client_socket):
            client = tornado.iostream.SSLIOStream(client_socket)
            server.handle_stream(client, self.application.inbound_ip)

        # Tiny Hack to satisfy proxychains CONNECT request to HTTP port.
        # HTTPS fail check has to be improvised
        def ssl_fail():
            self.request.connection.stream.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            server.handle_stream(self.request.connection.stream, self.application.inbound_ip)

        ######
        # Hacking to be done here, so as to check for ssl using proxy and auth
        try:
            s = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0))
            upstream = tornado.iostream.SSLIOStream(s)
            #start_tunnel()
            upstream.set_close_callback(ssl_fail)
            upstream.connect((host, int(port)), start_tunnel)
        except Exception:
            self.finish()

class CustomWebSocketHandler(tornado.websocket.WebSocketHandler):
    """
    * See docs XD
    * This class is used for handling websocket traffic.
    * Object of this class replaces the main request handler for a request with
      header => "Upgrade: websocket"
    * wss:// - CONNECT request is handled by main handler
    """
    def upstream_connect(self, io_loop=None, callback=None):
        """
        Implemented as a custom alternative to tornado.websocket.websocket_connect
        """
        # io_loop is needed, how else will it work with tornado :P
        if io_loop is None:
            io_loop = tornado.ioloop.IOLoop.current()

        # During secure communication, we get relative URI, so make them absolute
        if self.request.uri.startswith(self.request.protocol,0): # Normal Proxy Request
            self.request.url = self.request.uri
        else:  # Transparent Proxy Request
            self.request.url = self.request.protocol + "://" + self.request.host + self.request.uri
        # WebSocketClientConnection expects ws:// & wss://
        self.request.url = self.request.url.replace("http", "ws", 1)

        # Have to add cookies and stuff
        request_headers = tornado.httputil.HTTPHeaders()
        for name, value in self.request.headers.iteritems():
            if name not in restricted_request_headers:
                request_headers.add(name, value)
        # Build a custom request
        request = tornado.httpclient.HTTPRequest(
                                                    url=self.request.url,
                                                    headers=request_headers,
                                                    proxy_host=self.application.outbound_ip,
                                                    proxy_port=self.application.outbound_port,
                                                    proxy_username=self.application.outbound_username,
                                                    proxy_password=self.application.outbound_password
                                                )
        self.upstream_connection = CustomWebSocketClientConnection(io_loop, request)
        if callback is not None:
            io_loop.add_future(self.upstream_connection.connect_future, callback)
        return self.upstream_connection.connect_future # This returns a future

    def _execute(self, transforms, *args, **kwargs):
        """
        Overriding of a method of WebSocketHandler
        """
        def start_tunnel(future):
            """
            A callback which is called when connection to url is successful
            """
            self.upstream = future.result() # We need upstream to write further messages
            self.handshake_request = self.upstream_connection.request # HTTPRequest needed for caching :P
            self.handshake_request.response_buffer = "" # Needed for websocket data & compliance with cache_handler stuff
            self.handshake_request.version = "HTTP/1.1" # Tiny hack to protect caching (But according to websocket standards)
            self.handshake_request.body = self.handshake_request.body or "" # I dont know why a None is coming :P
            tornado.websocket.WebSocketHandler._execute(self, transforms, *args, **kwargs) # The regular procedures are to be done

        # We try to connect to provided URL & then we proceed with connection on client side.
        self.upstream = self.upstream_connect(callback=start_tunnel)

    def store_upstream_data(self, message):
        """
        Save websocket data sent from client to server, i.e add it to HTTPRequest.response_buffer with direction (>>)
        """
        try: # Cannot write binary content as a string, so catch it
            self.handshake_request.response_buffer += (">>> %s\r\n"%(message))
        except TypeError:
            self.handshake_request.response_buffer += (">>> May be binary\r\n")

    def store_downstream_data(self, message):
        """
        Save websocket data sent from client to server, i.e add it to HTTPRequest.response_buffer with direction (<<)
        """
        try: # Cannot write binary content as a string, so catch it
            self.handshake_request.response_buffer += ("<<< %s\r\n"%(message))
        except TypeError:
            self.handshake_request.response_buffer += ("<<< May be binary\r\n")

    def on_message(self, message):
        """
        Everytime a message is received from client side, this instance method is called
        """
        self.upstream.write_message(message) # The obtained message is written to upstream
        self.store_upstream_data(message)

        # The following check ensures that if a callback is added for reading message from upstream, another one is not added
        if not self.upstream.read_future:
            self.upstream.read_message(callback=self.on_response) # A callback is added to read the data when upstream responds

    def on_response(self, message):
        """
        A callback when a message is recieved from upstream
        *** Here message is a future
        """
        # The following check ensures that if a callback is added for reading message from upstream, another one is not added
        if not self.upstream.read_future:
            self.upstream.read_message(callback=self.on_response)
        if self.ws_connection: # Check if connection still exists
            if message.result(): # Check if it is not NULL ( Indirect checking of upstream connection )
                self.write_message(message.result()) # Write obtained message to client
                self.store_downstream_data(message.result())
            else:
                self.close()

    def on_close(self):
        """
        Called when websocket is closed. So handshake request-response pair along with websocket data as response body is saved
        """
        # Required for cache_handler
        self.handshake_response = tornado.httpclient.HTTPResponse(
                                                                    self.handshake_request,
                                                                    self.upstream_connection.code,
                                                                    headers=self.upstream_connection.headers,
                                                                    request_time=0
                                                                 )
        # Close fd descriptor

class CustomWebSocketClientConnection(tornado.websocket.WebSocketClientConnection):
    # Had to extract response code, so it is necessary to override
    def _handle_1xx(self, code):
        self.code = code
        super(CustomWebSocketClientConnection, self)._handle_1xx(code)


# The tornado application, which is used to pass variables to request handler
application = tornado.web.Application(handlers=[
                                                    (r'.*', ProxyHandler)
                                                    ],
                                            debug=False,
                                            gzip=True,
                                           )
application.async_client = tornado.httpclient.AsyncHTTPClient()
instances = "1"

# SSL MiTM
# SSL certs, keys and other settings (os.path.expanduser because they are stored in users home directory ~/.owtf/proxy )


application.outbound_ip = None
application.outbound_port = None
application.outbound_username = None
application.outbound_password = None
application.inbound_ip="0.0.0.0"

#try: # Ensure CA.crt and Key exist
#assert os.path.exists(application.ca_cert)
#assert os.path.exists(application.ca_key)
#except AssertionError:
#print ("Files required for SSL MiTM are missing. Please run the install script")


# Server has to be global, because it is used inside request handler to attach sockets for monitoring
global server
server = tornado.httpserver.HTTPServer(application)
server = server

# Header filters
# Restricted headers are picked from framework/config/framework_config.cfg
# These headers are removed from the response obtained from webserver, before sending it to browser
global restricted_response_headers
rresh=["Content-Length","Content-Encoding","Etag","Transfer-Encoding","Connection","Vary","Accept-Ranges","Pragma"]
restricted_response_headers = rresh
# These headers are removed from request obtained from browser, before sending it to webserver
global restricted_request_headers
rreqh=["Connection","Pragma","Cache-Control","If-Modified-Since"]
restricted_request_headers = rreqh


# "0" equals the number of cores present in a machine
if len(sys.argv)==4:
    LOG=sys.argv[3]
    try:
        server.bind(sys.argv[2], address=sys.argv[1])
        # Useful for using custom loggers because of relative paths in secure requests
        # http://www.joet3ch.com/blog/2011/09/08/alternative-tornado-logging/
        #ornado.options.parse_command_line(args=["dummy_arg","--log_file_prefix="+application.Core.DB.Config.Get("PROXY_LOG"),"--logging=info"])
        tornado.options.parse_command_line(args=["dummy_arg","--log_file_prefix=logs/proxy.log","--logging=info"])
        # To run any number of instances
        server.start(int(1))
        tornado.ioloop.IOLoop.instance().start()
    except Exception as e:
        print "[WebProxy Error] "+str(e)
else:
    print "proxy.py <IP> <PORT> <LOGFILE>"

