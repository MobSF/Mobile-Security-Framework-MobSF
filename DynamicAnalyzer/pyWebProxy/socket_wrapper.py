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
from tornado import ioloop
import ssl

from gen_cert import gen_signed_cert


def wrap_socket(socket, domain, ca_crt, ca_key, ca_pass, certs_folder, success=None, failure=None, io=None, **options):
    """Wrap an active socket in an SSL socket."""

    # # Default Options
    options.setdefault('do_handshake_on_connect', False)
    options.setdefault('ssl_version', ssl.PROTOCOL_SSLv23)
    options.setdefault('server_side', True)

    # The idea is to handle domains with greater than 3 dots using wildcard
    # certs
    if domain.count(".") >= 3:
        key, cert = gen_signed_cert(
            "*." + ".".join(domain.split(".")[-3:]), ca_crt, ca_key, ca_pass, certs_folder)
    else:
        key, cert = gen_signed_cert(
            domain, ca_crt, ca_key, ca_pass, certs_folder)
    options.setdefault('certfile', cert)
    options.setdefault('keyfile', key)

    # # Handlers

    def done():
        """Handshake finished successfully."""

        io.remove_handler(wrapped.fileno())
        success and success(wrapped)

    def error():
        """The handshake failed."""

        if failure:
            return failure(wrapped)
        # # By default, just close the socket.
        io.remove_handler(wrapped.fileno())
        wrapped.close()

    def handshake(fd, events):
        """Handler fGetting the same error here... also looking for answers....
        TheHippo Dec 19 '12 at 20:29or SSL handshake negotiation.
        See Python docs for ssl.do_handshake()."""

        if events & io.ERROR:
            error()
            return

        try:
            new_state = io.ERROR
            wrapped.do_handshake()
            return done()
        except ssl.SSLError as exc:
            if exc.args[0] == ssl.SSL_ERROR_WANT_READ:
                new_state |= io.READ
            elif exc.args[0] == ssl.SSL_ERROR_WANT_WRITE:
                new_state |= io.WRITE
            else:
                raise

        if new_state != state[0]:
            state[0] = new_state
            io.update_handler(fd, new_state)

    # # set up handshake state; use a list as a mutable cell.
    io = io or ioloop.IOLoop.instance()
    state = [io.ERROR]

    # # Wrap the socket; swap out handlers.
    io.remove_handler(socket.fileno())
    wrapped = ssl.SSLSocket(socket, **options)
    wrapped.setblocking(0)
    io.add_handler(wrapped.fileno(), handshake, state[0])

    # # Begin the handshake.
    handshake(wrapped.fileno(), 0)
    return wrapped
