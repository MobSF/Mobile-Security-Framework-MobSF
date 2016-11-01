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
from OpenSSL import crypto
import os
import hashlib
import re


def gen_signed_cert(domain, ca_crt, ca_key, ca_pass, certs_folder):
    """
    This function takes a domain name as a parameter and then creates a certificate and key with the
    domain name(replacing dots by underscores), finally signing the certificate using specified CA and
    returns the path of key and cert files. If you are yet to generate a CA then check the top comments
    """
    key_path = os.path.join(certs_folder, re.sub(
        '[^-0-9a-zA-Z_]', '_', domain) + ".key")
    cert_path = os.path.join(certs_folder, re.sub(
        '[^-0-9a-zA-Z_]', '_', domain) + ".crt")

    # The first conditions checks if file exists, and does nothing if true
    # If file doenst exist lock is obtained for writing (Other processes in race must wait)
    # After obtaining lock another check to handle race conditions gracefully
    if os.path.exists(key_path) and os.path.exists(cert_path):
        pass
    else:

        # Check happens if the certificate and key pair already exists for a
        # domain
        if os.path.exists(key_path) and os.path.exists(cert_path):
            pass
        else:
            # Serial Generation - Serial number must be unique for each certificate,
            # so serial is generated based on domain name
            md5_hash = hashlib.md5()
            md5_hash.update(domain)
            serial = int(md5_hash.hexdigest(), 36)
            # The CA stuff is loaded from the same folder as this script

            ca_cert = crypto.load_certificate(
                crypto.FILETYPE_PEM, open(ca_crt).read())
            # The last parameter is the password for your CA key file
            ca_key = crypto.load_privatekey(
                crypto.FILETYPE_PEM, open(ca_key).read(), ca_pass)
            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, 2048)
            cert = crypto.X509()
            cert.get_subject().C = "IN"
            cert.get_subject().ST = "BL"
            cert.get_subject().L = "127.0.0.1"
            cert.get_subject().O = "MobSec"
            cert.get_subject().OU = "MobSec-Proxy"
            cert.get_subject().CN = domain
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
            cert.set_serial_number(serial)
            cert.set_issuer(ca_cert.get_subject())
            cert.set_pubkey(key)
            cert.sign(ca_key, "sha1")
            # The key and cert files are dumped and their paths are returned
            domain_key = open(key_path, "w")
            domain_key.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
            domain_cert = open(cert_path, "w")
            domain_cert.write(crypto.dump_certificate(
                crypto.FILETYPE_PEM, cert))
            # print(("[*] Generated signed certificate for %s" % (domain)))
    return key_path, cert_path
