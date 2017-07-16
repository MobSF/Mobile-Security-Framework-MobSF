# Copyright 2014 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Routines to generate root and server certificates.

Certificate Naming Conventions:
  ca_cert:  crypto.X509 for the certificate authority (w/ both the pub &
                priv keys)
  cert:  a crypto.X509 certificate (w/ just the pub key)
  cert_str:  a certificate string (w/ just the pub cert)
  key:  a private crypto.PKey  (from ca or pem)
  ca_cert_str:  a certificae authority string (w/ both the pub & priv certs)
"""

import logging
import os
import platform
import socket
import subprocess
import time

openssl_import_error = None

Error = None
SSL_METHOD = None
SysCallError = None
VERIFY_PEER = None
ZeroReturnError = None
FILETYPE_PEM = None

try:
  from OpenSSL import crypto, SSL

  Error = SSL.Error
  SSL_METHOD = SSL.SSLv23_METHOD
  SysCallError = SSL.SysCallError
  VERIFY_PEER = SSL.VERIFY_PEER
  ZeroReturnError = SSL.ZeroReturnError
  FILETYPE_PEM = crypto.FILETYPE_PEM
except ImportError, e:
  openssl_import_error = e


def get_ssl_context(method=SSL_METHOD):
  # One of: One of SSLv2_METHOD, SSLv3_METHOD, SSLv23_METHOD, or TLSv1_METHOD
  if openssl_import_error:
    raise openssl_import_error  # pylint: disable=raising-bad-type
  return SSL.Context(method)


class WrappedConnection(object):

  def __init__(self, obj):
    self._wrapped_obj = obj

  def __getattr__(self, attr):
    if attr in self.__dict__:
      return getattr(self, attr)
    return getattr(self._wrapped_obj, attr)

  def recv(self, buflen=1024, flags=0):
    try:
      return self._wrapped_obj.recv(buflen, flags)
    except SSL.SysCallError, e:
      if e.args[1] == 'Unexpected EOF':
        return ''
      raise
    except SSL.ZeroReturnError:
      return ''


def get_ssl_connection(context, connection):
  return WrappedConnection(SSL.Connection(context, connection))


def load_privatekey(key, filetype=FILETYPE_PEM):
  """Loads obj private key object from string."""
  return crypto.load_privatekey(filetype, key)


def load_cert(cert_str, filetype=FILETYPE_PEM):
  """Loads obj cert object from string."""
  return crypto.load_certificate(filetype, cert_str)


def _dump_privatekey(key, filetype=FILETYPE_PEM):
  """Dumps obj private key object to string."""
  return crypto.dump_privatekey(filetype, key)


def _dump_cert(cert, filetype=FILETYPE_PEM):
  """Dumps obj cert object to string."""
  return crypto.dump_certificate(filetype, cert)


def generate_dummy_ca_cert(subject='_WebPageReplayCert'):
  """Generates dummy certificate authority.

  Args:
    subject: a string representing the desired root cert issuer
  Returns:
    A tuple of the public key and the private key strings for the root
    certificate
  """
  if openssl_import_error:
    raise openssl_import_error  # pylint: disable=raising-bad-type

  key = crypto.PKey()
  key.generate_key(crypto.TYPE_RSA, 1024)

  ca_cert = crypto.X509()
  ca_cert.set_serial_number(int(time.time()*10000))
  ca_cert.set_version(2)
  ca_cert.get_subject().CN = subject
  ca_cert.get_subject().O = subject
  ca_cert.gmtime_adj_notBefore(-60 * 60 * 24 * 365 * 2)
  ca_cert.gmtime_adj_notAfter(60 * 60 * 24 * 365 * 2)
  ca_cert.set_issuer(ca_cert.get_subject())
  ca_cert.set_pubkey(key)
  ca_cert.add_extensions([
      crypto.X509Extension('basicConstraints', True, 'CA:TRUE'),
      crypto.X509Extension('subjectAltName', False, 'DNS:' + subject),
      crypto.X509Extension('nsCertType', True, 'sslCA'),
      crypto.X509Extension('extendedKeyUsage', True,
                           ('serverAuth,clientAuth,emailProtection,'
                            'timeStamping,msCodeInd,msCodeCom,msCTLSign,'
                            'msSGC,msEFS,nsSGC')),
      crypto.X509Extension('keyUsage', False, 'keyCertSign, cRLSign'),
      crypto.X509Extension('subjectKeyIdentifier', False, 'hash',
                           subject=ca_cert),
      ])
  ca_cert.sign(key, 'sha256')
  key_str = _dump_privatekey(key)
  ca_cert_str = _dump_cert(ca_cert)
  return ca_cert_str, key_str


def get_host_cert(host, port=443):
  """Contacts the host and returns its certificate."""
  host_certs = []
  def verify_cb(conn, cert, errnum, depth, ok):
    host_certs.append(cert)
    # Return True to indicates that the certificate was ok.
    return True

  context = SSL.Context(SSL.SSLv23_METHOD)
  context.set_verify(SSL.VERIFY_PEER, verify_cb)  # Demand a certificate
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  connection = SSL.Connection(context, s)
  try:
    connection.connect((host, port))
    connection.send('')
  except SSL.SysCallError:
    pass
  except socket.gaierror:
    logging.debug('Host name is not valid')
  finally:
    connection.shutdown()
    connection.close()
  if not host_certs:
    logging.warning('Unable to get host certificate from %s:%s', host, port)
    return ''
  return _dump_cert(host_certs[-1])


def write_dummy_ca_cert(ca_cert_str, key_str, cert_path):
  """Writes four certificate files.

  For example, if cert_path is "mycert.pem":
      mycert.pem - CA plus private key
      mycert-cert.pem - CA in PEM format
      mycert-cert.cer - CA for Android
      mycert-cert.p12 - CA in PKCS12 format for Windows devices
  Args:
    cert_path: path string such as "mycert.pem"
    ca_cert_str: certificate string
    key_str: private key string
  """
  dirname = os.path.dirname(cert_path)
  if dirname and not os.path.exists(dirname):
    os.makedirs(dirname)

  root_path = os.path.splitext(cert_path)[0]
  ca_cert_path = root_path + '-cert.pem'
  android_cer_path = root_path + '-cert.cer'
  windows_p12_path = root_path + '-cert.p12'

  # Dump the CA plus private key
  with open(cert_path, 'w') as f:
    f.write(key_str)
    f.write(ca_cert_str)

  # Dump the certificate in PEM format
  with open(ca_cert_path, 'w') as f:
    f.write(ca_cert_str)

  # Create a .cer file with the same contents for Android
  with open(android_cer_path, 'w') as f:
    f.write(ca_cert_str)

  ca_cert = load_cert(ca_cert_str)
  key = load_privatekey(key_str)
  # Dump the certificate in PKCS12 format for Windows devices
  with open(windows_p12_path, 'w') as f:
    p12 = crypto.PKCS12()
    p12.set_certificate(ca_cert)
    p12.set_privatekey(key)
    f.write(p12.export())


def generate_cert(root_ca_cert_str, server_cert_str, server_host):
  """Generates a cert_str with the sni field in server_cert_str signed by the
  root_ca_cert_str.

  Args:
    root_ca_cert_str: PEM formatted string representing the root cert
    server_cert_str: PEM formatted string representing cert
    server_host: host name to use if there is no server_cert_str
  Returns:
    a PEM formatted certificate string
  """
  EXTENSION_WHITELIST = set(['subjectAltName'])

  if openssl_import_error:
    raise openssl_import_error  # pylint: disable=raising-bad-type

  common_name = server_host
  reused_extensions = []
  if server_cert_str:
    original_cert = load_cert(server_cert_str)
    common_name = original_cert.get_subject().commonName
    for i in xrange(original_cert.get_extension_count()):
      original_cert_extension = original_cert.get_extension(i)
      if original_cert_extension.get_short_name() in EXTENSION_WHITELIST:
        reused_extensions.append(original_cert_extension)

  ca_cert = load_cert(root_ca_cert_str)
  ca_key = load_privatekey(root_ca_cert_str)

  cert = crypto.X509()
  cert.get_subject().CN = common_name
  cert.gmtime_adj_notBefore(-60 * 60)
  cert.gmtime_adj_notAfter(60 * 60 * 24 * 30)
  cert.set_issuer(ca_cert.get_subject())
  cert.set_serial_number(int(time.time()*10000))
  cert.set_pubkey(ca_key)
  cert.add_extensions(reused_extensions)
  cert.sign(ca_key, 'sha256')

  return _dump_cert(cert)


def install_cert_in_nssdb(home_directory_path, certificate_path):
  """Installs a certificate into the ~/.pki/nssdb database.

  Args:
    home_directory_path: Path of the home directory where to install
    certificate_path: Path of a CA in PEM format
  """
  assert os.path.isdir(home_directory_path)
  assert platform.system() == 'Linux', \
      'SSL certification authority has only been tested for linux.'
  if (os.path.abspath(home_directory_path) ==
          os.path.abspath(os.environ['HOME'])):
    raise Exception('Modifying $HOME/.pki/nssdb compromises your machine.')

  cert_database_path = os.path.join(home_directory_path, '.pki', 'nssdb')
  def certutil(args):
    cmd = ['certutil', '--empty-password', '-d', 'sql:' + cert_database_path]
    cmd.extend(args)
    logging.info(subprocess.list2cmdline(cmd))
    subprocess.check_call(cmd)

  if not os.path.isdir(cert_database_path):
    os.makedirs(cert_database_path)
    certutil(['-N'])

  certutil(['-A', '-t', 'PC,,', '-n', certificate_path, '-i', certificate_path])
