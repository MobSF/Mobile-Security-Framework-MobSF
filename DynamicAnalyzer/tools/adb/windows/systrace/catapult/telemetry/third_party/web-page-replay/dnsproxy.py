#!/usr/bin/env python
# Copyright 2010 Google Inc. All Rights Reserved.
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

import daemonserver
import errno
import logging
import socket
import SocketServer
import threading
import time

from third_party.dns import flags
from third_party.dns import message
from third_party.dns import rcode
from third_party.dns import resolver
from third_party.dns import rdatatype
from third_party import ipaddr



class DnsProxyException(Exception):
  pass


DEFAULT_DNS_PORT = 53


class RealDnsLookup(object):
  def __init__(self, name_servers, dns_forwarding, proxy_host, proxy_port):
    if (proxy_host in name_servers and proxy_port == DEFAULT_DNS_PORT and
        dns_forwarding):
      raise DnsProxyException(
          'Invalid nameserver: %s (causes an infinte loop)'.format(
              proxy_host))
    self.resolver = resolver.get_default_resolver()
    self.resolver.nameservers = name_servers
    self.dns_cache_lock = threading.Lock()
    self.dns_cache = {}

  @staticmethod
  def _IsIPAddress(hostname):
    try:
      socket.inet_aton(hostname)
      return True
    except socket.error:
      return False

  def __call__(self, hostname, rdtype=rdatatype.A):
    """Return real IP for a host.

    Args:
      host: a hostname ending with a period (e.g. "www.google.com.")
      rdtype: the query type (1 for 'A', 28 for 'AAAA')
    Returns:
      the IP address as a string (e.g. "192.168.25.2")
    """
    if self._IsIPAddress(hostname):
      return hostname
    self.dns_cache_lock.acquire()
    ip = self.dns_cache.get(hostname)
    self.dns_cache_lock.release()
    if ip:
      return ip
    try:
      answers = self.resolver.query(hostname, rdtype)
    except resolver.NXDOMAIN:
      return None
    except resolver.NoNameservers:
      logging.debug('_real_dns_lookup(%s) -> No nameserver.',
                    hostname)
      return None
    except (resolver.NoAnswer, resolver.Timeout) as ex:
      logging.debug('_real_dns_lookup(%s) -> None (%s)',
                    hostname, ex.__class__.__name__)
      return None
    if answers:
      ip = str(answers[0])
    self.dns_cache_lock.acquire()
    self.dns_cache[hostname] = ip
    self.dns_cache_lock.release()
    return ip

  def ClearCache(self):
    """Clear the dns cache."""
    self.dns_cache_lock.acquire()
    self.dns_cache.clear()
    self.dns_cache_lock.release()


class ReplayDnsLookup(object):
  """Resolve DNS requests to replay host."""
  def __init__(self, replay_ip, filters=None):
    self.replay_ip = replay_ip
    self.filters = filters or []

  def __call__(self, hostname):
    ip = self.replay_ip
    for f in self.filters:
      ip = f(hostname, default_ip=ip)
    return ip


class PrivateIpFilter(object):
  """Resolve private hosts to their real IPs and others to the Web proxy IP.

  Hosts in the given http_archive will resolve to the Web proxy IP without
  checking the real IP.

  This only supports IPv4 lookups.
  """
  def __init__(self, real_dns_lookup, http_archive):
    """Initialize PrivateIpDnsLookup.

    Args:
      real_dns_lookup: a function that resolves a host to an IP.
      http_archive: an instance of a HttpArchive
        Hosts is in the archive will always resolve to the web_proxy_ip
    """
    self.real_dns_lookup = real_dns_lookup
    self.http_archive = http_archive
    self.InitializeArchiveHosts()

  def __call__(self, host, default_ip):
    """Return real IPv4 for private hosts and Web proxy IP otherwise.

    Args:
      host: a hostname ending with a period (e.g. "www.google.com.")
    Returns:
      IP address as a string or None (if lookup fails)
    """
    ip = default_ip
    if host not in self.archive_hosts:
      real_ip = self.real_dns_lookup(host)
      if real_ip:
        if ipaddr.IPAddress(real_ip).is_private:
          ip = real_ip
      else:
        ip = None
    return ip

  def InitializeArchiveHosts(self):
    """Recompute the archive_hosts from the http_archive."""
    self.archive_hosts = set('%s.' % req.host.split(':')[0]
                             for req in self.http_archive)


class DelayFilter(object):
  """Add a delay to replayed lookups."""

  def __init__(self, is_record_mode, delay_ms):
    self.is_record_mode = is_record_mode
    self.delay_ms = int(delay_ms)

  def __call__(self, host, default_ip):
    if not self.is_record_mode:
      time.sleep(self.delay_ms * 1000.0)
    return default_ip

  def SetRecordMode(self):
    self.is_record_mode = True

  def SetReplayMode(self):
    self.is_record_mode = False


class UdpDnsHandler(SocketServer.DatagramRequestHandler):
  """Resolve DNS queries to localhost.

  Possible alternative implementation:
  http://howl.play-bow.org/pipermail/dnspython-users/2010-February/000119.html
  """

  STANDARD_QUERY_OPERATION_CODE = 0

  def handle(self):
    """Handle a DNS query.

    IPv6 requests (with rdtype AAAA) receive mismatched IPv4 responses
    (with rdtype A). To properly support IPv6, the http proxy would
    need both types of addresses. By default, Windows XP does not
    support IPv6.
    """
    self.data = self.rfile.read()
    self.transaction_id = self.data[0]
    self.flags = self.data[1]
    self.qa_counts = self.data[4:6]
    self.domain = ''
    operation_code = (ord(self.data[2]) >> 3) & 15
    if operation_code == self.STANDARD_QUERY_OPERATION_CODE:
      self.wire_domain = self.data[12:]
      self.domain = self._domain(self.wire_domain)
    else:
      logging.debug("DNS request with non-zero operation code: %s",
                    operation_code)
    ip = self.server.dns_lookup(self.domain)
    if ip is None:
      logging.debug('dnsproxy: %s -> NXDOMAIN', self.domain)
      response = self.get_dns_no_such_name_response()
    else:
      if ip == self.server.server_address[0]:
        logging.debug('dnsproxy: %s -> %s (replay web proxy)', self.domain, ip)
      else:
        logging.debug('dnsproxy: %s -> %s', self.domain, ip)
      response = self.get_dns_response(ip)
    self.wfile.write(response)

  @classmethod
  def _domain(cls, wire_domain):
    domain = ''
    index = 0
    length = ord(wire_domain[index])
    while length:
      domain += wire_domain[index + 1:index + length + 1] + '.'
      index += length + 1
      length = ord(wire_domain[index])
    return domain

  def get_dns_response(self, ip):
    packet = ''
    if self.domain:
      packet = (
          self.transaction_id +
          self.flags +
          '\x81\x80' +        # standard query response, no error
          self.qa_counts * 2 + '\x00\x00\x00\x00' +  # Q&A counts
          self.wire_domain +
          '\xc0\x0c'          # pointer to domain name
          '\x00\x01'          # resource record type ("A" host address)
          '\x00\x01'          # class of the data
          '\x00\x00\x00\x3c'  # ttl (seconds)
          '\x00\x04' +        # resource data length (4 bytes for ip)
          socket.inet_aton(ip)
          )
    return packet

  def get_dns_no_such_name_response(self):
    query_message = message.from_wire(self.data)
    response_message = message.make_response(query_message)
    response_message.flags |= flags.AA | flags.RA
    response_message.set_rcode(rcode.NXDOMAIN)
    return response_message.to_wire()


class DnsProxyServer(SocketServer.ThreadingUDPServer,
                     daemonserver.DaemonServer):
  # Increase the request queue size. The default value, 5, is set in
  # SocketServer.TCPServer (the parent of BaseHTTPServer.HTTPServer).
  # Since we're intercepting many domains through this single server,
  # it is quite possible to get more than 5 concurrent requests.
  request_queue_size = 256

  # Allow sockets to be reused. See
  # http://svn.python.org/projects/python/trunk/Lib/SocketServer.py for more
  # details.
  allow_reuse_address = True

  # Don't prevent python from exiting when there is thread activity.
  daemon_threads = True

  def __init__(self, host='', port=53, dns_lookup=None):
    """Initialize DnsProxyServer.

    Args:
      host: a host string (name or IP) to bind the dns proxy and to which
        DNS requests will be resolved.
      port: an integer port on which to bind the proxy.
      dns_lookup: a list of filters to apply to lookup.
    """
    try:
      SocketServer.ThreadingUDPServer.__init__(
          self, (host, port), UdpDnsHandler)
    except socket.error, (error_number, msg):
      if error_number == errno.EACCES:
        raise DnsProxyException(
            'Unable to bind DNS server on (%s:%s)' % (host, port))
      raise
    self.dns_lookup = dns_lookup or (lambda host: self.server_address[0])
    self.server_port = self.server_address[1]
    logging.warning('DNS server started on %s:%d', self.server_address[0],
                                                   self.server_address[1])

  def cleanup(self):
    try:
      self.shutdown()
      self.server_close()
    except KeyboardInterrupt, e:
      pass
    logging.info('Stopped DNS server')
