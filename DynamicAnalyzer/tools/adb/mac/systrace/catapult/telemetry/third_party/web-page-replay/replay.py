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

"""Replays web pages under simulated network conditions.

Must be run as administrator (sudo).

To record web pages:
  1. Start the program in record mode.
     $ sudo ./replay.py --record archive.wpr
  2. Load the web pages you want to record in a web browser. It is important to
     clear browser caches before this so that all subresources are requested
     from the network.
  3. Kill the process to stop recording.

To replay web pages:
  1. Start the program in replay mode with a previously recorded archive.
     $ sudo ./replay.py archive.wpr
  2. Load recorded pages in a web browser. A 404 will be served for any pages or
     resources not in the recorded archive.

Network simulation examples:
  # 128KByte/s uplink bandwidth, 4Mbps/s downlink bandwidth with 100ms RTT time
  $ sudo ./replay.py --up 128KByte/s --down 4Mbit/s --delay_ms=100 archive.wpr

  # 1% packet loss rate
  $ sudo ./replay.py --packet_loss_rate=0.01 archive.wpr
"""

import argparse
import json
import logging
import os
import socket
import sys
import traceback

import customhandlers
import dnsproxy
import httparchive
import httpclient
import httpproxy
import net_configs
import platformsettings
import rules_parser
import script_injector
import servermanager
import trafficshaper

if sys.version < '2.6':
  print 'Need Python 2.6 or greater.'
  sys.exit(1)


def configure_logging(log_level_name, log_file_name=None):
  """Configure logging level and format.

  Args:
    log_level_name: 'debug', 'info', 'warning', 'error', or 'critical'.
    log_file_name: a file name
  """
  if logging.root.handlers:
    logging.critical('A logging method (e.g. "logging.warn(...)")'
                     ' was called before logging was configured.')
  log_level = getattr(logging, log_level_name.upper())
  log_format = (
    '(%(levelname)s) %(asctime)s %(module)s.%(funcName)s:%(lineno)d  '
    '%(message)s')


  logging.basicConfig(level=log_level, format=log_format)
  logger = logging.getLogger()
  if log_file_name:
    fh = logging.FileHandler(log_file_name)
    fh.setLevel(log_level)
    fh.setFormatter(logging.Formatter(log_format))
    logger.addHandler(fh)
  system_handler = platformsettings.get_system_logging_handler()
  if system_handler:
    logger.addHandler(system_handler)


def AddDnsForward(server_manager, host):
  """Forward DNS traffic."""
  server_manager.Append(platformsettings.set_temporary_primary_nameserver, host)


def AddDnsProxy(server_manager, options, host, port, real_dns_lookup,
                http_archive):
  dns_filters = []
  if options.dns_private_passthrough:
    private_filter = dnsproxy.PrivateIpFilter(real_dns_lookup, http_archive)
    dns_filters.append(private_filter)
    server_manager.AppendRecordCallback(private_filter.InitializeArchiveHosts)
    server_manager.AppendReplayCallback(private_filter.InitializeArchiveHosts)
  if options.shaping_dns:
    delay_filter = dnsproxy.DelayFilter(options.record, **options.shaping_dns)
    dns_filters.append(delay_filter)
    server_manager.AppendRecordCallback(delay_filter.SetRecordMode)
    server_manager.AppendReplayCallback(delay_filter.SetReplayMode)
  server_manager.Append(dnsproxy.DnsProxyServer, host, port,
                        dns_lookup=dnsproxy.ReplayDnsLookup(host, dns_filters))


def AddWebProxy(server_manager, options, host, real_dns_lookup, http_archive):
  if options.rules_path:
    with open(options.rules_path) as file_obj:
      allowed_imports = [
          name.strip() for name in options.allowed_rule_imports.split(',')]
      rules = rules_parser.Rules(file_obj, allowed_imports)
    logging.info('Parsed %s rules:\n%s', options.rules_path, rules)
  else:
    rules = rules_parser.Rules()
  injector = script_injector.GetScriptInjector(options.inject_scripts)
  custom_handlers = customhandlers.CustomHandlers(options, http_archive)
  custom_handlers.add_server_manager_handler(server_manager)
  archive_fetch = httpclient.ControllableHttpArchiveFetch(
      http_archive, real_dns_lookup,
      injector,
      options.diff_unknown_requests, options.record,
      use_closest_match=options.use_closest_match,
      scramble_images=options.scramble_images)
  server_manager.AppendRecordCallback(archive_fetch.SetRecordMode)
  server_manager.AppendReplayCallback(archive_fetch.SetReplayMode)
  allow_generate_304 = not options.record
  server_manager.Append(
      httpproxy.HttpProxyServer,
      archive_fetch, custom_handlers, rules,
      host=host, port=options.port, use_delays=options.use_server_delay,
      allow_generate_304=allow_generate_304,
      **options.shaping_http)
  if options.ssl:
    if options.should_generate_certs:
      server_manager.Append(
          httpproxy.HttpsProxyServer, archive_fetch, custom_handlers, rules,
          options.https_root_ca_cert_path, host=host, port=options.ssl_port,
          allow_generate_304=allow_generate_304,
          use_delays=options.use_server_delay, **options.shaping_http)
    else:
      server_manager.Append(
          httpproxy.SingleCertHttpsProxyServer, archive_fetch,
          custom_handlers, rules, options.https_root_ca_cert_path, host=host,
          port=options.ssl_port, use_delays=options.use_server_delay,
          allow_generate_304=allow_generate_304,
          **options.shaping_http)
  if options.http_to_https_port:
    server_manager.Append(
        httpproxy.HttpToHttpsProxyServer,
        archive_fetch, custom_handlers, rules,
        host=host, port=options.http_to_https_port,
        use_delays=options.use_server_delay,
        allow_generate_304=allow_generate_304,
        **options.shaping_http)


def AddTrafficShaper(server_manager, options, host):
  if options.shaping_dummynet:
    server_manager.AppendTrafficShaper(
        trafficshaper.TrafficShaper, host=host,
        use_loopback=not options.server_mode and host == '127.0.0.1',
        **options.shaping_dummynet)


class OptionsWrapper(object):
  """Add checks, updates, and methods to option values.

  Example:
    options, args = arg_parser.parse_args()
    options = OptionsWrapper(options, arg_parser)  # run checks and updates
    if options.record and options.HasTrafficShaping():
       [...]
  """
  _TRAFFICSHAPING_OPTIONS = {
      'down', 'up', 'delay_ms', 'packet_loss_rate', 'init_cwnd', 'net'}
  _CONFLICTING_OPTIONS = (
      ('record', ('down', 'up', 'delay_ms', 'packet_loss_rate', 'net',
                  'spdy', 'use_server_delay')),
      ('append', ('down', 'up', 'delay_ms', 'packet_loss_rate', 'net',
                  'use_server_delay')),  # same as --record
      ('net', ('down', 'up', 'delay_ms')),
      ('server', ('server_mode',)),
  )

  def __init__(self, options, parser):
    self._options = options
    self._parser = parser
    self._nondefaults = set([
        action.dest for action in parser._optionals._actions
        if getattr(options, action.dest, action.default) is not action.default])
    self._CheckConflicts()
    self._CheckValidIp('host')
    self._CheckFeatureSupport()
    self._MassageValues()

  def _CheckConflicts(self):
    """Give an error if mutually exclusive options are used."""
    for option, bad_options in self._CONFLICTING_OPTIONS:
      if option in self._nondefaults:
        for bad_option in bad_options:
          if bad_option in self._nondefaults:
            self._parser.error('Option --%s cannot be used with --%s.' %
                                (bad_option, option))

  def _CheckValidIp(self, name):
    """Give an error if option |name| is not a valid IPv4 address."""
    value = getattr(self._options, name)
    if value:
      try:
        socket.inet_aton(value)
      except Exception:
        self._parser.error('Option --%s must be a valid IPv4 address.' % name)

  def _CheckFeatureSupport(self):
    if (self._options.should_generate_certs and
        not platformsettings.HasSniSupport()):
      self._parser.error('Option --should_generate_certs requires pyOpenSSL '
                         '0.13 or greater for SNI support.')

  def _ShapingKeywordArgs(self, shaping_key):
    """Return the shaping keyword args for |shaping_key|.

    Args:
      shaping_key: one of 'dummynet', 'dns', 'http'.
    Returns:
      {}  # if shaping_key does not apply, or options have default values.
      {k: v, ...}
    """
    kwargs = {}
    def AddItemIfSet(d, kw_key, opt_key=None):
      opt_key = opt_key or kw_key
      if opt_key in self._nondefaults:
        d[kw_key] = getattr(self, opt_key)
    if ((self.shaping_type == 'proxy' and shaping_key in ('dns', 'http')) or
        self.shaping_type == shaping_key):
      AddItemIfSet(kwargs, 'delay_ms')
      if shaping_key in ('dummynet', 'http'):
        AddItemIfSet(kwargs, 'down_bandwidth', opt_key='down')
        AddItemIfSet(kwargs, 'up_bandwidth', opt_key='up')
        if shaping_key == 'dummynet':
          AddItemIfSet(kwargs, 'packet_loss_rate')
          AddItemIfSet(kwargs, 'init_cwnd')
        elif self.shaping_type != 'none':
          if 'packet_loss_rate' in self._nondefaults:
            logging.warn('Shaping type, %s, ignores --packet_loss_rate=%s',
                         self.shaping_type, self.packet_loss_rate)
          if 'init_cwnd' in self._nondefaults:
            logging.warn('Shaping type, %s, ignores --init_cwnd=%s',
                         self.shaping_type, self.init_cwnd)
    return kwargs

  def _MassageValues(self):
    """Set options that depend on the values of other options."""
    if self.append and not self.record:
      self._options.record = True
    if self.net:
      self._options.down, self._options.up, self._options.delay_ms = \
          net_configs.GetNetConfig(self.net)
      self._nondefaults.update(['down', 'up', 'delay_ms'])
    if not self.ssl:
      self._options.https_root_ca_cert_path = None
    self.shaping_dns = self._ShapingKeywordArgs('dns')
    self.shaping_http = self._ShapingKeywordArgs('http')
    self.shaping_dummynet = self._ShapingKeywordArgs('dummynet')

  def __getattr__(self, name):
    """Make the original option values available."""
    return getattr(self._options, name)

  def __repr__(self):
    """Return a json representation of the original options dictionary."""
    return json.dumps(self._options.__dict__)

  def IsRootRequired(self):
    """Returns True iff the options require whole program root access."""
    if self.server:
      return True

    def IsPrivilegedPort(port):
      return port and port < 1024

    if IsPrivilegedPort(self.port) or (self.ssl and
                                       IsPrivilegedPort(self.ssl_port)):
      return True

    if self.dns_forwarding:
      if IsPrivilegedPort(self.dns_port):
        return True
      if not self.server_mode and self.host == '127.0.0.1':
        return True

    return False


def replay(options, replay_filename):
  if options.record and sys.version_info < (2, 7, 9):
    print ('Need Python 2.7.9 or greater for recording mode.\n'
           'For instructions on how to upgrade Python on Ubuntu 14.04, see:\n'
           'http://mbless.de/blog/2016/01/09/upgrade-to-python-2711-on-ubuntu-1404-lts.html\n')
  if options.admin_check and options.IsRootRequired():
    platformsettings.rerun_as_administrator()
  configure_logging(options.log_level, options.log_file)
  server_manager = servermanager.ServerManager(options.record)
  if options.server:
    AddDnsForward(server_manager, options.server)
  else:
    if options.record:
      httparchive.HttpArchive.AssertWritable(replay_filename)
      if options.append and os.path.exists(replay_filename):
        http_archive = httparchive.HttpArchive.Load(replay_filename)
        logging.info('Appending to %s (loaded %d existing responses)',
                     replay_filename, len(http_archive))
      else:
        http_archive = httparchive.HttpArchive()
    else:
      http_archive = httparchive.HttpArchive.Load(replay_filename)
      logging.info('Loaded %d responses from %s',
                   len(http_archive), replay_filename)
    server_manager.AppendRecordCallback(http_archive.clear)

    ipfw_dns_host = None
    if options.dns_forwarding or options.shaping_dummynet:
      # compute the ip/host used for the DNS server and traffic shaping
      ipfw_dns_host = options.host
      if not ipfw_dns_host:
        ipfw_dns_host = platformsettings.get_server_ip_address(
            options.server_mode)

    real_dns_lookup = dnsproxy.RealDnsLookup(
        name_servers=[platformsettings.get_original_primary_nameserver()],
        dns_forwarding=options.dns_forwarding,
        proxy_host=ipfw_dns_host,
        proxy_port=options.dns_port)
    server_manager.AppendRecordCallback(real_dns_lookup.ClearCache)

    if options.dns_forwarding:
      if not options.server_mode and ipfw_dns_host == '127.0.0.1':
        AddDnsForward(server_manager, ipfw_dns_host)
      AddDnsProxy(server_manager, options, ipfw_dns_host, options.dns_port,
                  real_dns_lookup, http_archive)
    if options.ssl and options.https_root_ca_cert_path is None:
      options.https_root_ca_cert_path = os.path.join(os.path.dirname(__file__),
                                                     'wpr_cert.pem')
    http_proxy_address = options.host
    if not http_proxy_address:
      http_proxy_address = platformsettings.get_httpproxy_ip_address(
          options.server_mode)
    AddWebProxy(server_manager, options, http_proxy_address, real_dns_lookup,
                http_archive)
    AddTrafficShaper(server_manager, options, ipfw_dns_host)

  exit_status = 0
  try:
    server_manager.Run()
  except KeyboardInterrupt:
    logging.info('Shutting down.')
  except (dnsproxy.DnsProxyException,
          trafficshaper.TrafficShaperException,
          platformsettings.NotAdministratorError,
          platformsettings.DnsUpdateError) as e:
    logging.critical('%s: %s', e.__class__.__name__, e)
    exit_status = 1
  except Exception:
    logging.critical(traceback.format_exc())
    exit_status = 2

  if options.record:
    http_archive.Persist(replay_filename)
    logging.info('Saved %d responses to %s', len(http_archive), replay_filename)
  return exit_status


def GetParser():
  arg_parser = argparse.ArgumentParser(
      usage='%(prog)s [options] replay_file',
      description=__doc__,
      formatter_class=argparse.RawDescriptionHelpFormatter,
      epilog='http://code.google.com/p/web-page-replay/')

  arg_parser.add_argument('replay_filename', type=str, help='Replay file',
                          nargs='?')

  arg_parser.add_argument('-r', '--record', default=False,
      action='store_true',
      help='Download real responses and record them to replay_file')
  arg_parser.add_argument('--append', default=False,
      action='store_true',
      help='Append responses to replay_file.')
  arg_parser.add_argument('-l', '--log_level', default='debug',
      action='store',
      type=str,
      choices=('debug', 'info', 'warning', 'error', 'critical'),
      help='Minimum verbosity level to log')
  arg_parser.add_argument('-f', '--log_file', default=None,
      action='store',
      type=str,
      help='Log file to use in addition to writting logs to stderr.')

  network_group = arg_parser.add_argument_group(
      title='Network Simulation Options',
      description=('These options configure the network simulation in '
                   'replay mode'))
  network_group.add_argument('-u', '--up', default='0',
      action='store',
      type=str,
      help='Upload Bandwidth in [K|M]{bit/s|Byte/s}. Zero means unlimited.')
  network_group.add_argument('-d', '--down', default='0',
      action='store',
      type=str,
      help='Download Bandwidth in [K|M]{bit/s|Byte/s}. Zero means unlimited.')
  network_group.add_argument('-m', '--delay_ms', default='0',
      action='store',
      type=str,
      help='Propagation delay (latency) in milliseconds. Zero means no delay.')
  network_group.add_argument('-p', '--packet_loss_rate', default='0',
      action='store',
      type=str,
      help='Packet loss rate in range [0..1]. Zero means no loss.')
  network_group.add_argument('-w', '--init_cwnd', default='0',
      action='store',
      type=str,
      help='Set initial cwnd (linux only, requires kernel patch)')
  network_group.add_argument('--net', default=None,
      action='store',
      type=str,
      choices=net_configs.NET_CONFIG_NAMES,
      help='Select a set of network options: %s.' % ', '.join(
          net_configs.NET_CONFIG_NAMES))
  network_group.add_argument('--shaping_type', default='dummynet',
      action='store',
      choices=('dummynet', 'proxy'),
      help='When shaping is configured (i.e. --up, --down, etc.) decides '
           'whether to use |dummynet| (default), or |proxy| servers.')

  harness_group = arg_parser.add_argument_group(
      title='Replay Harness Options',
      description=('These advanced options configure various aspects '
                   'of the replay harness'))
  harness_group.add_argument('-S', '--server', default=None,
      action='store',
      type=str,
      help='IP address of host running "replay.py --server_mode". '
           'This only changes the primary DNS nameserver to use the given IP.')
  harness_group.add_argument('-M', '--server_mode', default=False,
      action='store_true',
      help='Run replay DNS & http proxies, and trafficshaping on --port '
           'without changing the primary DNS nameserver. '
           'Other hosts may connect to this using "replay.py --server" '
           'or by pointing their DNS to this server.')
  harness_group.add_argument('-i', '--inject_scripts', default='deterministic.js',
      action='store',
      dest='inject_scripts',
      help='A comma separated list of JavaScript sources to inject in all '
           'pages. By default a script is injected that eliminates sources '
           'of entropy such as Date() and Math.random() deterministic. '
           'CAUTION: Without deterministic.js, many pages will not replay.')
  harness_group.add_argument('-D', '--no-diff_unknown_requests', default=True,
      action='store_false',
      dest='diff_unknown_requests',
      help='During replay, do not show a diff of unknown requests against '
           'their nearest match in the archive.')
  harness_group.add_argument('-C', '--use_closest_match', default=False,
      action='store_true',
      dest='use_closest_match',
      help='During replay, if a request is not found, serve the closest match'
           'in the archive instead of giving a 404.')
  harness_group.add_argument('-U', '--use_server_delay', default=False,
      action='store_true',
      dest='use_server_delay',
      help='During replay, simulate server delay by delaying response time to'
           'requests.')
  harness_group.add_argument('-I', '--screenshot_dir', default=None,
      action='store',
      type=str,
      help='Save PNG images of the loaded page in the given directory.')
  harness_group.add_argument('-P', '--no-dns_private_passthrough', default=True,
      action='store_false',
      dest='dns_private_passthrough',
      help='Don\'t forward DNS requests that resolve to private network '
           'addresses. CAUTION: With this option important services like '
           'Kerberos will resolve to the HTTP proxy address.')
  harness_group.add_argument('-x', '--no-dns_forwarding', default=True,
      action='store_false',
      dest='dns_forwarding',
      help='Don\'t forward DNS requests to the local replay server. '
           'CAUTION: With this option an external mechanism must be used to '
           'forward traffic to the replay server.')
  harness_group.add_argument('--host', default=None,
      action='store',
      type=str,
      help='The IP address to bind all servers to. Defaults to 0.0.0.0 or '
           '127.0.0.1, depending on --server_mode and platform.')
  harness_group.add_argument('-o', '--port', default=80,
      action='store',
      type=int,
      help='Port number to listen on.')
  harness_group.add_argument('--ssl_port', default=443,
      action='store',
      type=int,
      help='SSL port number to listen on.')
  harness_group.add_argument('--http_to_https_port', default=None,
      action='store',
      type=int,
      help='Port on which WPR will listen for HTTP requests that it will send '
           'along as HTTPS requests.')
  harness_group.add_argument('--dns_port', default=53,
      action='store',
      type=int,
      help='DNS port number to listen on.')
  harness_group.add_argument('-c', '--https_root_ca_cert_path', default=None,
      action='store',
      type=str,
      help='Certificate file to use with SSL (gets auto-generated if needed).')
  harness_group.add_argument('--no-ssl', default=True,
      action='store_false',
      dest='ssl',
      help='Do not setup an SSL proxy.')
  harness_group.add_argument('--should_generate_certs', default=False,
      action='store_true',
      help='Use OpenSSL to generate certificate files for requested hosts.')
  harness_group.add_argument('--no-admin-check', default=True,
      action='store_false',
      dest='admin_check',
      help='Do not check if administrator access is needed.')
  harness_group.add_argument('--scramble_images', default=False,
      action='store_true',
      dest='scramble_images',
      help='Scramble image responses.')
  harness_group.add_argument('--rules_path', default=None,
      action='store',
      help='Path of file containing Python rules.')
  harness_group.add_argument('--allowed_rule_imports', default='rules',
      action='store',
      help='A comma-separate list of allowed rule imports, or \'*\' to allow'
           ' all packages.  Defaults to %(default)s.')
  return arg_parser


def main():
  arg_parser = GetParser()
  options = arg_parser.parse_args()
  options = OptionsWrapper(options, arg_parser)

  if options.server:
    options.replay_filename = None
  elif options.replay_filename is None:
    arg_parser.error('Must specify a replay_file')
  return replay(options, options.replay_filename)


if __name__ == '__main__':
  sys.exit(main())
