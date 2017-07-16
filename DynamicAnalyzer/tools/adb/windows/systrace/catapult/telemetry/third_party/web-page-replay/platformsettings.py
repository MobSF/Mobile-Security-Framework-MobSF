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

"""Provides cross-platform utility functions.

Example:
  import platformsettings
  ip = platformsettings.get_server_ip_address()

Functions with "_temporary_" in their name automatically clean-up upon
termination (via the atexit module).

For the full list of functions, see the bottom of the file.
"""

import atexit
import distutils.spawn
import distutils.version
import fileinput
import logging
import os
import platform
import re
import socket
import stat
import subprocess
import sys
import time
import urlparse


class PlatformSettingsError(Exception):
  """Module catch-all error."""
  pass


class DnsReadError(PlatformSettingsError):
  """Raised when unable to read DNS settings."""
  pass


class DnsUpdateError(PlatformSettingsError):
  """Raised when unable to update DNS settings."""
  pass


class NotAdministratorError(PlatformSettingsError):
  """Raised when not running as administrator."""
  pass


class CalledProcessError(PlatformSettingsError):
  """Raised when a _check_output() process returns a non-zero exit status."""
  def __init__(self, returncode, cmd):
    super(CalledProcessError, self).__init__()
    self.returncode = returncode
    self.cmd = cmd

  def __str__(self):
    return 'Command "%s" returned non-zero exit status %d' % (
        ' '.join(self.cmd), self.returncode)


def FindExecutable(executable):
  """Finds the given executable in PATH.

  Since WPR may be invoked as sudo, meaning PATH is empty, we also hardcode a
  few common paths.

  Returns:
    The fully qualified path with .exe appended if appropriate or None if it
    doesn't exist.
  """
  return distutils.spawn.find_executable(executable,
                                         os.pathsep.join([os.environ['PATH'],
                                                          '/sbin',
                                                          '/usr/bin',
                                                          '/usr/sbin/',
                                                          '/usr/local/sbin',
                                                          ]))

def HasSniSupport():
  try:
    import OpenSSL
    return (distutils.version.StrictVersion(OpenSSL.__version__) >=
            distutils.version.StrictVersion('0.13'))
  except ImportError:
    return False


def SupportsFdLimitControl():
  """Whether the platform supports changing the process fd limit."""
  return os.name is 'posix'


def GetFdLimit():
  """Returns a tuple of (soft_limit, hard_limit)."""
  import resource
  return resource.getrlimit(resource.RLIMIT_NOFILE)


def AdjustFdLimit(new_soft_limit, new_hard_limit):
  """Sets a new soft and hard limit for max number of fds."""
  import resource
  resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft_limit, new_hard_limit))


class SystemProxy(object):
  """A host/port pair for a HTTP or HTTPS proxy configuration."""

  def __init__(self, host, port):
    """Initialize a SystemProxy instance.

    Args:
      host: a host name or IP address string (e.g. "example.com" or "1.1.1.1").
      port: a port string or integer (e.g. "8888" or 8888).
    """
    self.host = host
    self.port = int(port) if port else None

  def __nonzero__(self):
    """True if the host is set."""
    return bool(self.host)

  @classmethod
  def from_url(cls, proxy_url):
    """Create a SystemProxy instance.

    If proxy_url is None, an empty string, or an invalid URL, the
    SystemProxy instance with have None and None for the host and port
    (no exception is raised).

    Args:
      proxy_url: a proxy url string such as "http://proxy.com:8888/".
    Returns:
      a System proxy instance.
    """
    if proxy_url:
      parse_result = urlparse.urlparse(proxy_url)
      return cls(parse_result.hostname, parse_result.port)
    return cls(None, None)


class _BasePlatformSettings(object):

  def get_system_logging_handler(self):
    """Return a handler for the logging module (optional)."""
    return None

  def rerun_as_administrator(self):
    """If needed, rerun the program with administrative privileges.

    Raises NotAdministratorError if unable to rerun.
    """
    pass

  def timer(self):
    """Return the current time in seconds as a floating point number."""
    return time.time()

  def get_server_ip_address(self, is_server_mode=False):
    """Returns the IP address to use for dnsproxy and ipfw."""
    if is_server_mode:
      return socket.gethostbyname(socket.gethostname())
    return '127.0.0.1'

  def get_httpproxy_ip_address(self, is_server_mode=False):
    """Returns the IP address to use for httpproxy."""
    if is_server_mode:
      return '0.0.0.0'
    return '127.0.0.1'

  def get_system_proxy(self, use_ssl):
    """Returns the system HTTP(S) proxy host, port."""
    del use_ssl
    return SystemProxy(None, None)

  def _ipfw_cmd(self):
    raise NotImplementedError

  def ipfw(self, *args):
    ipfw_cmd = (self._ipfw_cmd(), ) + args
    return self._check_output(*ipfw_cmd, elevate_privilege=True)

  def has_ipfw(self):
    try:
      self.ipfw('list')
      return True
    except AssertionError as e:
      logging.warning('Failed to start ipfw command. '
                      'Error: %s' % e.message)
      return False

  def _get_cwnd(self):
    return None

  def _set_cwnd(self, args):
    pass

  def _elevate_privilege_for_cmd(self, args):
    return args

  def _check_output(self, *args, **kwargs):
    """Run Popen(*args) and return its output as a byte string.

    Python 2.7 has subprocess.check_output. This is essentially the same
    except that, as a convenience, all the positional args are used as
    command arguments and the |elevate_privilege| kwarg is supported.

    Args:
      *args: sequence of program arguments
      elevate_privilege: Run the command with elevated privileges.
    Raises:
      CalledProcessError if the program returns non-zero exit status.
    Returns:
      output as a byte string.
    """
    command_args = [str(a) for a in args]

    if os.path.sep not in command_args[0]:
      qualified_command = FindExecutable(command_args[0])
      assert qualified_command, 'Failed to find %s in path' % command_args[0]
      command_args[0] = qualified_command

    if kwargs.get('elevate_privilege'):
      command_args = self._elevate_privilege_for_cmd(command_args)

    logging.debug(' '.join(command_args))
    process = subprocess.Popen(
        command_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = process.communicate()[0]
    retcode = process.poll()
    if retcode:
      raise CalledProcessError(retcode, command_args)
    return output

  def set_temporary_tcp_init_cwnd(self, cwnd):
    cwnd = int(cwnd)
    original_cwnd = self._get_cwnd()
    if original_cwnd is None:
      raise PlatformSettingsError('Unable to get current tcp init_cwnd.')
    if cwnd == original_cwnd:
      logging.info('TCP init_cwnd already set to target value: %s', cwnd)
    else:
      self._set_cwnd(cwnd)
      if self._get_cwnd() == cwnd:
        logging.info('Changed cwnd to %s', cwnd)
        atexit.register(self._set_cwnd, original_cwnd)
      else:
        logging.error('Unable to update cwnd to %s', cwnd)

  def setup_temporary_loopback_config(self):
    """Setup the loopback interface similar to real interface.

    We use loopback for much of our testing, and on some systems, loopback
    behaves differently from real interfaces.
    """
    logging.error('Platform does not support loopback configuration.')

  def _save_primary_interface_properties(self):
    self._orig_nameserver = self.get_original_primary_nameserver()

  def _restore_primary_interface_properties(self):
    self._set_primary_nameserver(self._orig_nameserver)

  def _get_primary_nameserver(self):
    raise NotImplementedError

  def _set_primary_nameserver(self, _):
    raise NotImplementedError

  def get_original_primary_nameserver(self):
    if not hasattr(self, '_original_nameserver'):
      self._original_nameserver = self._get_primary_nameserver()
      logging.info('Saved original primary DNS nameserver: %s',
                   self._original_nameserver)
    return self._original_nameserver

  def set_temporary_primary_nameserver(self, nameserver):
    self._save_primary_interface_properties()
    self._set_primary_nameserver(nameserver)
    if self._get_primary_nameserver() == nameserver:
      logging.info('Changed temporary primary nameserver to %s', nameserver)
      atexit.register(self._restore_primary_interface_properties)
    else:
      raise self._get_dns_update_error()


class _PosixPlatformSettings(_BasePlatformSettings):

  # pylint: disable=abstract-method
  # Suppress lint check for _get_primary_nameserver & _set_primary_nameserver

  def rerun_as_administrator(self):
    """If needed, rerun the program with administrative privileges.

    Raises NotAdministratorError if unable to rerun.
    """
    if os.geteuid() != 0:
      logging.warn('Rerunning with sudo: %s', sys.argv)
      os.execv('/usr/bin/sudo', ['--'] + sys.argv)

  def _elevate_privilege_for_cmd(self, args):
    def IsSetUID(path):
      return (os.stat(path).st_mode & stat.S_ISUID) == stat.S_ISUID

    def IsElevated():
      p = subprocess.Popen(
          ['sudo', '-nv'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
          stderr=subprocess.STDOUT)
      stdout = p.communicate()[0]
      # Some versions of sudo set the returncode based on whether sudo requires
      # a password currently. Other versions return output when password is
      # required and no output when the user is already authenticated.
      return not p.returncode and not stdout

    if not IsSetUID(args[0]):
      args = ['sudo'] + args

      if not IsElevated():
        print 'WPR needs to run %s under sudo. Please authenticate.' % args[1]
        subprocess.check_call(['sudo', '-v'])  # Synchronously authenticate.

        prompt = ('Would you like to always allow %s to run without sudo '
                  '(via `sudo chmod +s %s`)? (y/N)' % (args[1], args[1]))
        if raw_input(prompt).lower() == 'y':
          subprocess.check_call(['sudo', 'chmod', '+s', args[1]])
    return args

  def get_system_proxy(self, use_ssl):
    """Returns the system HTTP(S) proxy host, port."""
    proxy_url = os.environ.get('https_proxy' if use_ssl else 'http_proxy')
    return SystemProxy.from_url(proxy_url)

  def _ipfw_cmd(self):
    return 'ipfw'

  def _get_dns_update_error(self):
    return DnsUpdateError('Did you run under sudo?')

  def _sysctl(self, *args, **kwargs):
    sysctl_args = [FindExecutable('sysctl')]
    if kwargs.get('use_sudo'):
      sysctl_args = self._elevate_privilege_for_cmd(sysctl_args)
    sysctl_args.extend(str(a) for a in args)
    sysctl = subprocess.Popen(
        sysctl_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    stdout = sysctl.communicate()[0]
    return sysctl.returncode, stdout

  def has_sysctl(self, name):
    if not hasattr(self, 'has_sysctl_cache'):
      self.has_sysctl_cache = {}
    if name not in self.has_sysctl_cache:
      self.has_sysctl_cache[name] = self._sysctl(name)[0] == 0
    return self.has_sysctl_cache[name]

  def set_sysctl(self, name, value):
    rv = self._sysctl('%s=%s' % (name, value), use_sudo=True)[0]
    if rv != 0:
      logging.error('Unable to set sysctl %s: %s', name, rv)

  def get_sysctl(self, name):
    rv, value = self._sysctl('-n', name)
    if rv == 0:
      return value
    else:
      logging.error('Unable to get sysctl %s: %s', name, rv)
      return None


class _OsxPlatformSettings(_PosixPlatformSettings):
  LOCAL_SLOWSTART_MIB_NAME = 'net.inet.tcp.local_slowstart_flightsize'

  def _scutil(self, cmd):
    scutil = subprocess.Popen([FindExecutable('scutil')],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    return scutil.communicate(cmd)[0]

  def _ifconfig(self, *args):
    return self._check_output('ifconfig', *args, elevate_privilege=True)

  def set_sysctl(self, name, value):
    rv = self._sysctl('-w', '%s=%s' % (name, value), use_sudo=True)[0]
    if rv != 0:
      logging.error('Unable to set sysctl %s: %s', name, rv)

  def _get_cwnd(self):
    return int(self.get_sysctl(self.LOCAL_SLOWSTART_MIB_NAME))

  def _set_cwnd(self, size):
    self.set_sysctl(self.LOCAL_SLOWSTART_MIB_NAME, size)

  def _get_loopback_mtu(self):
    config = self._ifconfig('lo0')
    match = re.search(r'\smtu\s+(\d+)', config)
    return int(match.group(1)) if match else None

  def setup_temporary_loopback_config(self):
    """Configure loopback to temporarily use reasonably sized frames.

    OS X uses jumbo frames by default (16KB).
    """
    TARGET_LOOPBACK_MTU = 1500
    original_mtu = self._get_loopback_mtu()
    if original_mtu is None:
      logging.error('Unable to read loopback mtu. Setting left unchanged.')
      return
    if original_mtu == TARGET_LOOPBACK_MTU:
      logging.debug('Loopback MTU already has target value: %d', original_mtu)
    else:
      self._ifconfig('lo0', 'mtu', TARGET_LOOPBACK_MTU)
      if self._get_loopback_mtu() == TARGET_LOOPBACK_MTU:
        logging.debug('Set loopback MTU to %d (was %d)',
                      TARGET_LOOPBACK_MTU, original_mtu)
        atexit.register(self._ifconfig, 'lo0', 'mtu', original_mtu)
      else:
        logging.error('Unable to change loopback MTU from %d to %d',
                      original_mtu, TARGET_LOOPBACK_MTU)

  def _get_dns_service_key(self):
    output = self._scutil('show State:/Network/Global/IPv4')
    lines = output.split('\n')
    for line in lines:
      key_value = line.split(' : ')
      if key_value[0] == '  PrimaryService':
        return 'State:/Network/Service/%s/DNS' % key_value[1]
    raise DnsReadError('Unable to find DNS service key: %s', output)

  def _get_primary_nameserver(self):
    output = self._scutil('show %s' % self._get_dns_service_key())
    match = re.search(
        br'ServerAddresses\s+:\s+<array>\s+{\s+0\s+:\s+((\d{1,3}\.){3}\d{1,3})',
        output)
    if match:
      return match.group(1)
    else:
      raise DnsReadError('Unable to find primary DNS server: %s', output)

  def _set_primary_nameserver(self, dns):
    command = '\n'.join([
      'd.init',
      'd.add ServerAddresses * %s' % dns,
      'set %s' % self._get_dns_service_key()
    ])
    self._scutil(command)


class _FreeBSDPlatformSettings(_PosixPlatformSettings):
  """Partial implementation for FreeBSD.  Does not allow a DNS server to be
  launched nor ipfw to be used.
  """
  RESOLV_CONF = '/etc/resolv.conf'

  def _get_default_route_line(self):
    raise NotImplementedError

  def _set_cwnd(self, cwnd):
    raise NotImplementedError

  def _get_cwnd(self):
    raise NotImplementedError

  def setup_temporary_loopback_config(self):
    raise NotImplementedError

  def _write_resolve_conf(self, dns):
    raise NotImplementedError

  def _get_primary_nameserver(self):
    try:
      resolv_file = open(self.RESOLV_CONF)
    except IOError:
      raise DnsReadError()
    for line in resolv_file:
      if line.startswith('nameserver '):
        return line.split()[1]
    raise DnsReadError()

  def _set_primary_nameserver(self, dns):
    raise NotImplementedError


class _LinuxPlatformSettings(_PosixPlatformSettings):
  """The following thread recommends a way to update DNS on Linux:

  http://ubuntuforums.org/showthread.php?t=337553

         sudo cp /etc/dhcp3/dhclient.conf /etc/dhcp3/dhclient.conf.bak
         sudo gedit /etc/dhcp3/dhclient.conf
         #prepend domain-name-servers 127.0.0.1;
         prepend domain-name-servers 208.67.222.222, 208.67.220.220;

         prepend domain-name-servers 208.67.222.222, 208.67.220.220;
         request subnet-mask, broadcast-address, time-offset, routers,
             domain-name, domain-name-servers, host-name,
             netbios-name-servers, netbios-scope;
         #require subnet-mask, domain-name-servers;

         sudo /etc/init.d/networking restart

  The code below does not try to change dchp and does not restart networking.
  Update this as needed to make it more robust on more systems.
  """
  RESOLV_CONF = '/etc/resolv.conf'
  ROUTE_RE = re.compile('initcwnd (\d+)')
  TCP_BASE_MSS = 'net.ipv4.tcp_base_mss'
  TCP_MTU_PROBING = 'net.ipv4.tcp_mtu_probing'

  def _get_default_route_line(self):
    stdout = self._check_output('ip', 'route')
    for line in stdout.split('\n'):
      if line.startswith('default'):
        return line
    return None

  def _set_cwnd(self, cwnd):
    default_line = self._get_default_route_line()
    self._check_output(
        'ip', 'route', 'change', default_line, 'initcwnd', str(cwnd))

  def _get_cwnd(self):
    default_line = self._get_default_route_line()
    m = self.ROUTE_RE.search(default_line)
    if m:
      return int(m.group(1))
    # If 'initcwnd' wasn't found, then 0 means it's the system default.
    return 0

  def setup_temporary_loopback_config(self):
    """Setup Linux to temporarily use reasonably sized frames.

    Linux uses jumbo frames by default (16KB), using the combination
    of MTU probing and a base MSS makes it use normal sized packets.

    The reason this works is because tcp_base_mss is only used when MTU
    probing is enabled.  And since we're using the max value, it will
    always use the reasonable size.  This is relevant for server-side realism.
    The client-side will vary depending on the client TCP stack config.
    """
    ENABLE_MTU_PROBING = 2
    original_probing = self.get_sysctl(self.TCP_MTU_PROBING)
    self.set_sysctl(self.TCP_MTU_PROBING, ENABLE_MTU_PROBING)
    atexit.register(self.set_sysctl, self.TCP_MTU_PROBING, original_probing)

    TCP_FULL_MSS = 1460
    original_mss = self.get_sysctl(self.TCP_BASE_MSS)
    self.set_sysctl(self.TCP_BASE_MSS, TCP_FULL_MSS)
    atexit.register(self.set_sysctl, self.TCP_BASE_MSS, original_mss)

  def _write_resolve_conf(self, dns):
    is_first_nameserver_replaced = False
    # The fileinput module uses sys.stdout as the edited file output.
    for line in fileinput.input(self.RESOLV_CONF, inplace=1, backup='.bak'):
      if line.startswith('nameserver ') and not is_first_nameserver_replaced:
        print 'nameserver %s' % dns
        is_first_nameserver_replaced = True
      else:
        print line,
    if not is_first_nameserver_replaced:
      raise DnsUpdateError('Could not find a suitable nameserver entry in %s' %
                           self.RESOLV_CONF)

  def _get_primary_nameserver(self):
    try:
      resolv_file = open(self.RESOLV_CONF)
    except IOError:
      raise DnsReadError()
    for line in resolv_file:
      if line.startswith('nameserver '):
        return line.split()[1]
    raise DnsReadError()

  def _set_primary_nameserver(self, dns):
    """Replace the first nameserver entry with the one given."""
    try:
      self._write_resolve_conf(dns)
    except OSError, e:
      if 'Permission denied' in e:
        raise self._get_dns_update_error()
      raise


class _WindowsPlatformSettings(_BasePlatformSettings):

  # pylint: disable=abstract-method
  # Suppress lint check for _ipfw_cmd

  def get_system_logging_handler(self):
    """Return a handler for the logging module (optional).

    For Windows, output can be viewed with DebugView.
    http://technet.microsoft.com/en-us/sysinternals/bb896647.aspx
    """
    import ctypes
    output_debug_string = ctypes.windll.kernel32.OutputDebugStringA
    output_debug_string.argtypes = [ctypes.c_char_p]
    class DebugViewHandler(logging.Handler):
      def emit(self, record):
        output_debug_string('[wpr] ' + self.format(record))
    return DebugViewHandler()

  def rerun_as_administrator(self):
    """If needed, rerun the program with administrative privileges.

    Raises NotAdministratorError if unable to rerun.
    """
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
      raise NotAdministratorError('Rerun with administrator privileges.')
      #os.execv('runas', sys.argv)  # TODO: replace needed Windows magic

  def timer(self):
    """Return the current time in seconds as a floating point number.

    From time module documentation:
       On Windows, this function [time.clock()] returns wall-clock
       seconds elapsed since the first call to this function, as a
       floating point number, based on the Win32 function
       QueryPerformanceCounter(). The resolution is typically better
       than one microsecond.
    """
    return time.clock()

  def _arp(self, *args):
    return self._check_output('arp', *args)

  def _route(self, *args):
    return self._check_output('route', *args)

  def _ipconfig(self, *args):
    return self._check_output('ipconfig', *args)

  def _get_mac_address(self, ip):
    """Return the MAC address for the given ip."""
    ip_re = re.compile(r'^\s*IP(?:v4)? Address[ .]+:\s+([0-9.]+)')
    for line in self._ipconfig('/all').splitlines():
      if line[:1].isalnum():
        current_ip = None
        current_mac = None
      elif ':' in line:
        line = line.strip()
        ip_match = ip_re.match(line)
        if ip_match:
          current_ip = ip_match.group(1)
        elif line.startswith('Physical Address'):
          current_mac = line.split(':', 1)[1].lstrip()
        if current_ip == ip and current_mac:
          return current_mac
    return None

  def setup_temporary_loopback_config(self):
    """On Windows, temporarily route the server ip to itself."""
    ip = self.get_server_ip_address()
    mac_address = self._get_mac_address(ip)
    if self.mac_address:
      self._arp('-s', ip, self.mac_address)
      self._route('add', ip, ip, 'mask', '255.255.255.255')
      atexit.register(self._arp, '-d', ip)
      atexit.register(self._route, 'delete', ip, ip, 'mask', '255.255.255.255')
    else:
      logging.warn('Unable to configure loopback: MAC address not found.')
    # TODO(slamm): Configure cwnd, MTU size

  def _get_dns_update_error(self):
    return DnsUpdateError('Did you run as administrator?')

  def _netsh_show_dns(self):
    """Return DNS information:

    Example output:
        Configuration for interface "Local Area Connection 3"
        DNS servers configured through DHCP:  None
        Register with which suffix:           Primary only

        Configuration for interface "Wireless Network Connection 2"
        DNS servers configured through DHCP:  192.168.1.1
        Register with which suffix:           Primary only
    """
    return self._check_output('netsh', 'interface', 'ip', 'show', 'dns')

  def _netsh_set_dns(self, iface_name, addr):
    """Modify DNS information on the primary interface."""
    output = self._check_output('netsh', 'interface', 'ip', 'set', 'dns',
                                iface_name, 'static', addr)

  def _netsh_set_dns_dhcp(self, iface_name):
    """Modify DNS information on the primary interface."""
    output = self._check_output('netsh', 'interface', 'ip', 'set', 'dns',
                                iface_name, 'dhcp')

  def _get_interfaces_with_dns(self):
    output = self._netsh_show_dns()
    lines = output.split('\n')
    iface_re = re.compile(r'^Configuration for interface \"(?P<name>.*)\"')
    dns_re = re.compile(r'(?P<kind>.*):\s+(?P<dns>\d+\.\d+\.\d+\.\d+)')
    iface_name = None
    iface_dns = None
    iface_kind = None
    ifaces = []
    for line in lines:
      iface_match = iface_re.match(line)
      if iface_match:
        iface_name = iface_match.group('name')
      dns_match = dns_re.match(line)
      if dns_match:
        iface_dns = dns_match.group('dns')
        iface_dns_config = dns_match.group('kind').strip()
        if iface_dns_config == "Statically Configured DNS Servers":
          iface_kind = "static"
        elif iface_dns_config == "DNS servers configured through DHCP":
          iface_kind = "dhcp"
      if iface_name and iface_dns and iface_kind:
        ifaces.append((iface_dns, iface_name, iface_kind))
        iface_name = None
        iface_dns = None
    return ifaces

  def _save_primary_interface_properties(self):
    # TODO(etienneb): On windows, an interface can have multiple DNS server
    # configured. We should save/restore all of them.
    ifaces = self._get_interfaces_with_dns()
    self._primary_interfaces = ifaces

  def _restore_primary_interface_properties(self):
    for iface in self._primary_interfaces:
      (iface_dns, iface_name, iface_kind) = iface
      self._netsh_set_dns(iface_name, iface_dns)
      if iface_kind == "dhcp":
        self._netsh_set_dns_dhcp(iface_name)

  def _get_primary_nameserver(self):
    ifaces = self._get_interfaces_with_dns()
    if not len(ifaces):
      raise DnsUpdateError("Interface with valid DNS configured not found.")
    (iface_dns, iface_name, iface_kind) = ifaces[0]
    return iface_dns

  def _set_primary_nameserver(self, dns):
    for iface in self._primary_interfaces:
      (iface_dns, iface_name, iface_kind) = iface
      self._netsh_set_dns(iface_name, dns)


class _WindowsXpPlatformSettings(_WindowsPlatformSettings):
  def _ipfw_cmd(self):
    return (r'third_party\ipfw_win32\ipfw.exe',)


def _new_platform_settings(system, release):
  """Make a new instance of PlatformSettings for the current system."""
  if system == 'Darwin':
    return _OsxPlatformSettings()
  if system == 'Linux':
    return _LinuxPlatformSettings()
  if system == 'Windows' and release == 'XP':
    return _WindowsXpPlatformSettings()
  if system == 'Windows':
    return _WindowsPlatformSettings()
  if system == 'FreeBSD':
    return _FreeBSDPlatformSettings()
  raise NotImplementedError('Sorry %s %s is not supported.' % (system, release))


# Create one instance of the platform-specific settings and
# make the functions available at the module-level.
_inst = _new_platform_settings(platform.system(), platform.release())

get_system_logging_handler = _inst.get_system_logging_handler
rerun_as_administrator = _inst.rerun_as_administrator
timer = _inst.timer

get_server_ip_address = _inst.get_server_ip_address
get_httpproxy_ip_address = _inst.get_httpproxy_ip_address
get_system_proxy = _inst.get_system_proxy
ipfw = _inst.ipfw
has_ipfw = _inst.has_ipfw
set_temporary_tcp_init_cwnd = _inst.set_temporary_tcp_init_cwnd
setup_temporary_loopback_config = _inst.setup_temporary_loopback_config

get_original_primary_nameserver = _inst.get_original_primary_nameserver
set_temporary_primary_nameserver = _inst.set_temporary_primary_nameserver
