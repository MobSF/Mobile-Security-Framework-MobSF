# Copyright (C) 2003-2007, 2009, 2010 Nominum, Inc.
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NOMINUM DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NOMINUM BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""DNS stub resolver.

@var default_resolver: The default resolver object
@type default_resolver: dns.resolver.Resolver object"""

import socket
import sys
import time

import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype

if sys.platform == 'win32':
    import _winreg

class NXDOMAIN(dns.exception.DNSException):
    """The query name does not exist."""
    pass

# The definition of the Timeout exception has moved from here to the
# dns.exception module.  We keep dns.resolver.Timeout defined for
# backwards compatibility.

Timeout = dns.exception.Timeout

class NoAnswer(dns.exception.DNSException):
    """The response did not contain an answer to the question."""
    pass

class NoNameservers(dns.exception.DNSException):
    """No non-broken nameservers are available to answer the query."""
    pass

class NotAbsolute(dns.exception.DNSException):
    """Raised if an absolute domain name is required but a relative name
    was provided."""
    pass

class NoRootSOA(dns.exception.DNSException):
    """Raised if for some reason there is no SOA at the root name.
    This should never happen!"""
    pass


class Answer(object):
    """DNS stub resolver answer

    Instances of this class bundle up the result of a successful DNS
    resolution.

    For convenience, the answer object implements much of the sequence
    protocol, forwarding to its rrset.  E.g. "for a in answer" is
    equivalent to "for a in answer.rrset", "answer[i]" is equivalent
    to "answer.rrset[i]", and "answer[i:j]" is equivalent to
    "answer.rrset[i:j]".

    Note that CNAMEs or DNAMEs in the response may mean that answer
    node's name might not be the query name.

    @ivar qname: The query name
    @type qname: dns.name.Name object
    @ivar rdtype: The query type
    @type rdtype: int
    @ivar rdclass: The query class
    @type rdclass: int
    @ivar response: The response message
    @type response: dns.message.Message object
    @ivar rrset: The answer
    @type rrset: dns.rrset.RRset object
    @ivar expiration: The time when the answer expires
    @type expiration: float (seconds since the epoch)
    """
    def __init__(self, qname, rdtype, rdclass, response):
        self.qname = qname
        self.rdtype = rdtype
        self.rdclass = rdclass
        self.response = response
        min_ttl = -1
        rrset = None
        for count in xrange(0, 15):
            try:
                rrset = response.find_rrset(response.answer, qname,
                                            rdclass, rdtype)
                if min_ttl == -1 or rrset.ttl < min_ttl:
                    min_ttl = rrset.ttl
                break
            except KeyError:
                if rdtype != dns.rdatatype.CNAME:
                    try:
                        crrset = response.find_rrset(response.answer,
                                                     qname,
                                                     rdclass,
                                                     dns.rdatatype.CNAME)
                        if min_ttl == -1 or crrset.ttl < min_ttl:
                            min_ttl = crrset.ttl
                        for rd in crrset:
                            qname = rd.target
                            break
                        continue
                    except KeyError:
                        raise NoAnswer
                raise NoAnswer
        if rrset is None:
            raise NoAnswer
        self.rrset = rrset
        self.expiration = time.time() + min_ttl

    def __getattr__(self, attr):
        if attr == 'name':
            return self.rrset.name
        elif attr == 'ttl':
            return self.rrset.ttl
        elif attr == 'covers':
            return self.rrset.covers
        elif attr == 'rdclass':
            return self.rrset.rdclass
        elif attr == 'rdtype':
            return self.rrset.rdtype
        else:
            raise AttributeError(attr)

    def __len__(self):
        return len(self.rrset)

    def __iter__(self):
        return iter(self.rrset)

    def __getitem__(self, i):
        return self.rrset[i]

    def __delitem__(self, i):
        del self.rrset[i]

    def __getslice__(self, i, j):
        return self.rrset[i:j]

    def __delslice__(self, i, j):
        del self.rrset[i:j]

class Cache(object):
    """Simple DNS answer cache.

    @ivar data: A dictionary of cached data
    @type data: dict
    @ivar cleaning_interval: The number of seconds between cleanings.  The
    default is 300 (5 minutes).
    @type cleaning_interval: float
    @ivar next_cleaning: The time the cache should next be cleaned (in seconds
    since the epoch.)
    @type next_cleaning: float
    """

    def __init__(self, cleaning_interval=300.0):
        """Initialize a DNS cache.

        @param cleaning_interval: the number of seconds between periodic
        cleanings.  The default is 300.0
        @type cleaning_interval: float.
        """

        self.data = {}
        self.cleaning_interval = cleaning_interval
        self.next_cleaning = time.time() + self.cleaning_interval

    def maybe_clean(self):
        """Clean the cache if it's time to do so."""

        now = time.time()
        if self.next_cleaning <= now:
            keys_to_delete = []
            for (k, v) in self.data.iteritems():
                if v.expiration <= now:
                    keys_to_delete.append(k)
            for k in keys_to_delete:
                del self.data[k]
            now = time.time()
            self.next_cleaning = now + self.cleaning_interval

    def get(self, key):
        """Get the answer associated with I{key}.  Returns None if
        no answer is cached for the key.
        @param key: the key
        @type key: (dns.name.Name, int, int) tuple whose values are the
        query name, rdtype, and rdclass.
        @rtype: dns.resolver.Answer object or None
        """

        self.maybe_clean()
        v = self.data.get(key)
        if v is None or v.expiration <= time.time():
            return None
        return v

    def put(self, key, value):
        """Associate key and value in the cache.
        @param key: the key
        @type key: (dns.name.Name, int, int) tuple whose values are the
        query name, rdtype, and rdclass.
        @param value: The answer being cached
        @type value: dns.resolver.Answer object
        """

        self.maybe_clean()
        self.data[key] = value

    def flush(self, key=None):
        """Flush the cache.

        If I{key} is specified, only that item is flushed.  Otherwise
        the entire cache is flushed.

        @param key: the key to flush
        @type key: (dns.name.Name, int, int) tuple or None
        """

        if not key is None:
            if self.data.has_key(key):
                del self.data[key]
        else:
            self.data = {}
            self.next_cleaning = time.time() + self.cleaning_interval

class Resolver(object):
    """DNS stub resolver

    @ivar domain: The domain of this host
    @type domain: dns.name.Name object
    @ivar nameservers: A list of nameservers to query.  Each nameserver is
    a string which contains the IP address of a nameserver.
    @type nameservers: list of strings
    @ivar search: The search list.  If the query name is a relative name,
    the resolver will construct an absolute query name by appending the search
    names one by one to the query name.
    @type search: list of dns.name.Name objects
    @ivar port: The port to which to send queries.  The default is 53.
    @type port: int
    @ivar timeout: The number of seconds to wait for a response from a
    server, before timing out.
    @type timeout: float
    @ivar lifetime: The total number of seconds to spend trying to get an
    answer to the question.  If the lifetime expires, a Timeout exception
    will occur.
    @type lifetime: float
    @ivar keyring: The TSIG keyring to use.  The default is None.
    @type keyring: dict
    @ivar keyname: The TSIG keyname to use.  The default is None.
    @type keyname: dns.name.Name object
    @ivar keyalgorithm: The TSIG key algorithm to use.  The default is
    dns.tsig.default_algorithm.
    @type keyalgorithm: string
    @ivar edns: The EDNS level to use.  The default is -1, no Edns.
    @type edns: int
    @ivar ednsflags: The EDNS flags
    @type ednsflags: int
    @ivar payload: The EDNS payload size.  The default is 0.
    @type payload: int
    @ivar cache: The cache to use.  The default is None.
    @type cache: dns.resolver.Cache object
    """
    def __init__(self, filename='/etc/resolv.conf', configure=True):
        """Initialize a resolver instance.

        @param filename: The filename of a configuration file in
        standard /etc/resolv.conf format.  This parameter is meaningful
        only when I{configure} is true and the platform is POSIX.
        @type filename: string or file object
        @param configure: If True (the default), the resolver instance
        is configured in the normal fashion for the operating system
        the resolver is running on.  (I.e. a /etc/resolv.conf file on
        POSIX systems and from the registry on Windows systems.)
        @type configure: bool"""

        self.reset()
        if configure:
            if sys.platform == 'win32':
                self.read_registry()
            elif filename:
                self.read_resolv_conf(filename)

    def reset(self):
        """Reset all resolver configuration to the defaults."""
        self.domain = \
            dns.name.Name(dns.name.from_text(socket.gethostname())[1:])
        if len(self.domain) == 0:
            self.domain = dns.name.root
        self.nameservers = []
        self.search = []
        self.port = 53
        self.timeout = 2.0
        self.lifetime = 30.0
        self.keyring = None
        self.keyname = None
        self.keyalgorithm = dns.tsig.default_algorithm
        self.edns = -1
        self.ednsflags = 0
        self.payload = 0
        self.cache = None

    def read_resolv_conf(self, f):
        """Process f as a file in the /etc/resolv.conf format.  If f is
        a string, it is used as the name of the file to open; otherwise it
        is treated as the file itself."""
        if isinstance(f, str) or isinstance(f, unicode):
            try:
                f = open(f, 'r')
            except IOError:
                # /etc/resolv.conf doesn't exist, can't be read, etc.
                # We'll just use the default resolver configuration.
                self.nameservers = ['127.0.0.1']
                return
            want_close = True
        else:
            want_close = False
        try:
            for l in f:
                if len(l) == 0 or l[0] == '#' or l[0] == ';':
                    continue
                tokens = l.split()
                if len(tokens) == 0:
                    continue
                if tokens[0] == 'nameserver':
                    self.nameservers.append(tokens[1])
                elif tokens[0] == 'domain':
                    self.domain = dns.name.from_text(tokens[1])
                elif tokens[0] == 'search':
                    for suffix in tokens[1:]:
                        self.search.append(dns.name.from_text(suffix))
        finally:
            if want_close:
                f.close()
        if len(self.nameservers) == 0:
            self.nameservers.append('127.0.0.1')

    def _determine_split_char(self, entry):
        #
        # The windows registry irritatingly changes the list element
        # delimiter in between ' ' and ',' (and vice-versa) in various
        # versions of windows.
        #
        if entry.find(' ') >= 0:
            split_char = ' '
        elif entry.find(',') >= 0:
            split_char = ','
        else:
            # probably a singleton; treat as a space-separated list.
            split_char = ' '
        return split_char

    def _config_win32_nameservers(self, nameservers):
        """Configure a NameServer registry entry."""
        # we call str() on nameservers to convert it from unicode to ascii
        nameservers = str(nameservers)
        split_char = self._determine_split_char(nameservers)
        ns_list = nameservers.split(split_char)
        for ns in ns_list:
            if not ns in self.nameservers:
                self.nameservers.append(ns)

    def _config_win32_domain(self, domain):
        """Configure a Domain registry entry."""
        # we call str() on domain to convert it from unicode to ascii
        self.domain = dns.name.from_text(str(domain))

    def _config_win32_search(self, search):
        """Configure a Search registry entry."""
        # we call str() on search to convert it from unicode to ascii
        search = str(search)
        split_char = self._determine_split_char(search)
        search_list = search.split(split_char)
        for s in search_list:
            if not s in self.search:
                self.search.append(dns.name.from_text(s))

    def _config_win32_fromkey(self, key):
        """Extract DNS info from a registry key."""
        try:
            servers, rtype = _winreg.QueryValueEx(key, 'NameServer')
        except WindowsError:
            servers = None
        if servers:
            self._config_win32_nameservers(servers)
            try:
                dom, rtype = _winreg.QueryValueEx(key, 'Domain')
                if dom:
                    self._config_win32_domain(dom)
            except WindowsError:
                pass
        else:
            try:
                servers, rtype = _winreg.QueryValueEx(key, 'DhcpNameServer')
            except WindowsError:
                servers = None
            if servers:
                self._config_win32_nameservers(servers)
                try:
                    dom, rtype = _winreg.QueryValueEx(key, 'DhcpDomain')
                    if dom:
                        self._config_win32_domain(dom)
                except WindowsError:
                    pass
        try:
            search, rtype = _winreg.QueryValueEx(key, 'SearchList')
        except WindowsError:
            search = None
        if search:
            self._config_win32_search(search)

    def read_registry(self):
        """Extract resolver configuration from the Windows registry."""
        lm = _winreg.ConnectRegistry(None, _winreg.HKEY_LOCAL_MACHINE)
        want_scan = False
        try:
            try:
                # XP, 2000
                tcp_params = _winreg.OpenKey(lm,
                                             r'SYSTEM\CurrentControlSet'
                                             r'\Services\Tcpip\Parameters')
                want_scan = True
            except EnvironmentError:
                # ME
                tcp_params = _winreg.OpenKey(lm,
                                             r'SYSTEM\CurrentControlSet'
                                             r'\Services\VxD\MSTCP')
            try:
                self._config_win32_fromkey(tcp_params)
            finally:
                tcp_params.Close()
            if want_scan:
                interfaces = _winreg.OpenKey(lm,
                                             r'SYSTEM\CurrentControlSet'
                                             r'\Services\Tcpip\Parameters'
                                             r'\Interfaces')
                try:
                    i = 0
                    while True:
                        try:
                            guid = _winreg.EnumKey(interfaces, i)
                            i += 1
                            key = _winreg.OpenKey(interfaces, guid)
                            if not self._win32_is_nic_enabled(lm, guid, key):
                                continue
                            try:
                                self._config_win32_fromkey(key)
                            finally:
                                key.Close()
                        except EnvironmentError:
                            break
                finally:
                    interfaces.Close()
        finally:
            lm.Close()

    def _win32_is_nic_enabled(self, lm, guid, interface_key):
         # Look in the Windows Registry to determine whether the network
         # interface corresponding to the given guid is enabled.
         #
         # (Code contributed by Paul Marks, thanks!)
         #
         try:
             # This hard-coded location seems to be consistent, at least
             # from Windows 2000 through Vista.
             connection_key = _winreg.OpenKey(
                 lm,
                 r'SYSTEM\CurrentControlSet\Control\Network'
                 r'\{4D36E972-E325-11CE-BFC1-08002BE10318}'
                 r'\%s\Connection' % guid)

             try:
                 # The PnpInstanceID points to a key inside Enum
                 (pnp_id, ttype) = _winreg.QueryValueEx(
                     connection_key, 'PnpInstanceID')

                 if ttype != _winreg.REG_SZ:
                     raise ValueError

                 device_key = _winreg.OpenKey(
                     lm, r'SYSTEM\CurrentControlSet\Enum\%s' % pnp_id)

                 try:
                     # Get ConfigFlags for this device
                     (flags, ttype) = _winreg.QueryValueEx(
                         device_key, 'ConfigFlags')

                     if ttype != _winreg.REG_DWORD:
                         raise ValueError

                     # Based on experimentation, bit 0x1 indicates that the
                     # device is disabled.
                     return not (flags & 0x1)

                 finally:
                     device_key.Close()
             finally:
                 connection_key.Close()
         except (EnvironmentError, ValueError):
             # Pre-vista, enabled interfaces seem to have a non-empty
             # NTEContextList; this was how dnspython detected enabled
             # nics before the code above was contributed.  We've retained
             # the old method since we don't know if the code above works
             # on Windows 95/98/ME.
             try:
                 (nte, ttype) = _winreg.QueryValueEx(interface_key,
                                                     'NTEContextList')
                 return nte is not None
             except WindowsError:
                 return False

    def _compute_timeout(self, start):
        now = time.time()
        if now < start:
            if start - now > 1:
                # Time going backwards is bad.  Just give up.
                raise Timeout
            else:
                # Time went backwards, but only a little.  This can
                # happen, e.g. under vmware with older linux kernels.
                # Pretend it didn't happen.
                now = start
        duration = now - start
        if duration >= self.lifetime:
            raise Timeout
        return min(self.lifetime - duration, self.timeout)

    def query(self, qname, rdtype=dns.rdatatype.A, rdclass=dns.rdataclass.IN,
              tcp=False, source=None):
        """Query nameservers to find the answer to the question.

        The I{qname}, I{rdtype}, and I{rdclass} parameters may be objects
        of the appropriate type, or strings that can be converted into objects
        of the appropriate type.  E.g. For I{rdtype} the integer 2 and the
        the string 'NS' both mean to query for records with DNS rdata type NS.

        @param qname: the query name
        @type qname: dns.name.Name object or string
        @param rdtype: the query type
        @type rdtype: int or string
        @param rdclass: the query class
        @type rdclass: int or string
        @param tcp: use TCP to make the query (default is False).
        @type tcp: bool
        @param source: bind to this IP address (defaults to machine default IP).
        @type source: IP address in dotted quad notation
        @rtype: dns.resolver.Answer instance
        @raises Timeout: no answers could be found in the specified lifetime
        @raises NXDOMAIN: the query name does not exist
        @raises NoAnswer: the response did not contain an answer
        @raises NoNameservers: no non-broken nameservers are available to
        answer the question."""

        if isinstance(qname, (str, unicode)):
            qname = dns.name.from_text(qname, None)
        if isinstance(rdtype, str):
            rdtype = dns.rdatatype.from_text(rdtype)
        if isinstance(rdclass, str):
            rdclass = dns.rdataclass.from_text(rdclass)
        qnames_to_try = []
        if qname.is_absolute():
            qnames_to_try.append(qname)
        else:
            if len(qname) > 1:
                qnames_to_try.append(qname.concatenate(dns.name.root))
            if self.search:
                for suffix in self.search:
                    qnames_to_try.append(qname.concatenate(suffix))
            else:
                qnames_to_try.append(qname.concatenate(self.domain))
        all_nxdomain = True
        start = time.time()
        for qname in qnames_to_try:
            if self.cache:
                answer = self.cache.get((qname, rdtype, rdclass))
                if answer:
                    return answer
            request = dns.message.make_query(qname, rdtype, rdclass)
            if not self.keyname is None:
                request.use_tsig(self.keyring, self.keyname, self.keyalgorithm)
            request.use_edns(self.edns, self.ednsflags, self.payload)
            response = None
            #
            # make a copy of the servers list so we can alter it later.
            #
            nameservers = self.nameservers[:]
            backoff = 0.10
            while response is None:
                if len(nameservers) == 0:
                    raise NoNameservers
                for nameserver in nameservers[:]:
                    timeout = self._compute_timeout(start)
                    try:
                        if tcp:
                            response = dns.query.tcp(request, nameserver,
                                                     timeout, self.port,
                                                     source=source)
                        else:
                            response = dns.query.udp(request, nameserver,
                                                     timeout, self.port,
                                                     source=source)
                    except (socket.error, dns.exception.Timeout):
                        #
                        # Communication failure or timeout.  Go to the
                        # next server
                        #
                        response = None
                        continue
                    except dns.query.UnexpectedSource:
                        #
                        # Who knows?  Keep going.
                        #
                        response = None
                        continue
                    except dns.exception.FormError:
                        #
                        # We don't understand what this server is
                        # saying.  Take it out of the mix and
                        # continue.
                        #
                        nameservers.remove(nameserver)
                        response = None
                        continue
                    rcode = response.rcode()
                    if rcode == dns.rcode.NOERROR or \
                           rcode == dns.rcode.NXDOMAIN:
                        break
                    #
                    # We got a response, but we're not happy with the
                    # rcode in it.  Remove the server from the mix if
                    # the rcode isn't SERVFAIL.
                    #
                    if rcode != dns.rcode.SERVFAIL:
                        nameservers.remove(nameserver)
                    response = None
                if not response is None:
                    break
                #
                # All nameservers failed!
                #
                if len(nameservers) > 0:
                    #
                    # But we still have servers to try.  Sleep a bit
                    # so we don't pound them!
                    #
                    timeout = self._compute_timeout(start)
                    sleep_time = min(timeout, backoff)
                    backoff *= 2
                    time.sleep(sleep_time)
            if response.rcode() == dns.rcode.NXDOMAIN:
                continue
            all_nxdomain = False
            break
        if all_nxdomain:
            raise NXDOMAIN
        answer = Answer(qname, rdtype, rdclass, response)
        if self.cache:
            self.cache.put((qname, rdtype, rdclass), answer)
        return answer

    def use_tsig(self, keyring, keyname=None,
                 algorithm=dns.tsig.default_algorithm):
        """Add a TSIG signature to the query.

        @param keyring: The TSIG keyring to use; defaults to None.
        @type keyring: dict
        @param keyname: The name of the TSIG key to use; defaults to None.
        The key must be defined in the keyring.  If a keyring is specified
        but a keyname is not, then the key used will be the first key in the
        keyring.  Note that the order of keys in a dictionary is not defined,
        so applications should supply a keyname when a keyring is used, unless
        they know the keyring contains only one key.
        @param algorithm: The TSIG key algorithm to use.  The default
        is dns.tsig.default_algorithm.
        @type algorithm: string"""
        self.keyring = keyring
        if keyname is None:
            self.keyname = self.keyring.keys()[0]
        else:
            self.keyname = keyname
        self.keyalgorithm = algorithm

    def use_edns(self, edns, ednsflags, payload):
        """Configure Edns.

        @param edns: The EDNS level to use.  The default is -1, no Edns.
        @type edns: int
        @param ednsflags: The EDNS flags
        @type ednsflags: int
        @param payload: The EDNS payload size.  The default is 0.
        @type payload: int"""

        if edns is None:
            edns = -1
        self.edns = edns
        self.ednsflags = ednsflags
        self.payload = payload

default_resolver = None

def get_default_resolver():
    """Get the default resolver, initializing it if necessary."""
    global default_resolver
    if default_resolver is None:
        default_resolver = Resolver()
    return default_resolver

def query(qname, rdtype=dns.rdatatype.A, rdclass=dns.rdataclass.IN,
          tcp=False, source=None):
    """Query nameservers to find the answer to the question.

    This is a convenience function that uses the default resolver
    object to make the query.
    @see: L{dns.resolver.Resolver.query} for more information on the
    parameters."""
    return get_default_resolver().query(qname, rdtype, rdclass, tcp, source)

def zone_for_name(name, rdclass=dns.rdataclass.IN, tcp=False, resolver=None):
    """Find the name of the zone which contains the specified name.

    @param name: the query name
    @type name: absolute dns.name.Name object or string
    @param rdclass: The query class
    @type rdclass: int
    @param tcp: use TCP to make the query (default is False).
    @type tcp: bool
    @param resolver: the resolver to use
    @type resolver: dns.resolver.Resolver object or None
    @rtype: dns.name.Name"""

    if isinstance(name, (str, unicode)):
        name = dns.name.from_text(name, dns.name.root)
    if resolver is None:
        resolver = get_default_resolver()
    if not name.is_absolute():
        raise NotAbsolute(name)
    while 1:
        try:
            answer = resolver.query(name, dns.rdatatype.SOA, rdclass, tcp)
            return name
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            try:
                name = name.parent()
            except dns.name.NoParent:
                raise NoRootSOA
