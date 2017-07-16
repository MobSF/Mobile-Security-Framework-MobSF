#!/usr/bin/python
"""
Copyright 2016 Google Inc. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import asyncore
import gc
import logging
import platform
import Queue
import re
import signal
import socket
import sys
import threading
import time

server = None
in_pipe = None
out_pipe = None
must_exit = False
options = None
dest_addresses = None
connections = {}
dns_cache = {}
port_mappings = None
map_localhost = False
needs_flush = False
flush_pipes = False
last_activity = None
REMOVE_TCP_OVERHEAD = 1460.0 / 1500.0
lock = threading.Lock()
background_activity_count = 0


def PrintMessage(msg):
  # Print the message to stdout & flush to make sure that the message is not
  # buffered when tsproxy is run as a subprocess.
  print >> sys.stdout, msg
  sys.stdout.flush()

########################################################################################################################
#   Traffic-shaping pipe (just passthrough for now)
########################################################################################################################
class TSPipe():
  PIPE_IN = 0
  PIPE_OUT = 1

  def __init__(self, direction, latency, kbps):
    self.direction = direction
    self.latency = latency
    self.kbps = kbps
    self.queue = Queue.Queue()
    self.last_tick = time.clock()
    self.next_message = None
    self.available_bytes = .0
    self.peer = 'server'
    if self.direction == self.PIPE_IN:
      self.peer = 'client'

  def SendMessage(self, message, main_thread = True):
    global connections, in_pipe, out_pipe
    message_sent = False
    now = time.clock()
    if message['message'] == 'closed':
      message['time'] = now
    else:
      message['time'] = time.clock() + self.latency
    message['size'] = .0
    if 'data' in message:
      message['size'] = float(len(message['data']))
    try:
      connection_id = message['connection']
      # Send messages directly, bypassing the queues is throttling is disabled and we are on the main thread
      if main_thread and connection_id in connections and self.peer in connections[connection_id]and self.latency == 0 and self.kbps == .0:
        message_sent = self.SendPeerMessage(message)
    except:
      pass
    if not message_sent:
      try:
        self.queue.put(message)
      except:
        pass

  def SendPeerMessage(self, message):
    global last_activity
    last_activity = time.clock()
    message_sent = False
    connection_id = message['connection']
    if connection_id in connections:
      if self.peer in connections[connection_id]:
        try:
          connections[connection_id][self.peer].handle_message(message)
          message_sent = True
        except:
          # Clean up any disconnected connections
          try:
            connections[connection_id]['server'].close()
          except:
            pass
          try:
            connections[connection_id]['client'].close()
          except:
            pass
          del connections[connection_id]
    return message_sent

  def tick(self):
    global connections
    global flush_pipes
    processed_messages = False
    now = time.clock()
    try:
      if self.next_message is None:
        self.next_message = self.queue.get_nowait()

      # Accumulate bandwidth if an available packet/message was waiting since our last tick
      if self.next_message is not None and self.kbps > .0 and self.next_message['time'] <= now:
        elapsed = now - self.last_tick
        accumulated_bytes = elapsed * self.kbps * 1000.0 / 8.0
        self.available_bytes += accumulated_bytes

      # process messages as long as the next message is sendable (latency or available bytes)
      while (self.next_message is not None) and\
          (flush_pipes or ((self.next_message['time'] <= now) and
                          (self.kbps <= .0 or self.next_message['size'] <= self.available_bytes))):
        self.queue.task_done()
        processed_messages = True
        if self.kbps > .0:
          self.available_bytes -= self.next_message['size']
        self.SendPeerMessage(self.next_message)
        self.next_message = None
        self.next_message = self.queue.get_nowait()
    except:
      pass

    # Only accumulate bytes while we have messages that are ready to send
    if self.next_message is None or self.next_message['time'] > now:
      self.available_bytes = .0
    self.last_tick = now

    return processed_messages


########################################################################################################################
#   Threaded DNS resolver
########################################################################################################################
class AsyncDNS(threading.Thread):
  def __init__(self, client_id, hostname, port, result_pipe):
    threading.Thread.__init__(self)
    self.hostname = hostname
    self.port = port
    self.client_id = client_id
    self.result_pipe = result_pipe

  def run(self):
    global lock, background_activity_count
    try:
      logging.debug('[{0:d}] AsyncDNS - calling getaddrinfo for {1}:{2:d}'.format(self.client_id, self.hostname, self.port))
      addresses = socket.getaddrinfo(self.hostname, self.port)
      logging.info('[{0:d}] Resolving {1}:{2:d} Completed'.format(self.client_id, self.hostname, self.port))
    except:
      addresses = ()
      logging.info('[{0:d}] Resolving {1}:{2:d} Failed'.format(self.client_id, self.hostname, self.port))
    message = {'message': 'resolved', 'connection': self.client_id, 'addresses': addresses}
    self.result_pipe.SendMessage(message, False)
    lock.acquire()
    if background_activity_count > 0:
      background_activity_count -= 1
    lock.release()
    # open and close a local socket which will interrupt the long polling loop to process the message
    s = socket.socket()
    s.connect((server.ipaddr, server.port))
    s.close()


########################################################################################################################
#   TCP Client
########################################################################################################################
class TCPConnection(asyncore.dispatcher):
  STATE_ERROR = -1
  STATE_IDLE = 0
  STATE_RESOLVING = 1
  STATE_CONNECTING = 2
  STATE_CONNECTED = 3

  def __init__(self, client_id):
    global options
    asyncore.dispatcher.__init__(self)
    self.client_id = client_id
    self.state = self.STATE_IDLE
    self.buffer = ''
    self.addr = None
    self.dns_thread = None
    self.hostname = None
    self.port = None
    self.needs_config = True
    self.needs_close = False
    self.is_localhost = False
    self.did_resolve = False

  def SendMessage(self, type, message):
    message['message'] = type
    message['connection'] = self.client_id
    in_pipe.SendMessage(message)

  def handle_message(self, message):
    if message['message'] == 'data' and 'data' in message and len(message['data']):
      self.buffer += message['data']
      if self.state == self.STATE_CONNECTED:
        self.handle_write()
    elif message['message'] == 'resolve':
      self.HandleResolve(message)
    elif message['message'] == 'connect':
      self.HandleConnect(message)
    elif message['message'] == 'closed':
      if len(self.buffer) == 0:
        self.handle_close()
      else:
        self.needs_close = True

  def handle_error(self):
    logging.warning('[{0:d}] Error'.format(self.client_id))
    if self.state == self.STATE_CONNECTING:
      self.SendMessage('connected', {'success': False, 'address': self.addr})

  def handle_close(self):
    logging.info('[{0:d}] Server Connection Closed'.format(self.client_id))
    self.state = self.STATE_ERROR
    self.close()
    try:
      if self.client_id in connections:
        if 'server' in connections[self.client_id]:
          del connections[self.client_id]['server']
        if 'client' in connections[self.client_id]:
          self.SendMessage('closed', {})
        else:
          del connections[self.client_id]
    except:
      pass

  def handle_connect(self):
    if self.state == self.STATE_CONNECTING:
      self.state = self.STATE_CONNECTED
      self.SendMessage('connected', {'success': True, 'address': self.addr})
      logging.info('[{0:d}] Connected'.format(self.client_id))
    self.handle_write()

  def writable(self):
    if self.state == self.STATE_CONNECTING:
      return True
    return len(self.buffer) > 0

  def handle_write(self):
    if self.needs_config:
      self.needs_config = False
      self.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
      self.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 128 * 1024)
      self.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 128 * 1024)
    if len(self.buffer) > 0:
      sent = self.send(self.buffer)
      logging.debug('[{0:d}] TCP => {1:d} byte(s)'.format(self.client_id, sent))
      self.buffer = self.buffer[sent:]
      if self.needs_close and len(self.buffer) == 0:
        self.needs_close = False
        self.handle_close()

  def handle_read(self):
    try:
      while True:
        data = self.recv(1460)
        if data:
          if self.state == self.STATE_CONNECTED:
            logging.debug('[{0:d}] TCP <= {1:d} byte(s)'.format(self.client_id, len(data)))
            self.SendMessage('data', {'data': data})
        else:
          return
    except:
      pass

  def HandleResolve(self, message):
    global in_pipe,  map_localhost, lock, background_activity_count
    self.did_resolve = True
    if 'hostname' in message:
      self.hostname = message['hostname']
    self.port = 0
    if 'port' in message:
      self.port = message['port']
    logging.info('[{0:d}] Resolving {1}:{2:d}'.format(self.client_id, self.hostname, self.port))
    if self.hostname == 'localhost':
      self.hostname = '127.0.0.1'
    if self.hostname == '127.0.0.1':
      logging.info('[{0:d}] Connection to localhost detected'.format(self.client_id))
      self.is_localhost = True
    if (dest_addresses is not None) and (not self.is_localhost or map_localhost):
      logging.info('[{0:d}] Resolving {1}:{2:d} to mapped address {3}'.format(self.client_id, self.hostname, self.port, dest_addresses))
      self.SendMessage('resolved', {'addresses': dest_addresses})
    else:
      lock.acquire()
      background_activity_count += 1
      lock.release()
      self.state = self.STATE_RESOLVING
      self.dns_thread = AsyncDNS(self.client_id, self.hostname, self.port, in_pipe)
      self.dns_thread.start()

  def HandleConnect(self, message):
    global map_localhost
    if 'addresses' in message and len(message['addresses']):
      self.state = self.STATE_CONNECTING
      if not self.did_resolve and message['addresses'][0] == '127.0.0.1':
        logging.info('[{0:d}] Connection to localhost detected'.format(self.client_id))
        self.is_localhost = True
      if (dest_addresses is not None) and (not self.is_localhost or map_localhost):
        self.addr = dest_addresses[0]
      else:
        self.addr = message['addresses'][0]
      self.create_socket(self.addr[0], socket.SOCK_STREAM)
      addr = self.addr[4][0]
      if not self.is_localhost or map_localhost:
        port = GetDestPort(message['port'])
      else:
        port = message['port']
      logging.info('[{0:d}] Connecting to {1}:{2:d}'.format(self.client_id, addr, port))
      self.connect((addr, port))


########################################################################################################################
#   Socks5 Server
########################################################################################################################
class Socks5Server(asyncore.dispatcher):

  def __init__(self, host, port):
    asyncore.dispatcher.__init__(self)
    self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
      #self.set_reuse_addr()
      self.bind((host, port))
      self.listen(socket.SOMAXCONN)
      self.ipaddr, self.port = self.getsockname()
      self.current_client_id = 0
    except:
      PrintMessage("Unable to listen on {0}:{1}. Is the port already in use?".format(host, port))
      exit(1)

  def handle_accept(self):
    global connections
    pair = self.accept()
    if pair is not None:
      sock, addr = pair
      self.current_client_id += 1
      logging.info('[{0:d}] Incoming connection from {1}'.format(self.current_client_id, repr(addr)))
      connections[self.current_client_id] = {
        'client' : Socks5Connection(sock, self.current_client_id),
        'server' : None
      }


# Socks5 reference: https://en.wikipedia.org/wiki/SOCKS#SOCKS5
class Socks5Connection(asyncore.dispatcher):
  STATE_ERROR = -1
  STATE_WAITING_FOR_HANDSHAKE = 0
  STATE_WAITING_FOR_CONNECT_REQUEST = 1
  STATE_RESOLVING = 2
  STATE_CONNECTING = 3
  STATE_CONNECTED = 4

  def __init__(self, connected_socket, client_id):
    global options
    asyncore.dispatcher.__init__(self, connected_socket)
    self.client_id = client_id
    self.state = self.STATE_WAITING_FOR_HANDSHAKE
    self.ip = None
    self.addresses = None
    self.hostname = None
    self.port = None
    self.requested_address = None
    self.buffer = ''
    self.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    self.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 128 * 1024)
    self.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 128 * 1024)
    self.needs_close = False

  def SendMessage(self, type, message):
    message['message'] = type
    message['connection'] = self.client_id
    out_pipe.SendMessage(message)

  def handle_message(self, message):
    if message['message'] == 'data' and 'data' in message and len(message['data']) > 0:
      self.buffer += message['data']
      if self.state == self.STATE_CONNECTED:
        self.handle_write()
    elif message['message'] == 'resolved':
      self.HandleResolved(message)
    elif message['message'] == 'connected':
      self.HandleConnected(message)
      self.handle_write()
    elif message['message'] == 'closed':
      if len(self.buffer) == 0:
        logging.info('[{0:d}] Server connection close being processed, closing Browser connection'.format(self.client_id))
        self.handle_close()
      else:
        logging.info('[{0:d}] Server connection close being processed, queuing browser connection close'.format(self.client_id))
        self.needs_close = True

  def writable(self):
    return len(self.buffer) > 0

  def handle_write(self):
    if len(self.buffer) > 0:
      sent = self.send(self.buffer)
      logging.debug('[{0:d}] SOCKS <= {1:d} byte(s)'.format(self.client_id, sent))
      self.buffer = self.buffer[sent:]
      if self.needs_close and len(self.buffer) == 0:
        logging.info('[{0:d}] queued browser connection close being processed, closing Browser connection'.format(self.client_id))
        self.needs_close = False
        self.handle_close()

  def handle_read(self):
    global connections
    global dns_cache
    try:
      while True:
        # Consume in up-to packet-sized chunks (TCP packet payload as 1460 bytes from 1500 byte ethernet frames)
        data = self.recv(1460)
        if data:
          data_len = len(data)
          if self.state == self.STATE_CONNECTED:
            logging.debug('[{0:d}] SOCKS => {1:d} byte(s)'.format(self.client_id, data_len))
            self.SendMessage('data', {'data': data})
          elif self.state == self.STATE_WAITING_FOR_HANDSHAKE:
            self.state = self.STATE_ERROR #default to an error state, set correctly if things work out
            if data_len >= 2 and ord(data[0]) == 0x05:
              supports_no_auth = False
              auth_count = ord(data[1])
              if data_len == auth_count + 2:
                for i in range(auth_count):
                  offset = i + 2
                  if ord(data[offset]) == 0:
                    supports_no_auth = True
              if supports_no_auth:
                # Respond with a message that "No Authentication" was agreed to
                logging.info('[{0:d}] New Socks5 client'.format(self.client_id))
                response = chr(0x05) + chr(0x00)
                self.state = self.STATE_WAITING_FOR_CONNECT_REQUEST
                self.buffer += response
                self.handle_write()
          elif self.state == self.STATE_WAITING_FOR_CONNECT_REQUEST:
            self.state = self.STATE_ERROR #default to an error state, set correctly if things work out
            if data_len >= 10 and ord(data[0]) == 0x05 and ord(data[2]) == 0x00:
              if ord(data[1]) == 0x01: #TCP connection (only supported method for now)
                connections[self.client_id]['server'] = TCPConnection(self.client_id)
              self.requested_address = data[3:]
              port_offset = 0
              if ord(data[3]) == 0x01:
                port_offset = 8
                self.ip = '{0:d}.{1:d}.{2:d}.{3:d}'.format(ord(data[4]), ord(data[5]), ord(data[6]), ord(data[7]))
              elif ord(data[3]) == 0x03:
                name_len = ord(data[4])
                if data_len >= 6 + name_len:
                  port_offset = 5 + name_len
                  self.hostname = data[5:5 + name_len]
              elif ord(data[3]) == 0x04 and data_len >= 22:
                port_offset = 20
                self.ip = ''
                for i in range(16):
                  self.ip += '{0:02x}'.format(ord(data[4 + i]))
                  if i % 2 and i < 15:
                    self.ip += ':'
              if port_offset and connections[self.client_id]['server'] is not None:
                self.port = 256 * ord(data[port_offset]) + ord(data[port_offset + 1])
                if self.port:
                  if self.ip is None and self.hostname is not None:
                    if self.hostname in dns_cache:
                      self.state = self.STATE_CONNECTING
                      self.addresses = dns_cache[self.hostname]
                      self.SendMessage('connect', {'addresses': self.addresses, 'port': self.port})
                    else:
                      self.state = self.STATE_RESOLVING
                      self.SendMessage('resolve', {'hostname': self.hostname, 'port': self.port})
                  elif self.ip is not None:
                    self.state = self.STATE_CONNECTING
                    logging.debug('[{0:d}] Socks Connect - calling getaddrinfo for {1}:{2:d}'.format(self.client_id, self.ip, self.port))
                    self.addresses = socket.getaddrinfo(self.ip, self.port)
                    self.SendMessage('connect', {'addresses': self.addresses, 'port': self.port})
        else:
          return
    except:
      pass

  def handle_close(self):
    logging.info('[{0:d}] Browser Connection Closed by browser'.format(self.client_id))
    self.state = self.STATE_ERROR
    self.close()
    try:
      if self.client_id in connections:
        if 'client' in connections[self.client_id]:
          del connections[self.client_id]['client']
        if 'server' in connections[self.client_id]:
          self.SendMessage('closed', {})
        else:
          del connections[self.client_id]
    except:
      pass

  def HandleResolved(self, message):
    global dns_cache
    if self.state == self.STATE_RESOLVING:
      if 'addresses' in message and len(message['addresses']):
        self.state = self.STATE_CONNECTING
        self.addresses = message['addresses']
        dns_cache[self.hostname] = self.addresses
        logging.debug('[{0:d}] Resolved {1}, Connecting'.format(self.client_id, self.hostname))
        self.SendMessage('connect', {'addresses': self.addresses, 'port': self.port})
      else:
        # Send host unreachable error
        self.state = self.STATE_ERROR
        self.buffer += chr(0x05) + chr(0x04) + self.requested_address
        self.handle_write()

  def HandleConnected(self, message):
    if 'success' in message and self.state == self.STATE_CONNECTING:
      response = chr(0x05)
      if message['success']:
        response += chr(0x00)
        logging.debug('[{0:d}] Connected to {1}'.format(self.client_id, self.hostname))
        self.state = self.STATE_CONNECTED
      else:
        response += chr(0x04)
        self.state = self.STATE_ERROR
      response += chr(0x00)
      response += self.requested_address
      self.buffer += response
      self.handle_write()


########################################################################################################################
#   stdin command processor
########################################################################################################################
class CommandProcessor():
  def __init__(self):
    thread = threading.Thread(target = self.run, args=())
    thread.daemon = True
    thread.start()

  def run(self):
    global must_exit
    while not must_exit:
      for line in iter(sys.stdin.readline, ''):
        self.ProcessCommand(line.strip())

  def ProcessCommand(self, input):
    global in_pipe
    global out_pipe
    global needs_flush
    global REMOVE_TCP_OVERHEAD
    global port_mappings
    global server
    if len(input):
      ok = False
      try:
        command = input.split()
        if len(command) and len(command[0]):
          if command[0].lower() == 'flush':
            ok = True
          elif command[0].lower() == 'set' and len(command) >= 3:
            if command[1].lower() == 'rtt' and len(command[2]):
              rtt = float(command[2])
              latency = rtt / 2000.0
              in_pipe.latency = latency
              out_pipe.latency = latency
              ok = True
            elif command[1].lower() == 'inkbps' and len(command[2]):
              in_pipe.kbps = float(command[2]) * REMOVE_TCP_OVERHEAD
              ok = True
            elif command[1].lower() == 'outkbps' and len(command[2]):
              out_pipe.kbps = float(command[2]) * REMOVE_TCP_OVERHEAD
              ok = True
            elif command[1].lower() == 'mapports' and len(command[2]):
              SetPortMappings(command[2])
              ok = True
          elif command[0].lower() == 'reset' and len(command) >= 2:
            if command[1].lower() == 'rtt' or command[1].lower() == 'all':
              in_pipe.latency = 0
              out_pipe.latency = 0
              ok = True
            if command[1].lower() == 'inkbps' or command[1].lower() == 'all':
              in_pipe.kbps = 0
              ok = True
            if command[1].lower() == 'outkbps' or command[1].lower() == 'all':
              out_pipe.kbps = 0
              ok = True
            if command[1].lower() == 'mapports' or command[1].lower() == 'all':
              port_mappings = {}
              ok = True

          if ok:
            needs_flush = True
      except:
        pass
      if not ok:
        PrintMessage('ERROR')
      # open and close a local socket which will interrupt the long polling loop to process the flush
      if needs_flush:
        s = socket.socket()
        s.connect((server.ipaddr, server.port))
        s.close()


########################################################################################################################
#   Main Entry Point
########################################################################################################################
def main():
  global server
  global options
  global in_pipe
  global out_pipe
  global dest_addresses
  global port_mappings
  global map_localhost
  import argparse
  global REMOVE_TCP_OVERHEAD
  parser = argparse.ArgumentParser(description='Traffic-shaping socks5 proxy.',
                                   prog='tsproxy')
  parser.add_argument('-v', '--verbose', action='count', help="Increase verbosity (specify multiple times for more). -vvvv for full debug output.")
  parser.add_argument('--logfile', help="Write log messages to given file instead of stdout.")
  parser.add_argument('-b', '--bind', default='localhost', help="Server interface address (defaults to localhost).")
  parser.add_argument('-p', '--port', type=int, default=1080, help="Server port (defaults to 1080, use 0 for randomly assigned).")
  parser.add_argument('-r', '--rtt', type=float, default=.0, help="Round Trip Time Latency (in ms).")
  parser.add_argument('-i', '--inkbps', type=float, default=.0, help="Download Bandwidth (in 1000 bits/s - Kbps).")
  parser.add_argument('-o', '--outkbps', type=float, default=.0, help="Upload Bandwidth (in 1000 bits/s - Kbps).")
  parser.add_argument('-w', '--window', type=int, default=10, help="Emulated TCP initial congestion window (defaults to 10).")
  parser.add_argument('-d', '--desthost', help="Redirect all outbound connections to the specified host.")
  parser.add_argument('-m', '--mapports', help="Remap outbound ports. Comma-separated list of original:new with * as a wildcard. --mapports '443:8443,*:8080'")
  parser.add_argument('-l', '--localhost', action='store_true', default=False,
                      help="Include connections already destined for localhost/127.0.0.1 in the host and port remapping.")
  options = parser.parse_args()

  # Set up logging
  log_level = logging.CRITICAL
  if options.verbose == 1:
    log_level = logging.ERROR
  elif options.verbose == 2:
    log_level = logging.WARNING
  elif options.verbose == 3:
    log_level = logging.INFO
  elif options.verbose >= 4:
    log_level = logging.DEBUG
  if options.logfile is not None:
    logging.basicConfig(filename=options.logfile, level=log_level,
                        format="%(asctime)s.%(msecs)03d - %(message)s", datefmt="%H:%M:%S")
  else:
    logging.basicConfig(level=log_level, format="%(asctime)s.%(msecs)03d - %(message)s", datefmt="%H:%M:%S")

  # Parse any port mappings
  if options.mapports:
    SetPortMappings(options.mapports)

  map_localhost = options.localhost

  # Resolve the address for a rewrite destination host if one was specified
  if options.desthost:
    logging.debug('Startup - calling getaddrinfo for {0}:{1:d}'.format(options.desthost, GetDestPort(80)))
    dest_addresses = socket.getaddrinfo(options.desthost, GetDestPort(80))

  # Set up the pipes.  1/2 of the latency gets applied in each direction (and /1000 to convert to seconds)
  in_pipe = TSPipe(TSPipe.PIPE_IN, options.rtt / 2000.0, options.inkbps * REMOVE_TCP_OVERHEAD)
  out_pipe = TSPipe(TSPipe.PIPE_OUT, options.rtt / 2000.0, options.outkbps * REMOVE_TCP_OVERHEAD)

  signal.signal(signal.SIGINT, signal_handler)
  server = Socks5Server(options.bind, options.port)
  command_processor = CommandProcessor()
  PrintMessage('Started Socks5 proxy server on {0}:{1:d}\nHit Ctrl-C to exit.'.format(server.ipaddr, server.port))
  run_loop()

def signal_handler(signal, frame):
  global server
  global must_exit
  logging.error('Exiting...')
  must_exit = True
  del server


# Wrapper around the asyncore loop that lets us poll the in/out pipes every 1ms
def run_loop():
  global must_exit
  global in_pipe
  global out_pipe
  global needs_flush
  global flush_pipes
  global last_activity
  winmm = None

  # increase the windows timer resolution to 1ms
  if platform.system() == "Windows":
    try:
      import ctypes
      winmm = ctypes.WinDLL('winmm')
      winmm.timeBeginPeriod(1)
    except:
      pass

  last_activity = time.clock()
  last_check = time.clock()
  # disable gc to avoid pauses during traffic shaping/proxying
  gc.disable()
  while not must_exit:
    # Tick every 1ms if traffic-shaping is enabled and we have data or are doing background dns lookups, every 1 second otherwise
    lock.acquire()
    tick_interval = 0.001
    if background_activity_count == 0:
      if in_pipe.next_message is None and in_pipe.queue.empty() and out_pipe.next_message is None and out_pipe.queue.empty():
        tick_interval = 1.0
      elif in_pipe.kbps == .0 and in_pipe.latency == 0 and out_pipe.kbps == .0 and out_pipe.latency == 0:
        tick_interval = 1.0
    lock.release()
    asyncore.poll(tick_interval, asyncore.socket_map)
    if needs_flush:
      flush_pipes = True
      needs_flush = False
    out_pipe.tick()
    in_pipe.tick()
    if flush_pipes:
      PrintMessage('OK')
      flush_pipes = False
    # Every 500 ms check to see if it is a good time to do a gc
    now = time.clock()
    if now - last_check > 0.5:
      last_check = now
      # manually gc after 5 seconds of idle
      if now - last_activity >= 5:
        last_activity = now
        logging.debug("Triggering manual GC")
        gc.collect()

  if winmm is not None:
    winmm.timeEndPeriod(1)

def GetDestPort(port):
  global port_mappings
  if port_mappings is not None:
    src_port = str(port)
    if src_port in port_mappings:
      return port_mappings[src_port]
    elif 'default' in port_mappings:
      return port_mappings['default']
  return port


def SetPortMappings(map_string):
  global port_mappings
  port_mappings = {}
  map_string = map_string.strip('\'" \t\r\n')
  for pair in map_string.split(','):
    (src, dest) = pair.split(':')
    if src == '*':
      port_mappings['default'] = int(dest)
      logging.debug("Default port mapped to port {0}".format(dest))
    else:
      logging.debug("Port {0} mapped to port {1}".format(src, dest))
      port_mappings[src] = int(dest)


if '__main__' == __name__:
  main()
