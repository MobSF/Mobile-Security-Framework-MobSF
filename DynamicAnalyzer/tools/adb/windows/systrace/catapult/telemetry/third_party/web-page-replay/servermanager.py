#!/usr/bin/env python
# Copyright 2011 Google Inc. All Rights Reserved.
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

"""Control "replay.py --server_mode" (e.g. switch from record to replay)."""

import sys
import time

class ServerManager(object):
  """Run servers until is removed or an exception is raised.

  Servers start in the order they are appended and stop in the
  opposite order. Servers are started by calling the initializer
  passed to ServerManager.Append() and by calling __enter__(). Once an
  server's initializer is called successfully, the __exit__() function
  is guaranteed to be called when ServerManager.Run() completes.
  """

  def __init__(self, is_record_mode):
    """Initialize a server manager."""
    self.initializers = []
    self.record_callbacks = []
    self.replay_callbacks = []
    self.traffic_shapers = []
    self.is_record_mode = is_record_mode
    self.should_exit = False

  def Append(self, initializer, *init_args, **init_kwargs):
    """Append a server to the end of the list to run.

    Servers start in the order they are appended and stop in the
    opposite order.

    Args:
      initializer: a function that returns a server instance.
          A server needs to implement the with-statement interface.
      init_args: positional arguments for the initializer.
      init_args: keyword arguments for the initializer.
    """
    self.initializers.append((initializer, init_args, init_kwargs))

  def AppendTrafficShaper(self, initializer, *init_args, **init_kwargs):
    """Append a traffic shaper to the end of the list to run.

    Args:
      initializer: a function that returns a server instance.
          A server needs to implement the with-statement interface.
      init_args: positional arguments for the initializer.
      init_args: keyword arguments for the initializer.
    """
    self.traffic_shapers.append((initializer, init_args, init_kwargs))

  def AppendRecordCallback(self, func):
    """Append a function to the list to call when switching to record mode.

    Args:
      func: a function that takes no arguments and returns no value.
    """
    self.record_callbacks.append(func)

  def AppendReplayCallback(self, func):
    """Append a function to the list to call when switching to replay mode.

    Args:
      func: a function that takes no arguments and returns no value.
    """
    self.replay_callbacks.append(func)

  def IsRecordMode(self):
    """Call all the functions that have been registered to enter replay mode."""
    return self.is_record_mode

  def SetRecordMode(self):
    """Call all the functions that have been registered to enter record mode."""
    self.is_record_mode = True
    for record_func in self.record_callbacks:
      record_func()

  def SetReplayMode(self):
    """Call all the functions that have been registered to enter replay mode."""
    self.is_record_mode = False
    for replay_func in self.replay_callbacks:
      replay_func()

  def Run(self):
    """Create the servers and loop.

    The loop quits if a server raises an exception.

    Raises:
      any exception raised by the servers
    """
    server_exits = []
    server_ports = []
    exception_info = (None, None, None)
    try:
      for initializer, init_args, init_kwargs in self.initializers:
        server = initializer(*init_args, **init_kwargs)
        if server:
          server_exits.insert(0, server.__exit__)
          server.__enter__()
          if hasattr(server, 'server_port'):
            server_ports.append(server.server_port)
      for initializer, init_args, init_kwargs in self.traffic_shapers:
        init_kwargs['ports'] = server_ports
        shaper = initializer(*init_args, **init_kwargs)
        if server:
          server_exits.insert(0, shaper.__exit__)
          shaper.__enter__()
      while True:
        time.sleep(1)
        if self.should_exit:
          break
    except Exception:
      exception_info = sys.exc_info()
    finally:
      for server_exit in server_exits:
        try:
          if server_exit(*exception_info):
            exception_info = (None, None, None)
        except Exception:
          exception_info = sys.exc_info()
      if exception_info != (None, None, None):
        # pylint: disable=raising-bad-type
        raise exception_info[0], exception_info[1], exception_info[2]
