# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import multiprocessing
import log
import time


_RealProcess = multiprocessing.Process
__all__ = []


class ProcessSubclass(_RealProcess):
  def __init__(self, shim, *args, **kwards):
    _RealProcess.__init__(self, *args, **kwards)
    self._shim = shim

  def run(self,*args,**kwargs):
    log._disallow_tracing_control()
    try:
      r = _RealProcess.run(self, *args, **kwargs)
    finally:
      if log.trace_is_enabled():
        log.trace_flush() # todo, reduce need for this...
    return r

class ProcessShim():
  def __init__(self, group=None, target=None, name=None, args=(), kwargs={}):
    self._proc = ProcessSubclass(self, group, target, name, args, kwargs)
    # hint to testing code that the shimming worked
    self._shimmed_by_trace_event = True

  def run(self):
    self._proc.run()

  def start(self):
    self._proc.start()

  def terminate(self):
    if log.trace_is_enabled():
      # give the flush a chance to finish --> TODO: find some other way.
      time.sleep(0.25)
    self._proc.terminate()

  def join(self, timeout=None):
    self._proc.join( timeout)

  def is_alive(self):
    return self._proc.is_alive()

  @property
  def name(self):
    return self._proc.name

  @name.setter
  def name(self, name):
    self._proc.name = name

  @property
  def daemon(self):
    return self._proc.daemon

  @daemon.setter
  def daemon(self, daemonic):
    self._proc.daemon = daemonic

  @property
  def authkey(self):
    return self._proc._authkey

  @authkey.setter
  def authkey(self, authkey):
    self._proc.authkey = AuthenticationString(authkey)

  @property
  def exitcode(self):
    return self._proc.exitcode

  @property
  def ident(self):
    return self._proc.ident

  @property
  def pid(self):
    return self._proc.pid

  def __repr__(self):
    return self._proc.__repr__()

# Monkeypatch in our process replacement.
if multiprocessing.Process != ProcessShim:
  multiprocessing.Process = ProcessShim
