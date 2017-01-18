# This file is part of Androguard.
#
# Copyright (C) 2012, Anthony Desnos <desnos at t0t0.fr>
# All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import Queue
import threading
import time
import zlib

from androguard.core import androconf
from androguard.core.bytecodes import apk, dvm
from androguard.core.analysis import analysis
from androguard.core.androconf import debug
from androguard.util import read


class AndroAuto(object):
  """
    The main class which analyse automatically android apps by calling methods
    from a specific object
    :param settings: the settings of the analysis
    :type settings: dict
  """
  def __init__(self, settings):
    self.settings = settings

  def dump(self):
    """
      Dump the analysis
    """
    self.settings["my"].dump()

  def dump_file(self, filename):
    """
      Dump the analysis in a filename
    """
    self.settings["my"].dump_file(filename)

  def go(self):
    """
      Launch the analysis
    """
    myandro = self.settings["my"]

    def worker(idx, q):
      debug("Running worker-%d" % idx)

      while True:
        a, d, dx, axmlobj, arscobj = None, None, None, None, None
        try:
          filename, fileraw = q.get()
          id_file = zlib.adler32(fileraw)

          debug("(worker-%d) get %s %d" % (idx, filename, id_file))

          log = self.settings["log"](id_file, filename)

          is_analysis_dex, is_analysis_adex = True, True
          debug("(worker-%d) filtering file %d" % (idx, id_file))
          filter_file_ret, filter_file_type = myandro.filter_file(log, fileraw)
          if filter_file_ret:
            debug("(worker-%d) analysis %s" % (id_file, filter_file_type))

            if filter_file_type == "APK":
              a = myandro.create_apk(log, fileraw)
              is_analysis_dex = myandro.analysis_apk(log, a)
              fileraw = a.get_dex()
              filter_file_type = androconf.is_android_raw(fileraw)

            elif filter_file_type == "AXML":
              axmlobj = myandro.create_axml(log, fileraw)
              myandro.analysis_axml(log, axmlobj)

            elif filter_file_type == "ARSC":
              arscobj = myandro.create_arsc(log, fileraw)
              myandro.analysis_arsc(log, arscobj)

            if is_analysis_dex and filter_file_type == "DEX":
              d = myandro.create_dex(log, fileraw)
              is_analysis_adex = myandro.analysis_dex(log, d)

            elif is_analysis_dex and filter_file_type == "DEY":
              d = myandro.create_dey(log, fileraw)
              is_analysis_adex = myandro.analysis_dey(log, d)

            if is_analysis_adex and d:
              dx = myandro.create_adex(log, d)
              myandro.analysis_adex(log, dx)

            myandro.analysis_app(log, a, d, dx)

          myandro.finish(log)
        except Exception, why:
          myandro.crash(log, why)
          myandro.finish(log)

        del a, d, dx, axmlobj, arscobj
        q.task_done()

    q = Queue.Queue(self.settings["max_fetcher"])
    for i in range(self.settings["max_fetcher"]):
      t = threading.Thread(target=worker, args=[i, q])
      t.daemon = True
      t.start()

    terminated = True
    while terminated:
      terminated = myandro.fetcher(q)

      try:
        if terminated:
          time.sleep(10)
      except KeyboardInterrupt:
        terminated = False

    q.join()


class DefaultAndroAnalysis(object):
  """
    This class can be used as a template in order to analyse apps
  """
  def fetcher(self, q):
    """
      This method is called to fetch a new app in order to analyse it. The queue
      must be fill with the following format: (filename, raw)

      :param q: the Queue to put new app
    """
    pass

  def filter_file(self, log, fileraw):
    """
      This method is called in order to filer a specific app

      :param log: an object which corresponds to a unique app
      :param fileraw: the raw app (a string)

      :rtype: a set with 2 elements, the return value (boolean) if it is necessary to
      continue the analysis and the file type
    """
    file_type = androconf.is_android_raw(fileraw)
    if file_type == "APK" or file_type == "DEX" or file_type == "DEY" or file_type == "AXML" or file_type == "ARSC":
      if file_type == "APK":
        if androconf.is_valid_android_raw(fileraw):
          return (True, "APK")
      else:
        return (True, file_type)
    return (False, None)

  def create_axml(self, log, fileraw):
    """
      This method is called in order to create a new AXML object

      :param log: an object which corresponds to a unique app
      :param fileraw: the raw axml (a string)

      :rtype: an :class:`APK` object
    """
    return apk.AXMLPrinter(fileraw)

  def create_arsc(self, log, fileraw):
    """
      This method is called in order to create a new ARSC object

      :param log: an object which corresponds to a unique app
      :param fileraw: the raw arsc (a string)

      :rtype: an :class:`APK` object
    """
    return apk.ARSCParser(fileraw)

  def create_apk(self, log, fileraw):
    """
      This method is called in order to create a new APK object

      :param log: an object which corresponds to a unique app
      :param fileraw: the raw apk (a string)

      :rtype: an :class:`APK` object
    """
    return apk.APK(fileraw, raw=True, zipmodule=2)

  def create_dex(self, log, dexraw):
    """
      This method is called in order to create a DalvikVMFormat object

      :param log: an object which corresponds to a unique app
      :param dexraw: the raw classes.dex (a string)

      :rtype: a :class:`DalvikVMFormat` object
    """
    return dvm.DalvikVMFormat(dexraw)

  def create_dey(self, log, deyraw):
    """
      This method is called in order to create a DalvikOdexVMFormat object

      :param log: an object which corresponds to a unique app
      :param dexraw: the raw odex file (a string)

      :rtype: a :class:`DalvikOdexVMFormat` object
    """
    return dvm.DalvikOdexVMFormat(deyraw)

  def create_adex(self, log, dexobj):
    """
      This method is called in order to create a VMAnalysis object

      :param log: an object which corresponds to a unique app
      :param dexobj: a :class:`DalvikVMFormat` object

      :rytpe: a :class:`VMAnalysis` object
    """
    return analysis.uVMAnalysis(dexobj)

  def analysis_axml(self, log, axmlobj):
    """
      This method is called in order to know if the analysis must continue

      :param log: an object which corresponds to a unique app
      :param axmlobj: a :class:`AXMLPrinter` object

      :rtype: a boolean
    """
    return True

  def analysis_arsc(self, log, arscobj):
    """
      This method is called in order to know if the analysis must continue

      :param log: an object which corresponds to a unique app
      :param arscobj: a :class:`ARSCParser` object

      :rtype: a boolean
    """
    return True

  def analysis_apk(self, log, apkobj):
    """
      This method is called in order to know if the analysis must continue

      :param log: an object which corresponds to a unique app
      :param apkobj: a :class:`APK` object

      :rtype: a boolean
    """
    return True

  def analysis_dex(self, log, dexobj):
    """
      This method is called in order to know if the analysis must continue

      :param log: an object which corresponds to a unique app
      :param dexobj: a :class:`DalvikVMFormat` object

      :rtype: a boolean
    """
    return True

  def analysis_dey(self, log, deyobj):
    """
      This method is called in order to know if the analysis must continue

      :param log: an object which corresponds to a unique app
      :param deyobj: a :class:`DalvikOdexVMFormat` object

      :rtype: a boolean
    """
    return True

  def analysis_adex(self, log, adexobj):
    """
      This method is called in order to know if the analysis must continue

      :param log: an object which corresponds to a unique app
      :param adexobj: a :class:`VMAnalysis` object

      :rtype: a boolean
    """
    return True

  def analysis_app(self, log, apkobj, dexobj, adexobj):
    """
      This method is called if you wish to analyse the final app

      :param log: an object which corresponds to a unique app
      :param apkobj: a :class:`APK` object
      :param dexobj: a :class:`DalvikVMFormat` object
      :param adexobj: a :class:`VMAnalysis` object
    """
    pass

  def finish(self, log):
    """
      This method is called before the end of the analysis

      :param log: an object which corresponds to a unique app
    """
    pass

  def crash(self, log, why):
    """
      This method is called if a crash appends

      :param log: an object which corresponds to a unique app
      :param why: the string exception
    """
    pass

  def dump(self):
    """
      This method is called to dump the result

      :param log: an object which corresponds to a unique app
    """
    pass

  def dump_file(self, filename):
    """
      This method is called to dump the result in a file

      :param log: an object which corresponds to a unique app
      :param filename: the filename to dump the result
    """
    pass


class DirectoryAndroAnalysis(DefaultAndroAnalysis):
  """
    A simple class example to analyse a directory
  """
  def __init__(self, directory):
    self.directory = directory

  def fetcher(self, q):
    for root, dirs, files in os.walk(self.directory, followlinks=True):
      if files != []:
        for f in files:
          real_filename = root
          if real_filename[-1] != "/":
            real_filename += "/"
          real_filename += f
          q.put((real_filename, read(real_filename)))
    return False
