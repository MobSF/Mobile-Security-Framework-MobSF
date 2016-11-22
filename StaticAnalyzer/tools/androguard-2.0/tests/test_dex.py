#!/usr/bin/env python

import logging
import datetime

import sys
PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL)

from optparse import OptionParser
from androguard.core.analysis import auto
from androguard.core.androconf import set_debug

option_0 = {'name': ('-d', '--directory'), 'help': 'directory input', 'nargs': 1}
option_1 = {'name': ('-v', '--verbose'), 'help': 'add debug', 'action': 'count'}
options = [option_0, option_1]

logger = logging.getLogger("main")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(console_handler)

logger.setLevel(logging.INFO)

def test(got, expected):
    if got == expected:
        prefix = ' OK '
    else:
        prefix = '  X '
    print '%s got: %s expected: %s' % (prefix, repr(got), repr(expected)),
    return (got == expected)


class AndroLog(object):
  def __init__(self, id_file, filename):
    self.id_file = id_file
    self.filename = filename

  def dump(self, msg):
    now = datetime.datetime.now()
    str_date = now.strftime("%Y-%m-%d %H:%M:%S ")
    logger.info(str_date + "%s[%d]: %s" % (self.filename, self.id_file, msg))

  def error(self, msg):
    now = datetime.datetime.now()
    str_date = now.strftime("%Y-%m-%d %H:%M:%S ")
    logger.info(str_date + "ERROR %s[%d]: %s" % (self.filename, self.id_file, msg))
    import traceback
    traceback.print_exc()


class MyDEXAnalysis(auto.DirectoryAndroAnalysis):
  def __init__(self, directory):
    super(MyDEXAnalysis, self).__init__(directory)

  def filter_file(self, log, fileraw):
    ret, file_type = super(MyDEXAnalysis, self).filter_file(log, fileraw)
    if file_type != "APK" and file_type != "DEX" and file_type != "DEY":
      return (False, None)
    return (ret, file_type)

  def analysis_dex(self, log, dex):
    log.dump("%s" % str(dex))
    for method in dex.get_methods():
      idx = 0
      for i in method.get_instructions():
        i.get_name(), i.show_buff(idx)
        idx += i.get_length()

    return False

  def analysis_dey(self, log, dey):
    log.dump("%s" % str(dey))
    for method in dey.get_methods():
      idx = 0
      for i in method.get_instructions():
        i.get_name(), i.show_buff(idx)
        idx += i.get_length()
    return False

  def crash(self, log, why):
    log.error(why)


def main(options, arguments):
  if options.verbose:
    set_debug()

  if options.directory:
    settings = {
      "my": MyDEXAnalysis(options.directory),
      "log": AndroLog,
      "max_fetcher": 3,
    }

    aa = auto.AndroAuto(settings)
    aa.go()

if __name__ == "__main__":
    parser = OptionParser()
    for option in options:
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
    main(options, arguments)
