# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import logging
import optparse
import os
import pkgutil
import pydoc
import re
import sys

import telemetry
from telemetry.core import util

telemetry_dir = util.GetTelemetryDir()
docs_dir = os.path.join(telemetry_dir, 'docs', 'pydoc')

def RemoveAllDocs():
  for dirname, _, filenames in os.walk(docs_dir):
    for filename in filenames:
      os.remove(os.path.join(dirname, filename))

def GenerateHTMLForModule(module):
  html = pydoc.html.page(pydoc.describe(module),
                         pydoc.html.document(module, module.__name__))

  # pydoc writes out html with links in a variety of funky ways. We need
  # to fix them up.
  assert not telemetry_dir.endswith(os.sep)
  links = re.findall('(<a href="(.+?)">(.+?)</a>)', html)
  for link_match in links:
    link, href, link_text = link_match
    if not href.startswith('file:'):
      continue

    new_href = href.replace('file:', '')
    new_href = new_href.replace(telemetry_dir, '..')
    new_href = new_href.replace(os.sep, '/')

    new_link_text = link_text.replace(telemetry_dir + os.sep, '')

    new_link = '<a href="%s">%s</a>' % (new_href, new_link_text)
    html = html.replace(link, new_link)

  # pydoc writes out html with absolute path file links. This is not suitable
  # for checked in documentation. So, fix up the HTML after it is generated.
  #html = re.sub('href="file:%s' % telemetry_dir, 'href="..', html)
  #html = re.sub(telemetry_dir + os.sep, '', html)
  return html

def WriteHTMLForModule(module):
  page = GenerateHTMLForModule(module)
  path = os.path.join(docs_dir, '%s.html' % module.__name__)
  with open(path, 'w') as f:
    sys.stderr.write('Wrote %s\n' % os.path.relpath(path))
    f.write(page)

def GetAllModulesToDocument(module):
  modules = [module]
  for _, modname, _ in pkgutil.walk_packages(
      module.__path__, module.__name__ + '.'):
    if modname.endswith('_unittest'):
      logging.debug("skipping %s due to being a unittest", modname)
      continue

    module = __import__(modname, fromlist=[""])
    name, _ = os.path.splitext(module.__file__)
    if not os.path.exists(name + '.py'):
      logging.info("skipping %s due to being an orphan .pyc", module.__file__)
      continue

    modules.append(module)
  return modules

class AlreadyDocumentedModule(object):
  def __init__(self, filename):
    self.filename = filename

  @property
  def name(self):
    basename = os.path.basename(self.filename)
    return os.path.splitext(basename)[0]

  @property
  def contents(self):
    with open(self.filename, 'r') as f:
      return f.read()

def GetAlreadyDocumentedModules():
  modules = []
  for dirname, _, filenames in os.walk(docs_dir):
    for filename in filenames:
      path = os.path.join(dirname, filename)
      modules.append(AlreadyDocumentedModule(path))
  return modules


def IsUpdateDocsNeeded():
  already_documented_modules = GetAlreadyDocumentedModules()
  already_documented_modules_by_name = dict(
    (module.name, module) for module in already_documented_modules)
  current_modules = GetAllModulesToDocument(telemetry)

  # Quick check: if the names of modules has changed, we definitely need
  # an update.
  already_documented_module_names = set(
    m.name for m in already_documented_modules)

  current_module_names = set([m.__name__ for m in current_modules])

  if current_module_names != already_documented_module_names:
    return True

  # Generate the new docs and compare aganist the old. If changed, then a
  # an update is needed.
  for current_module in current_modules:
    already_documented_module = already_documented_modules_by_name[
      current_module.__name__]
    current_html = GenerateHTMLForModule(current_module)
    if current_html != already_documented_module.contents:
      return True

  return False

def Main(args):
  parser = optparse.OptionParser()
  parser.add_option(
      '-v', '--verbose', action='count', dest='verbosity',
      help='Increase verbosity level (repeat as needed)')
  options, args = parser.parse_args(args)
  if options.verbosity >= 2:
    logging.getLogger().setLevel(logging.DEBUG)
  elif options.verbosity:
    logging.getLogger().setLevel(logging.INFO)
  else:
    logging.getLogger().setLevel(logging.WARNING)

  assert os.path.isdir(docs_dir), '%s does not exist' % docs_dir

  RemoveAllDocs()

  old_cwd = os.getcwd()
  try:
    os.chdir(telemetry_dir)
    for module in GetAllModulesToDocument(telemetry):
      WriteHTMLForModule(module)
  finally:
    os.chdir(old_cwd)
