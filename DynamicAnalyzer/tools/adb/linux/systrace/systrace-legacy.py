#!/usr/bin/env python

# Copyright (c) 2011 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Android system-wide tracing utility.

This is a tool for capturing a trace that includes data from both userland and
the kernel.  It creates an HTML file for visualizing the trace.
"""

import errno, optparse, os, select, subprocess, sys, time, zlib

# This list is based on the tags in frameworks/native/include/utils/Trace.h.
trace_tag_bits = {
  'gfx':      1<<1,
  'input':    1<<2,
  'view':     1<<3,
  'webview':  1<<4,
  'wm':       1<<5,
  'am':       1<<6,
  'sync':     1<<7,
  'audio':    1<<8,
  'video':    1<<9,
  'camera':   1<<10,
}

flattened_css_file = 'style.css'
flattened_js_file = 'script.js'

def add_adb_serial(command, serial):
  if serial != None:
    command.insert(1, serial)
    command.insert(1, '-s')

def main():
  parser = optparse.OptionParser()
  parser.add_option('-o', dest='output_file', help='write HTML to FILE',
                    default='trace.html', metavar='FILE')
  parser.add_option('-t', '--time', dest='trace_time', type='int',
                    help='trace for N seconds', metavar='N')
  parser.add_option('-b', '--buf-size', dest='trace_buf_size', type='int',
                    help='use a trace buffer size of N KB', metavar='N')
  parser.add_option('-d', '--disk', dest='trace_disk', default=False,
                    action='store_true', help='trace disk I/O (requires root)')
  parser.add_option('-f', '--cpu-freq', dest='trace_cpu_freq', default=False,
                    action='store_true', help='trace CPU frequency changes')
  parser.add_option('-i', '--cpu-idle', dest='trace_cpu_idle', default=False,
                    action='store_true', help='trace CPU idle events')
  parser.add_option('-l', '--cpu-load', dest='trace_cpu_load', default=False,
                    action='store_true', help='trace CPU load')
  parser.add_option('-s', '--no-cpu-sched', dest='trace_cpu_sched', default=True,
                    action='store_false', help='inhibit tracing CPU ' +
                    'scheduler (allows longer trace times by reducing data ' +
                    'rate into buffer)')
  parser.add_option('-u', '--bus-utilization', dest='trace_bus_utilization',
                    default=False, action='store_true',
                    help='trace bus utilization (requires root)')
  parser.add_option('-w', '--workqueue', dest='trace_workqueue', default=False,
                    action='store_true', help='trace the kernel workqueues ' +
                    '(requires root)')
  parser.add_option('--set-tags', dest='set_tags', action='store',
                    help='set the enabled trace tags and exit; set to a ' +
                    'comma separated list of: ' +
                    ', '.join(trace_tag_bits.iterkeys()))
  parser.add_option('--link-assets', dest='link_assets', default=False,
                    action='store_true', help='link to original CSS or JS resources '
                    'instead of embedding them')
  parser.add_option('--from-file', dest='from_file', action='store',
                    help='read the trace from a file rather than running a live trace')
  parser.add_option('--asset-dir', dest='asset_dir', default='trace-viewer',
                    type='string', help='')
  parser.add_option('-e', '--serial', dest='device_serial', type='string',
                    help='adb device serial number')
  options, args = parser.parse_args()

  if options.set_tags:
    flags = 0
    tags = options.set_tags.split(',')
    for tag in tags:
      try:
        flags |= trace_tag_bits[tag]
      except KeyError:
        parser.error('unrecognized tag: %s\nknown tags are: %s' %
                     (tag, ', '.join(trace_tag_bits.iterkeys())))
    atrace_args = ['adb', 'shell', 'setprop', 'debug.atrace.tags.enableflags', hex(flags)]
    add_adb_serial(atrace_args, options.device_serial)
    try:
      subprocess.check_call(atrace_args)
    except subprocess.CalledProcessError, e:
      print >> sys.stderr, 'unable to set tags: %s' % e
    print '\nSet enabled tags to: %s\n' % ', '.join(tags)
    print ('You will likely need to restart the Android framework for this to ' +
          'take effect:\n\n    adb shell stop\n    adb shell ' +
          'start\n')
    return

  atrace_args = ['adb', 'shell', 'atrace', '-z']
  add_adb_serial(atrace_args, options.device_serial)

  if options.trace_disk:
    atrace_args.append('-d')
  if options.trace_cpu_freq:
    atrace_args.append('-f')
  if options.trace_cpu_idle:
    atrace_args.append('-i')
  if options.trace_cpu_load:
    atrace_args.append('-l')
  if options.trace_cpu_sched:
    atrace_args.append('-s')
  if options.trace_bus_utilization:
    atrace_args.append('-u')
  if options.trace_workqueue:
    atrace_args.append('-w')
  if options.trace_time is not None:
    if options.trace_time > 0:
      atrace_args.extend(['-t', str(options.trace_time)])
    else:
      parser.error('the trace time must be a positive number')
  if options.trace_buf_size is not None:
    if options.trace_buf_size > 0:
      atrace_args.extend(['-b', str(options.trace_buf_size)])
    else:
      parser.error('the trace buffer size must be a positive number')

  if options.from_file is not None:
    atrace_args = ['cat', options.from_file]

  script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))

  if options.link_assets:
    src_dir = os.path.join(script_dir, options.asset_dir, 'src')
    build_dir = os.path.join(script_dir, options.asset_dir, 'build')

    js_files, js_flattenizer, css_files, templates = get_assets(src_dir, build_dir)

    css = '\n'.join(linked_css_tag % (os.path.join(src_dir, f)) for f in css_files)
    js = '<script language="javascript">\n%s</script>\n' % js_flattenizer
    js += '\n'.join(linked_js_tag % (os.path.join(src_dir, f)) for f in js_files)

  else:
    css_filename = os.path.join(script_dir, flattened_css_file)
    js_filename = os.path.join(script_dir, flattened_js_file)
    css = compiled_css_tag % (open(css_filename).read())
    js = compiled_js_tag % (open(js_filename).read())
    templates = ''

  html_filename = options.output_file

  trace_started = False
  leftovers = ''
  adb = subprocess.Popen(atrace_args, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
  dec = zlib.decompressobj()
  while True:
    ready = select.select([adb.stdout, adb.stderr], [], [adb.stdout, adb.stderr])
    if adb.stderr in ready[0]:
      err = os.read(adb.stderr.fileno(), 4096)
      sys.stderr.write(err)
      sys.stderr.flush()
    if adb.stdout in ready[0]:
      out = leftovers + os.read(adb.stdout.fileno(), 4096)
      if options.from_file is None:
        out = out.replace('\r\n', '\n')
      if out.endswith('\r'):
        out = out[:-1]
        leftovers = '\r'
      else:
        leftovers = ''
      if not trace_started:
        lines = out.splitlines(True)
        out = ''
        for i, line in enumerate(lines):
          if line == 'TRACE:\n':
            sys.stdout.write("downloading trace...")
            sys.stdout.flush()
            out = ''.join(lines[i+1:])
            html_prefix = read_asset(script_dir, 'prefix.html')
            html_file = open(html_filename, 'w')
            html_file.write(html_prefix % (css, js, templates))
            trace_started = True
            break
          elif 'TRACE:'.startswith(line) and i == len(lines) - 1:
            leftovers = line + leftovers
          else:
            sys.stdout.write(line)
            sys.stdout.flush()
      if len(out) > 0:
        out = dec.decompress(out)
      html_out = out.replace('\n', '\\n\\\n')
      if len(html_out) > 0:
        html_file.write(html_out)
    result = adb.poll()
    if result is not None:
      break
  if result != 0:
    print >> sys.stderr, 'adb returned error code %d' % result
  elif trace_started:
    html_out = dec.flush().replace('\n', '\\n\\\n').replace('\r', '')
    if len(html_out) > 0:
      html_file.write(html_out)
    html_suffix = read_asset(script_dir, 'suffix.html')
    html_file.write(html_suffix)
    html_file.close()
    print " done\n\n    wrote file://%s\n" % (os.path.abspath(options.output_file))
  else:
    print >> sys.stderr, ('An error occured while capturing the trace.  Output ' +
      'file was not written.')

def read_asset(src_dir, filename):
  return open(os.path.join(src_dir, filename)).read()

def get_assets(src_dir, build_dir):
  sys.path.append(build_dir)
  gen = __import__('generate_standalone_timeline_view', {}, {})
  parse_deps = __import__('parse_deps', {}, {})
  gen_templates = __import__('generate_template_contents', {}, {})
  filenames = gen._get_input_filenames()
  load_sequence = parse_deps.calc_load_sequence(filenames, src_dir)

  js_files = []
  js_flattenizer = "window.FLATTENED = {};\n"
  js_flattenizer += "window.FLATTENED_RAW_SCRIPTS = {};\n"
  css_files = []

  for module in load_sequence:
    js_files.append(os.path.relpath(module.filename, src_dir))
    js_flattenizer += "window.FLATTENED['%s'] = true;\n" % module.name
    for dependent_raw_script_name in module.dependent_raw_script_names:
      js_flattenizer += (
        "window.FLATTENED_RAW_SCRIPTS['%s'] = true;\n" %
        dependent_raw_script_name)

    for style_sheet in module.style_sheets:
      css_files.append(os.path.relpath(style_sheet.filename, src_dir))

  templates = gen_templates.generate_templates()

  sys.path.pop()

  return (js_files, js_flattenizer, css_files, templates)

compiled_css_tag = """<style type="text/css">%s</style>"""
compiled_js_tag = """<script language="javascript">%s</script>"""

linked_css_tag = """<link rel="stylesheet" href="%s"></link>"""
linked_js_tag = """<script language="javascript" src="%s"></script>"""

if __name__ == '__main__':
  main()
