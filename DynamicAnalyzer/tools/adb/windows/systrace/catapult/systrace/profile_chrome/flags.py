# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import optparse


def OutputOptions(parser):
  output_options = optparse.OptionGroup(parser, 'Output options')
  output_options.add_option('-o', '--output', dest='output_file',
                            help='Save trace output to file.')
  output_options.add_option('--json', help='Save trace as raw JSON instead of '
                            'HTML.', dest='write_json')
  output_options.add_option('--view', help='Open resulting trace file in a '
                            'browser.', action='store_true')
  return output_options
