"""
 Copyright (C) 2017  RedNaga. http://rednaga.io
 All rights reserved. Contact: rednaga@protonmail.com


 This file is part of APKiD


 Commercial License Usage
 ------------------------
 Licensees holding valid commercial APKiD licenses may use this file
 in accordance with the commercial license agreement provided with the
 Software or, alternatively, in accordance with the terms contained in
 a written agreement between you and RedNaga.


 GNU General Public License Usage
 --------------------------------
 Alternatively, this file may be used under the terms of the GNU General
 Public License version 3.0 as published by the Free Software Foundation
 and appearing in the file LICENSE.GPL included in the packaging of this
 file. Please visit http://www.gnu.org/copyleft/gpl.html and review the
 information to ensure the GNU General Public License version 3.0
 requirements will be met.

 Modified by Ajin Abraham for MobSF
 Modifcations
 ------------
 * Return Data as Python dict to MobSF
 * Removed __init__.py contents
 * Removed get_distribution() that uses pkg_resources
 * Removed yara rule files and added compiled yarac rule file
"""

import json
import logging
import os
import shutil
import sys
import tempfile
import traceback
import yara
import zipfile

__title__ = 'apkid'
__version__ = '1.0.0'
__author__ = 'Caleb Fenton & Tim Strazzere'
__license__ = 'GPL & Commercial'
__copyright__ = 'Copyright (C) 2017 RedNaga'


LOGGING_LEVEL = logging.INFO
logging.basicConfig(level=LOGGING_LEVEL,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    stream=sys.stdout)

# Magic doesn't need to be perfect. Just used to filter likely scannable files.
ZIP_MAGIC = ['PK\x03\x04', 'PK\x05\x06', 'PK\x07\x08']
DEX_MAGIC = ['dex\n', 'dey\n']
ELF_MAGIC = ['\x7fELF']
AXML_MAGIC = []  # TODO


def get_file_type(file_path):
    # Don't scan links
    if not os.path.isfile(file_path):
        return 'invalid'
    with open(file_path, 'rb') as f:
        magic = f.read(4)
    if magic in ZIP_MAGIC:
        return 'zip'
    elif magic in DEX_MAGIC:
        return 'dex'
    elif magic in ELF_MAGIC:
        return 'elf'
    elif magic in AXML_MAGIC:
        return 'axml'
    return 'invalid'


def collect_files(input):
    if os.path.isfile(input):
        file_type = get_file_type(input)
        if file_type != 'invalid':
            yield (file_type, input)
    else:
        for root, _, filenames in os.walk(input):
            for filename in filenames:
                filepath = os.path.join(root, filename)
                file_type = get_file_type(filepath)
                if file_type != 'invalid':
                    yield (file_type, filepath)


def get_rules():
    rules_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'rules/rules.yarc')
    return yara.load(rules_path)


def build_match_dict(matches):
    results = {}
    for match in matches:
        tags = ', '.join(sorted(match.tags))
        value = match.meta.get('description', match)
        if tags in results:
            if value not in results[tags]:
                results[tags].append(value)
        else:
            results[tags] = [value]
    return results


def print_matches(key_path, match_dict):
    ''' example matches dict
    [{
      'tags': ['foo', 'bar'],
      'matches': True,
      'namespace': 'default',
      'rule': 'my_rule',
      'meta': {},
      'strings': [(81L, '$a', 'abc'), (141L, '$b', 'def')]
    }]
    '''
    print("[*] {}".format(key_path))
    for tags in sorted(match_dict):
        values = ', '.join(sorted(match_dict[tags]))
        print(" |-> {} : {}".format(tags, values))


def is_target_member(name):
    if name.startswith('classes') or name.startswith('AndroidManifest.xml') or name.startswith(
            'lib/'):
        return True
    return False


def do_yara(file_path, rules, timeout):
    matches = rules.match(file_path, timeout=timeout)
    return build_match_dict(matches)


def scan_apk(apk_path, rules, timeout, output_json):
    td = None
    results = {}
    try:
        zf = zipfile.ZipFile(apk_path, 'r')
        target_members = filter(lambda n: is_target_member(n), zf.namelist())
        td = tempfile.mkdtemp()
        zf.extractall(td, members=target_members)
        zf.close()
        for file_type, file_path in collect_files(td):
            entry_name = file_path.replace('{}/'.format(td), '')
            key_path = '{}!{}'.format(apk_path, entry_name)
            match_dict = do_yara(file_path, rules, timeout)
            if len(match_dict) > 0:
                results[key_path] = match_dict
                if not output_json:
                    print_matches(key_path, match_dict)
    except Exception as e:
        tb = traceback.format_exc()
        logging.error("error extracting {}: {}\n{}".format(apk_path, e, tb))

    if td: shutil.rmtree(td)
    return results


def get_json_output(results):
    output = {
        'apkid_version': __version__,
        'files': [],
    }
    for filename in results:
        result = {
            'filename': filename,
            'results': results[filename],
        }
        output['files'].append(result)
    return output


def print_json_results(results):
    output = get_json_output(results)
    print(json.dumps(output))



def scan(input, timeout, output_json):
    rules = get_rules()
    results = {}
    for file_type, file_path in collect_files(input):
        try:
            match_dict = do_yara(file_path, rules, timeout)
            if len(match_dict) > 0:
                results[file_path] = match_dict
                if not output_json:
                    print_matches(file_path, match_dict)
            if 'zip' == file_type:
                apk_matches = scan_apk(file_path, rules, timeout, output_json)
                results.update(apk_matches)
        except yara.Error as e:
            logging.error("error scanning: {}".format(e))
    if output_json:
        return get_json_output(results)


def scan_singly(input, timeout, output_dir):
    rules = get_rules()
    for file_type, file_path in collect_files(input):
        results = {}
        filename = os.path.basename(file_path)
        out_file = os.path.join(output_dir, filename)
        if os.path.exists(out_file):
            continue
        print("Processing: {}".format(file_path))
        try:
            match_dict = do_yara(file_path, rules, timeout)
            if len(match_dict) > 0:
                results[file_path] = match_dict
            if 'zip' == file_type:
                apk_matches = scan_apk(file_path, rules, timeout, True)
                results.update(apk_matches)
            if len(results) > 0:
                if not os.path.exists(output_dir):
                    os.makedirs(output_dir)
                with open(out_file, 'w') as f:
                    f.write(json.dumps(results))
                print("Finished: {}".format(file_path))
        except yara.Error as e:
            logging.error("error scanning: {}".format(e))
