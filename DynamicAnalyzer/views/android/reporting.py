# -*- coding: utf_8 -*-
"""Core Functions of Android Dynamic Analysis."""
import logging
import ntpath
import os
import io
import re
import sqlite3 as sq

from django.conf import settings
from django.shortcuts import render
from django.template.defaulttags import register
from django.utils.html import escape


from DynamicAnalyzer.views.android.analysis import (api_analysis, download,
                                                    run_analysis)

from MobSF.utils import (print_n_send_error_response,
                         python_list)

from StaticAnalyzer.models import StaticAnalyzerAndroid

logger = logging.getLogger(__name__)


@register.filter
def key(d, key_name):
    """To get dict element by key name in template."""
    return d.get(key_name)


def report(request):
    """Dynamic Analysis Report Generation."""
    logger.info('Dynamic Analysis Report Generation')
    try:
        if request.method == 'GET':
            md5_hash = request.GET['md5']
            package = request.GET['pkg']
            if re.findall(r';|\$\(|\|\||&&', package):
                return print_n_send_error_response(request,
                                                   'Possible RCE Attack')
            if re.match('^[0-9a-f]{32}$', md5_hash):
                app_dir = os.path.join(
                    settings.UPLD_DIR, md5_hash + '/')  # APP DIRECTORY
                download_dir = settings.DWD_DIR
                droidmon_api_loc = os.path.join(app_dir, 'x_logcat.txt')
                api_analysis_result = api_analysis(package, droidmon_api_loc)
                analysis_result = run_analysis(app_dir, md5_hash, package)
                download(md5_hash, download_dir, app_dir, package)
                # Only After Download Process is Done
                imgs = []
                act_imgs = []
                act = {}
                expact_imgs = []
                exp_act = {}
                if os.path.exists(os.path.join(
                        download_dir,
                        md5_hash + '-screenshots-apk/')):
                    try:
                        imp_path = os.path.join(
                            download_dir, md5_hash + '-screenshots-apk/')
                        for img in os.listdir(imp_path):
                            if img.endswith('.png'):
                                if img.startswith('act'):
                                    act_imgs.append(img)
                                elif img.startswith('expact'):
                                    expact_imgs.append(img)
                                else:
                                    imgs.append(img)
                        sadb = StaticAnalyzerAndroid.objects.filter(
                            MD5=md5_hash)
                        if sadb.exists():
                            logger.info(
                                '\nFetching Exported Activity'
                                ' & Activity List from DB')
                            exported_act = python_list(
                                sadb[0].EXPORTED_ACT)
                            act_desc = python_list(
                                sadb[0].ACTIVITIES)
                            if act_imgs:
                                if len(act_imgs) == len(act_desc):
                                    act = dict(list(zip(act_imgs, act_desc)))
                            if expact_imgs:
                                if len(expact_imgs) == len(exported_act):
                                    exp_act = dict(
                                        list(zip(expact_imgs, exported_act)))
                        else:
                            logger.warning('Entry does not exists in the DB.')
                    except Exception:
                        logger.exception('Screenshot Sorting')
                context = {'md5': md5_hash,
                           'emails': analysis_result['emails'],
                           'urls': analysis_result['urls'],
                           'domains': analysis_result['domains'],
                           'clipboard': analysis_result['clipboard'],
                           'http': analysis_result['web_data'],
                           'xml': analysis_result['xmlfiles'],
                           'sqlite': analysis_result['sqlite_db'],
                           'others': analysis_result['other_files'],
                           'imgs': imgs,
                           'acttest': act,
                           'expacttest': exp_act,
                           'net': api_analysis_result['api_net'],
                           'base64': api_analysis_result['api_base64'],
                           'crypto': api_analysis_result['api_crypto'],
                           'fileio': api_analysis_result['api_fileio'],
                           'binder': api_analysis_result['api_binder'],
                           'divinfo': api_analysis_result['api_deviceinfo'],
                           'cntval': api_analysis_result['api_cntvl'],
                           'sms': api_analysis_result['api_sms'],
                           'sysprop': api_analysis_result['api_sysprop'],
                           'dexload': api_analysis_result['api_dexloader'],
                           'reflect': api_analysis_result['api_reflect'],
                           'sysman': api_analysis_result['api_acntmnger'],
                           'process': api_analysis_result['api_cmd'],
                           'pkg': package,
                           'title': 'Dynamic Analysis'}
                template = 'dynamic_analysis/android/result.html'
                return render(request, template, context)
            else:
                return print_n_send_error_response(request,
                                                   'Invalid Scan Hash')
        else:
            return print_n_send_error_response(request,
                                               'Only GET allowed')
    except Exception:
        logger.exception('Dynamic Analysis Report Generation')
        err = 'Error Geneating Dynamic Analysis Report'
        return print_n_send_error_response(request, err)


def handle_sqlite(sfile):
    """Sqlite Dump - Readable Text."""
    logger.info('SQLite DB Extraction')
    try:
        data = ''
        con = sq.connect(sfile)
        cur = con.cursor()
        cur.execute('SELECT name FROM sqlite_master WHERE type=\'table\';')
        tables = cur.fetchall()
        for table in tables:
            data += ('\nTABLE: {}'
                     ' \n==============='
                     '==================='
                     '===================\n'.format(table[0]))
            cur.execute('PRAGMA table_info(\'%s\')' % table)
            rows = cur.fetchall()
            head = ''
            for sq_row in rows:
                elm_data = sq_row[1]
                head += elm_data + ' | '
            data += ('{} \n================'
                     '============================'
                     '=========================\n'.format(head))
            cur.execute('SELECT * FROM \'%s\'' % table)
            rows = cur.fetchall()
            for sq_row in rows:
                dat = ''
                for each_row in sq_row:
                    dat += str(each_row) + ' | '
                data += dat + '\n'
        return data
    except Exception:
        logger.exception('SQLite DB Extraction')


def view(request):
    """View File."""
    logger.info('Viewing File')
    try:
        typ = ''
        fil = ''
        rtyp = ''
        dat = ''
        if re.match('^[0-9a-f]{32}$', request.GET['md5']):
            fil = request.GET['file']
            md5_hash = request.GET['md5']
            typ = request.GET['type']
            src = os.path.join(
                settings.UPLD_DIR,
                md5_hash + '/DYNAMIC_DeviceData/')
            sfile = os.path.join(src, fil)
            # Prevent Directory Traversal Attacks
            if (('../' in fil)
                or ('%2e%2e' in fil)
                or ('..' in fil)
                    or ('%252e' in fil)):
                err = 'Path Traversal Attack Detected'
                return print_n_send_error_response(request, err)
            else:
                with io.open(sfile, mode='r', encoding='ISO-8859-1') as flip:
                    dat = flip.read()
                if (fil.endswith('.xml')) and (typ == 'xml'):
                    rtyp = 'xml'
                elif typ == 'db':
                    dat = handle_sqlite(sfile)
                    rtyp = 'asciidoc'
                elif typ == 'others':
                    rtyp = 'asciidoc'
                else:
                    err = 'File Type not supported'
                    return print_n_send_error_response(request, err)
                context = {'title': escape(ntpath.basename(fil)),
                           'file': escape(ntpath.basename(fil)),
                           'dat': dat,
                           'type': rtyp}
                template = 'general/view.html'
                return render(request, template, context)
        else:
            return print_n_send_error_response(request, 'Invalid Scan Hash')
    except Exception:
        logger.exception('Viewing File')
        return print_n_send_error_response(request, 'ERROR Viewing File')
