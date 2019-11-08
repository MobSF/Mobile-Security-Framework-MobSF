# -*- coding: utf_8 -*-
"""Perform Analysis on Dynamic Analysis Data."""
import io
import logging
import os
import re
import shutil
import tarfile
from pathlib import Path

from MobSF.utils import (is_file_exists,
                         is_pipe_or_link,
                         python_list)

from StaticAnalyzer.models import StaticAnalyzerAndroid

from MalwareAnalyzer.views.domain_check import malware_check

logger = logging.getLogger(__name__)


def run_analysis(apk_dir, md5_hash, package):
    """Run Dynamic File Analysis."""
    analysis_result = {}
    logger.info('Dynamic File Analysis')
    domains = {}
    clipboard = []
    # Collect Log data
    datas = get_log_data(apk_dir, package)
    clip_tag = 'I/CLIPDUMP-INFO-LOG'
    clip_tag2 = 'I CLIPDUMP-INFO-LOG'
    # Collect Clipboard
    for log_line in datas['logcat']:
        if clip_tag in log_line:
            clipboard.append(log_line.replace(clip_tag, 'Process ID '))
        if clip_tag2 in log_line:
            log_line = log_line.split(clip_tag2)[1]
            clipboard.append(log_line)
    # URLs My Custom regex
    url_pattern = re.compile(
        r'((?:https?://|s?ftps?://|file://|'
        r'javascript:|data:|www\d{0,3}'
        r'[.])[\w().=/;,#:@?&~*+!$%\'{}-]+)', re.UNICODE)
    urls = re.findall(url_pattern, datas['traffic'].lower())
    if urls:
        urls = list(set(urls))
    else:
        urls = []
    # Domain Extraction and Malware Check
    logger.info('Performing Malware Check on extracted Domains')
    domains = malware_check(urls)

    # Email Etraction Regex
    emails = []
    regex = re.compile(r'[\w.-]+@[\w-]+\.[\w]{2,}')
    for email in regex.findall(datas['traffic'].lower()):
        if (email not in emails) and (not email.startswith('//')):
            emails.append(email)
    # Tar dump and fetch files
    all_files = get_app_files(apk_dir, md5_hash, package)
    analysis_result['urls'] = urls
    analysis_result['domains'] = domains
    analysis_result['emails'] = emails
    analysis_result['clipboard'] = clipboard
    analysis_result['xml'] = all_files['xml']
    analysis_result['sqlite'] = all_files['sqlite']
    analysis_result['other_files'] = all_files['others']
    return analysis_result


def get_screenshots(md5_hash, download_dir):
    """Get Screenshots."""
    # Only After Download Process is Done
    result = {}
    imgs = []
    act_imgs = []
    expact_imgs = []
    act = {}
    exp_act = {}
    try:
        screen_dir = os.path.join(download_dir,
                                  md5_hash + '-screenshots-apk/')
        sadb = StaticAnalyzerAndroid.objects.filter(MD5=md5_hash)
        if os.path.exists(screen_dir) and sadb.exists():
            for img in os.listdir(screen_dir):
                if img.endswith('.png'):
                    if img.startswith('act'):
                        act_imgs.append(img)
                    elif img.startswith('expact'):
                        expact_imgs.append(img)
                    else:
                        imgs.append(img)
            exported_act = python_list(sadb[0].EXPORTED_ACT)
            act_desc = python_list(sadb[0].ACTIVITIES)
            if act_imgs:
                if len(act_imgs) == len(act_desc):
                    act = dict(list(zip(act_imgs, act_desc)))
            if expact_imgs:
                if len(expact_imgs) == len(exported_act):
                    exp_act = dict(list(zip(expact_imgs, exported_act)))
    except Exception:
        logger.exception('Organising screenshots')
    result['screenshots'] = imgs
    result['activities'] = act
    result['exported_activities'] = exp_act
    return result


def get_log_data(apk_dir, package):
    """Get Data for analysis."""
    logcat_data = []
    droidmon_data = ''
    apimon_data = ''
    frida_logs = ''
    web_data = ''
    traffic = ''
    httptools = os.path.join(str(Path.home()), '.httptools')
    web = os.path.join(httptools, 'flows', package + '.flow.txt')
    logcat = os.path.join(apk_dir, 'logcat.txt')
    xlogcat = os.path.join(apk_dir, 'x_logcat.txt')
    apimon = os.path.join(apk_dir, 'mobsf_api_monitor.txt')
    fd_logs = os.path.join(apk_dir, 'mobsf_frida_out.txt')
    if is_file_exists(web):
        with io.open(web,
                     mode='r',
                     encoding='utf8',
                     errors='ignore') as flip:
            web_data = flip.read()
    if is_file_exists(logcat):
        with io.open(logcat,
                     mode='r',
                     encoding='utf8',
                     errors='ignore') as flip:
            logcat_data = flip.readlines()
            traffic = ''.join(logcat_data)
    if is_file_exists(xlogcat):
        with io.open(xlogcat,
                     mode='r',
                     encoding='utf8',
                     errors='ignore') as flip:
            droidmon_data = flip.read()
    if is_file_exists(apimon):
        with io.open(apimon,
                     mode='r',
                     encoding='utf8',
                     errors='ignore') as flip:
            apimon_data = flip.read()
    if is_file_exists(fd_logs):
        with io.open(fd_logs,
                     mode='r',
                     encoding='utf8',
                     errors='ignore') as flip:
            frida_logs = flip.read()
    traffic = (web_data + traffic + droidmon_data
               + apimon_data + frida_logs)
    return {'logcat': logcat_data,
            'traffic': traffic}


def get_app_files(apk_dir, md5_hash, package):
    """Get files from device."""
    logger.info('Getting app files')
    all_files = {'xml': [], 'sqlite': [], 'others': []}
    # Extract Device Data
    tar_loc = os.path.join(apk_dir, package + '.tar')
    untar_dir = os.path.join(apk_dir, 'DYNAMIC_DeviceData/')
    if not is_file_exists(tar_loc):
        return all_files
    if os.path.exists(untar_dir):
        # fix for permission errors
        shutil.rmtree(untar_dir)
    try:
        with tarfile.open(tar_loc, errorlevel=1) as tar:
            tar.extractall(untar_dir)
    except FileExistsError:
        pass
    except Exception:
        logger.exception('Tar extraction failed')
    # Do Static Analysis on Data from Device
    try:
        if not os.path.exists(untar_dir):
            os.makedirs(untar_dir)
        for dir_name, _, files in os.walk(untar_dir):
            for jfile in files:
                file_path = os.path.join(untar_dir, dir_name, jfile)
                fileparam = file_path.replace(untar_dir, '')
                if is_pipe_or_link(file_path):
                    continue
                if jfile == 'lib':
                    pass
                else:
                    if jfile.endswith('.xml'):
                        all_files['xml'].append(
                            {'type': 'xml', 'file': fileparam})
                    else:
                        with open(file_path,
                                  'r',
                                  encoding='ISO-8859-1') as flip:
                            file_cnt_sig = flip.read(6)
                        if file_cnt_sig == 'SQLite':
                            all_files['sqlite'].append(
                                {'type': 'db', 'file': fileparam})
                        elif not jfile.endswith('.DS_Store'):
                            all_files['others'].append(
                                {'type': 'others', 'file': fileparam})
    except Exception:
        logger.exception('Getting app files')
    return all_files


def generate_download(apk_dir, md5_hash, download_dir, package):
    """Generating Downloads."""
    logger.info('Generating Downloads')
    try:
        httptools = os.path.join(str(Path.home()), '.httptools')
        logcat = os.path.join(apk_dir, 'logcat.txt')
        xlogcat = os.path.join(apk_dir, 'x_logcat.txt')
        apimon = os.path.join(apk_dir, 'mobsf_api_monitor.txt')
        fd_logs = os.path.join(apk_dir, 'mobsf_frida_out.txt')
        dumpsys = os.path.join(apk_dir, 'dump.txt')
        sshot = os.path.join(apk_dir, 'screenshots-apk/')
        web = os.path.join(httptools, 'flows', package + '.flow.txt')
        star = os.path.join(apk_dir, package + '.tar')

        dlogcat = os.path.join(download_dir, md5_hash + '-logcat.txt')
        dxlogcat = os.path.join(download_dir, md5_hash + '-x_logcat.txt')
        dapimon = os.path.join(download_dir, md5_hash + '-api_monitor.txt')
        dfd_logs = os.path.join(download_dir, md5_hash + '-frida_out.txt')
        ddumpsys = os.path.join(download_dir, md5_hash + '-dump.txt')
        dsshot = os.path.join(download_dir, md5_hash + '-screenshots-apk/')
        dweb = os.path.join(download_dir, md5_hash + '-web_traffic.txt')
        dstar = os.path.join(download_dir, md5_hash + '-app_data.tar')

        # Delete existing data
        dellist = [dlogcat, dxlogcat, dapimon,
                   dfd_logs, ddumpsys, dsshot,
                   dweb, dstar]
        for item in dellist:
            if os.path.isdir(item):
                shutil.rmtree(item)
            elif os.path.isfile(item):
                os.remove(item)
        # Copy new data
        shutil.copyfile(logcat, dlogcat)
        shutil.copyfile(dumpsys, ddumpsys)
        if is_file_exists(xlogcat):
            shutil.copyfile(xlogcat, dxlogcat)
        if is_file_exists(apimon):
            shutil.copyfile(apimon, dapimon)
        if is_file_exists(fd_logs):
            shutil.copyfile(fd_logs, dfd_logs)
        try:
            shutil.copytree(sshot, dsshot)
        except Exception:
            pass
        if is_file_exists(web):
            shutil.copyfile(web, dweb)
        if is_file_exists(star):
            shutil.copyfile(star, dstar)
    except Exception:
        logger.exception('Generating Downloads')
