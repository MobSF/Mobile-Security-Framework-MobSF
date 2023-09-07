"""Perform Analysis on Dynamic Analysis Data."""
import io
import logging
import os
import re
import shutil
import tarfile
from json import load
from pathlib import Path

from mobsf.MobSF.utils import (
    clean_filename,
    is_file_exists,
    is_pipe_or_link,
    python_list,
)
from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid
from mobsf.MalwareAnalyzer.views.MalwareDomainCheck import (
    MalwareDomainCheck,
)

logger = logging.getLogger(__name__)


def run_analysis(apk_dir, md5_hash, package):
    """Run Dynamic File Analysis."""
    analysis_result = {}
    logger.info('Dynamic File Analysis')
    domains = {}
    clipboard = []
    # Collect Log data
    data = get_log_data(apk_dir, package)
    clip_tag = 'I/CLIPDUMP-INFO-LOG'
    clip_tag2 = 'I CLIPDUMP-INFO-LOG'
    # Collect Clipboard
    for log_line in data['logcat']:
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
    urls = re.findall(url_pattern, data['traffic'].lower())
    if urls:
        urls = list(set(urls))
    else:
        urls = []
    # Domain Extraction and Malware Check
    logger.info('Performing Malware Check on extracted Domains')
    domains = MalwareDomainCheck().scan(urls)

    # Email Etraction Regex
    emails = []
    regex = re.compile(r'[\w.-]{1,20}@[\w-]{1,20}\.[\w]{2,10}')
    for email in regex.findall(data['traffic'].lower()):
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
    analysis_result['tls_tests'] = get_tls_logs(apk_dir, md5_hash)
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
        if os.path.exists(screen_dir):
            for img in os.listdir(screen_dir):
                if img.endswith('.png'):
                    if img.startswith('act'):
                        act_imgs.append(img)
                    elif img.startswith('expact'):
                        expact_imgs.append(img)
                    else:
                        imgs.append(img)
            try:
                sadb = StaticAnalyzerAndroid.objects.get(MD5=md5_hash)
                exported_act = python_list(sadb.EXPORTED_ACTIVITIES)
                act_desc = python_list(sadb.ACTIVITIES)
                if act_imgs:
                    if len(act_imgs) == len(act_desc):
                        act = dict(list(zip(act_imgs, act_desc)))
                if expact_imgs:
                    if len(expact_imgs) == len(exported_act):
                        exp_act = dict(list(zip(expact_imgs, exported_act)))
            except Exception:
                pass
                # On device only APK don't have this information available.
    except Exception:
        logger.exception('Organising screenshots')
    result['screenshots'] = imgs
    result['activities'] = act
    result['exported_activities'] = exp_act
    return result


def get_tls_logs(apk_dir, md5_hash):
    """Get TLS/SSL test logs."""
    out = Path(apk_dir) / 'mobsf_tls_tests.json'
    if not out.exists():
        return None
    with out.open(encoding='utf-8') as src:
        return load(src)


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
        with io.open(logcat,  # lgtm [py/path-injection]
                     mode='r',
                     encoding='utf8',
                     errors='ignore') as flip:
            logcat_data = flip.readlines()
            traffic = ''.join(logcat_data)
    if is_file_exists(xlogcat):
        with io.open(xlogcat,  # lgtm [py/path-injection]
                     mode='r',
                     encoding='utf8',
                     errors='ignore') as flip:
            droidmon_data = flip.read()
    if is_file_exists(apimon):
        with io.open(apimon,  # lgtm [py/path-injection]
                     mode='r',
                     encoding='utf8',
                     errors='ignore') as flip:
            apimon_data = flip.read()
    if is_file_exists(fd_logs):
        with io.open(fd_logs,  # lgtm [py/path-injection]
                     mode='r',
                     encoding='utf8',
                     errors='ignore') as flip:
            frida_logs = flip.read()
    traffic = (web_data + traffic + droidmon_data
               + apimon_data + frida_logs)
    return {'logcat': logcat_data,
            'traffic': traffic}


def safe_paths(tar_meta):
    """Safe filenames in windows."""
    for fh in tar_meta:
        fh.name = clean_filename(fh.name)
        yield fh


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

            def is_within_directory(directory, target):
                abs_directory = os.path.abspath(directory)
                abs_target = os.path.abspath(target)
                prefix = os.path.commonprefix([abs_directory, abs_target])
                return prefix == abs_directory

            def safe_extract(tar, path='.',
                             members=None,
                             *,
                             numeric_owner=False):
                for member in tar.getmembers():
                    member_path = os.path.join(path, member.name)
                    if not is_within_directory(path, member_path):
                        raise Exception('Attempted Path Traversal in Tar File')
                tar.extractall(path, members, numeric_owner=numeric_owner)

            safe_extract(tar, untar_dir, members=safe_paths(tar))
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
                        with open(file_path,  # lgtm [py/path-injection]
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
