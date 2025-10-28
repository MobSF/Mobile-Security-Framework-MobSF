"""Perform Analysis on Dynamic Analysis Data."""
import io
import logging
import os
import shutil
from json import load
from pathlib import Path

from django.conf import settings

from mobsf.MobSF.utils import (
    is_file_exists,
    python_list,
)
from mobsf.DynamicAnalyzer.views.common.shared import (
    extract_urls_domains_emails,
    get_app_files,
)
from mobsf.DynamicAnalyzer.tools.webproxy import get_traffic
from mobsf.DynamicAnalyzer.tools.reporting import (
    build_dast_report as generate_dast_report,
)
from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid


logger = logging.getLogger(__name__)


def run_analysis(apk_dir, md5_hash, package):
    """Run Dynamic File Analysis."""
    analysis_result = {}
    logger.info('Dynamic File Analysis')
    domains = {}
    clipboard = []
    # Collect Log data
    data = get_log_data(apk_dir, package)
    clip = Path(apk_dir) / 'mobsf_app_clipboard.txt'
    if clip.exists():
        clipboard = clip.read_text('utf-8', 'ignore').split('\n')
    else:
        # For Xposed
        clip_tag = 'I/CLIPDUMP-INFO-LOG'
        clip_tag2 = 'I CLIPDUMP-INFO-LOG'
        # Collect Clipboard
        for log_line in data['logcat']:
            if clip_tag in log_line:
                clipboard.append(
                    log_line.replace(clip_tag, 'Process ID '))
            if clip_tag2 in log_line:
                log_line = log_line.split(clip_tag2)[1]
                clipboard.append(log_line)
    urls, domains, emails = extract_urls_domains_emails(
        md5_hash,
        data['traffic'].lower())
    # Tar dump and fetch files
    all_files = get_app_files(apk_dir, package)
    analysis_result['urls'] = urls
    analysis_result['domains'] = domains
    analysis_result['emails'] = list(emails)
    analysis_result['clipboard'] = clipboard
    analysis_result['xml'] = all_files['xml']
    analysis_result['sqlite'] = all_files['sqlite']
    analysis_result['other_files'] = all_files['others']
    analysis_result['tls_tests'] = get_tls_logs(apk_dir, md5_hash)
    analysis_result['dast'] = generate_dast_report(data['traffic'])
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
    web_data = get_traffic(package)
    traffic_parts = [web_data]
    logcat = os.path.join(apk_dir, 'logcat.txt')
    xlogcat = os.path.join(apk_dir, 'x_logcat.txt')
    apimon = os.path.join(apk_dir, 'mobsf_api_monitor.txt')
    fd_logs = os.path.join(apk_dir, 'mobsf_frida_out.txt')
    if is_file_exists(logcat):
        with io.open(logcat,  # lgtm [py/path-injection]
                     mode='r',
                     encoding='utf8',
                     errors='ignore') as flip:
            logcat_data = flip.readlines()
            traffic_parts.append(''.join(logcat_data))
    if is_file_exists(xlogcat):
        with io.open(xlogcat,  # lgtm [py/path-injection]
                     mode='r',
                     encoding='utf8',
                     errors='ignore') as flip:
            droidmon_data = flip.read()
            traffic_parts.append(droidmon_data)
    if is_file_exists(apimon):
        with io.open(apimon,  # lgtm [py/path-injection]
                     mode='r',
                     encoding='utf8',
                     errors='ignore') as flip:
            apimon_data = flip.read()
            traffic_parts.append(apimon_data)
    if is_file_exists(fd_logs):
        with io.open(fd_logs,  # lgtm [py/path-injection]
                     mode='r',
                     encoding='utf8',
                     errors='ignore') as flip:
            frida_logs = flip.read()
            traffic_parts.append(frida_logs)
    traffic = ''.join(part for part in traffic_parts if part)
    return {'logcat': logcat_data,
            'traffic': traffic}


def generate_download(apk_dir, md5_hash, download_dir, package):
    """Generating Downloads."""
    logger.info('Generating Downloads')
    try:
        logcat = os.path.join(apk_dir, 'logcat.txt')
        xlogcat = os.path.join(apk_dir, 'x_logcat.txt')
        apimon = os.path.join(apk_dir, 'mobsf_api_monitor.txt')
        fd_logs = os.path.join(apk_dir, 'mobsf_frida_out.txt')
        dumpsys = os.path.join(apk_dir, 'dump.txt')
        sshot = os.path.join(apk_dir, 'screenshots-apk/')
        star = os.path.join(apk_dir, package + '.tar')

        dlogcat = os.path.join(download_dir, md5_hash + '-logcat.txt')
        dxlogcat = os.path.join(download_dir, md5_hash + '-x_logcat.txt')
        dapimon = os.path.join(download_dir, md5_hash + '-api_monitor.txt')
        dfd_logs = os.path.join(download_dir, md5_hash + '-frida_out.txt')
        ddumpsys = os.path.join(download_dir, md5_hash + '-dump.txt')
        dsshot = os.path.join(download_dir, md5_hash + '-screenshots-apk/')
        dweb = os.path.join(download_dir, md5_hash + '-web_traffic.txt')
        dstar = os.path.join(download_dir, md5_hash + '-app_data.tar')
        dmitm = os.path.join(download_dir, md5_hash + '-mitmproxy.mitm')

        # Delete existing data
        dellist = [dlogcat, dxlogcat, dapimon,
                   dfd_logs, ddumpsys, dsshot,
                   dweb, dstar, dmitm]
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
            shutil.copytree(sshot, dsshot, dirs_exist_ok=True)
        except Exception:
            pass
        aggregated_traffic = get_traffic(package)
        if aggregated_traffic:
            with open(dweb, 'w', encoding='utf-8') as dest:
                dest.write(aggregated_traffic)
        mitm_capture = Path(settings.DAST_CAPTURE_DIR) / f'{package}.mitm'
        if mitm_capture.exists():
            shutil.copyfile(mitm_capture, dmitm)
        if is_file_exists(star):
            shutil.copyfile(star, dstar)
    except Exception:
        logger.exception('Generating Downloads')


