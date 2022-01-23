# -*- coding: utf_8 -*-
"""
Shared Functions.

Module providing the shared functions for iOS and Android
"""
import io
import hashlib
import logging
import platform
import re
import shutil
import subprocess
import zipfile
from urllib.parse import urlparse
from pathlib import Path

import requests

from django.utils import timezone
from django.utils.html import escape

from mobsf.MobSF import settings
from mobsf.MobSF.utils import (
    is_md5,
    print_n_send_error_response,
    upstream_proxy,
)
from mobsf.StaticAnalyzer.models import RecentScansDB
from mobsf.StaticAnalyzer.views.comparer import generic_compare

logger = logging.getLogger(__name__)


def hash_gen(app_path) -> tuple:
    """Generate and return sha1 and sha256 as a tuple."""
    try:
        logger.info('Generating Hashes')
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        block_size = 65536
        with io.open(app_path, mode='rb') as afile:
            buf = afile.read(block_size)
            while buf:
                sha1.update(buf)
                sha256.update(buf)
                buf = afile.read(block_size)
        sha1val = sha1.hexdigest()
        sha256val = sha256.hexdigest()
        return sha1val, sha256val
    except Exception:
        logger.exception('Generating Hashes')


def unzip(app_path, ext_path):
    logger.info('Unzipping')
    try:
        files = []
        with zipfile.ZipFile(app_path, 'r') as zipptr:
            for fileinfo in zipptr.infolist():
                filename = fileinfo.filename
                if not isinstance(filename, str):
                    filename = str(
                        filename, encoding='utf-8', errors='replace')
                files.append(filename)
                zipptr.extract(filename, ext_path)
        return files
    except Exception:
        logger.exception('Unzipping Error')
        if platform.system() == 'Windows':
            logger.info('Not yet Implemented.')
        else:
            logger.info('Using the Default OS Unzip Utility.')
            try:
                unzip_b = shutil.which('unzip')
                subprocess.call(
                    [unzip_b, '-o', '-q', app_path, '-d', ext_path])
                dat = subprocess.check_output([unzip_b, '-qq', '-l', app_path])
                dat = dat.decode('utf-8').split('\n')
                files_det = ['Length   Date   Time   Name']
                files_det = files_det + dat
                return files_det
            except Exception:
                logger.exception('Unzipping Error')


def url_n_email_extract(dat, relative_path):
    """Extract URLs and Emails from Source Code."""
    urls = []
    emails = []
    urllist = []
    url_n_file = []
    email_n_file = []
    # URLs Extraction My Custom regex
    pattern = re.compile(
        (
            r'((?:https?://|s?ftps?://|'
            r'file://|javascript:|data:|www\d{0,3}[.])'
            r'[\w().=/;,#:@?&~*+!$%\'{}-]+)'
        ),
        re.UNICODE)
    urllist = re.findall(pattern, dat)
    uflag = 0
    for url in urllist:
        if url not in urls:
            urls.append(url)
            uflag = 1
    if uflag == 1:
        url_n_file.append(
            {'urls': urls, 'path': escape(relative_path)})

    # Email Extraction Regex
    regex = re.compile(r'[\w.-]{1,20}@[\w-]{1,20}\.[\w]{2,10}')
    eflag = 0
    for email in regex.findall(dat.lower()):
        if (email not in emails) and (not email.startswith('//')):
            emails.append(email)
            eflag = 1
    if eflag == 1:
        email_n_file.append(
            {'emails': emails, 'path': escape(relative_path)})
    return urllist, url_n_file, email_n_file


# This is just the first sanity check that triggers generic_compare
def compare_apps(request, hash1: str, hash2: str, api=False):
    if hash1 == hash2:
        error_msg = 'Results with same hash cannot be compared'
        return print_n_send_error_response(request, error_msg, api)
    # Second Validation for REST API
    if not (is_md5(hash1) and is_md5(hash2)):
        error_msg = 'Invalid hashes'
        return print_n_send_error_response(request, error_msg, api)
    logger.info(
        'Starting App compare for %s and %s', hash1, hash2)
    return generic_compare(request, hash1, hash2, api)


def get_avg_cvss(findings):
    # Average CVSS Score
    cvss_scores = []
    avg_cvss = 0
    for finding in findings.values():
        find = finding.get('metadata')
        if not find:
            # Hack to support iOS Binary Scan Results
            find = finding
        if find.get('cvss'):
            if find['cvss'] != 0:
                cvss_scores.append(find['cvss'])
    if cvss_scores:
        avg_cvss = round(sum(cvss_scores) / len(cvss_scores), 1)
    if not getattr(settings, 'CVSS_SCORE_ENABLED', False):
        avg_cvss = None
    return avg_cvss


def update_scan_timestamp(scan_hash):
    # Update the last scan time.
    tms = timezone.now()
    RecentScansDB.objects.filter(MD5=scan_hash).update(TIMESTAMP=tms)


def open_firebase(url):
    # Detect Open Firebase Database
    try:
        purl = urlparse(url)
        base_url = '{}://{}/.json'.format(purl.scheme, purl.netloc)
        proxies, verify = upstream_proxy('https')
        headers = {
            'User-Agent': ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1)'
                           ' AppleWebKit/537.36 (KHTML, like Gecko) '
                           'Chrome/39.0.2171.95 Safari/537.36')}
        resp = requests.get(base_url, headers=headers,
                            proxies=proxies, verify=verify)
        if resp.status_code == 200:
            return base_url, True
    except Exception:
        logger.warning('Open Firebase DB detection failed.')
    return url, False


def firebase_analysis(urls):
    # Detect Firebase URL
    firebase_db = []
    logger.info('Detecting Firebase URL(s)')
    for url in urls:
        if 'firebaseio.com' in url:
            returl, is_open = open_firebase(url)
            fbdic = {'url': returl, 'open': is_open}
            if fbdic not in firebase_db:
                firebase_db.append(fbdic)
    return firebase_db


def find_java_source_folder(base_folder: Path):
    # Find the correct java/kotlin source folder for APK/source zip
    # Returns a Tuple of - (SRC_PATH, SRC_TYPE, SRC_SYNTAX)
    return next(p for p in [(base_folder / 'java_source',
                             'java', '*.java'),
                            (base_folder / 'app' / 'src' / 'main' / 'java',
                             'java', '*.java'),
                            (base_folder / 'app' / 'src' / 'main' / 'kotlin',
                             'kotlin', '*.kt'),
                            (base_folder / 'src',
                             'java', '*.java')]
                if p[0].exists())


def is_secret(inp):
    """Check if captures string is a possible secret."""
    inp = inp.lower()
    iden = (
        'api"', 'key"', 'api_', 'key_', 'secret"',
        'password"', 'aws', 'gcp', 's3_', '_s3', 'secret_',
        'token"', 'username"', 'user_name"', 'user"',
        'bearer', 'jwt', 'certificate"', 'credential',
        'azure', 'webhook', 'twilio_', 'bitcoin',
        '_auth', 'firebase', 'oauth', 'authorization',
        'private', 'pwd', 'session', 'token_',
    )
    not_string = (
        'label_', 'text', 'hint', 'msg_', 'create_',
        'message', 'new', 'confirm', 'activity_',
        'forgot', 'dashboard_', 'current_', 'signup',
        'sign_in', 'signin', 'title_', 'welcome_',
        'change_', 'this_', 'the_', 'placeholder',
        'invalid_', 'btn_', 'action_', 'prompt_',
        'lable', 'hide_', 'old', 'update', 'error',
        'empty', 'txt_', 'lbl_',
    )
    not_str = any(i in inp for i in not_string)
    return any(i in inp for i in iden) and not not_str
