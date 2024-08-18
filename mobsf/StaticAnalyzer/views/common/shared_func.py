# -*- coding: utf_8 -*-
"""
Shared Functions.

Module providing the shared functions for iOS and Android
"""
import io
import hashlib
import logging
import os
import platform
import re
import shutil
import subprocess
import zipfile
from urllib.parse import urlparse
from pathlib import Path

import requests

import arpy

from django.utils.html import escape
from django.http import HttpResponseRedirect

from mobsf.MobSF import settings
from mobsf.MobSF.utils import (
    EMAIL_REGEX,
    STRINGS_REGEX,
    URL_REGEX,
    append_scan_status,
    is_md5,
    is_path_traversal,
    is_safe_path,
    print_n_send_error_response,
    upstream_proxy,
    valid_host,
)
from mobsf.MobSF.views.scanning import (
    add_to_recent_scan,
    handle_uploaded_file,
)
from mobsf.StaticAnalyzer.views.comparer import (
    generic_compare,
)
from mobsf.StaticAnalyzer.views.common.entropy import (
    get_entropies,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.MobSF.views.authorization import (
    Permissions,
    permission_required,
)


logger = logging.getLogger(__name__)


def hash_gen(checksum, app_path) -> tuple:
    """Generate and return sha1 and sha256 as a tuple."""
    try:
        msg = 'Generating Hashes'
        logger.info(msg)
        append_scan_status(checksum, msg)
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
    except Exception as exp:
        msg = 'Failed to generate Hashes'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))


def unzip(checksum, app_path, ext_path):
    msg = 'Unzipping'
    logger.info(msg)
    append_scan_status(checksum, msg)
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
    except Exception as exp:
        msg = 'Unzipping Error'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
        if platform.system() == 'Windows':
            msg = 'Unzipping Error. Not yet implemented in Windows'
            logger.warning(msg)
            append_scan_status(checksum, msg)
        else:
            msg = 'Unzipping Error. Trying with OS unzip utility'
            logger.info(msg)
            append_scan_status(checksum, msg)
            try:
                unzip_b = shutil.which('unzip')
                subprocess.call(
                    [unzip_b, '-o', '-q', app_path, '-d', ext_path])
                dat = subprocess.check_output([unzip_b, '-qq', '-l', app_path])
                dat = dat.decode('utf-8').split('\n')
                files_det = ['Length   Date   Time   Name']
                files_det = files_det + dat
                return files_det
            except Exception as exp:
                msg = 'Unzipping Error with OS unzip utility'
                logger.exception(msg)
                append_scan_status(checksum, msg, repr(exp))


def lipo_thin(checksum, src, dst):
    """Thin Fat binary."""
    new_src = None
    try:
        msg = 'Thinning Fat binary'
        logger.info(msg)
        append_scan_status(checksum, msg)
        lipo = shutil.which('lipo')
        out = Path(dst) / (Path(src).stem + '_thin.a')
        new_src = out.as_posix()
        archs = [
            'armv7', 'armv6', 'arm64', 'x86_64',
            'armv4t', 'armv5', 'armv6m', 'armv7f',
            'armv7s', 'armv7k', 'armv7m', 'armv7em',
            'arm64v8']
        for arch in archs:
            args = [
                lipo,
                src,
                '-thin',
                arch,
                '-output',
                new_src]
            out = subprocess.run(
                args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT)
            if out.returncode == 0:
                break
    except Exception as exp:
        msg = 'lipo Fat binary thinning failed'
        logger.warning(msg)
        append_scan_status(checksum, msg, repr(exp))
    return new_src


def ar_os(src, dst):
    out = ''
    """Extract AR using OS utility."""
    cur = os.getcwd()
    try:
        os.chdir(dst)
        out = subprocess.check_output(
            [shutil.which('ar'), 'x', src],
            stderr=subprocess.STDOUT)
    except Exception as exp:
        out = exp.output
    finally:
        os.chdir(cur)
    return out


def ar_extract(checksum, src, dst):
    """Extract AR archive."""
    msg = 'Extracting static library archive'
    logger.info(msg)
    append_scan_status(checksum, msg)
    try:
        ar = arpy.Archive(src)
        ar.read_all_headers()
        for a, val in ar.archived_files.items():
            # Handle archive slip attacks
            filtered = a.decode('utf-8', 'ignore')
            if is_path_traversal(filtered):
                msg = f'Zip slip detected. skipped extracting {filtered}'
                logger.warning(msg)
                append_scan_status(checksum, msg)
                continue
            out = Path(dst) / filtered
            out.write_bytes(val.read())
    except Exception:
        # Possibly dealing with Fat binary, needs Mac host
        msg = 'Failed to extract .a archive'
        logger.warning(msg)
        append_scan_status(checksum, msg)
        # Use os ar utility
        plat = platform.system()
        os_err = 'Possibly a Fat binary. Requires MacOS for Analysis'
        if plat == 'Windows':
            logger.warning(os_err)
            append_scan_status(checksum, os_err)
            return
        msg = 'Using OS ar utility to handle archive'
        logger.info(msg)
        append_scan_status(checksum, msg)
        exp = ar_os(src, dst)
        if len(exp) > 3 and plat == 'Linux':
            # Can't convert FAT binary in Linux
            logger.warning(os_err)
            append_scan_status(checksum, os_err)
            return
        if b'lipo(1)' in exp:
            msg = 'Fat binary archive identified'
            logger.info(msg)
            append_scan_status(checksum, msg)
            # Fat binary archive
            try:
                nw_src = lipo_thin(checksum, src, dst)
                if nw_src:
                    ar_os(nw_src, dst)
            except Exception as exp:
                msg = 'Failed to thin fat archive'
                logger.exception(msg)
                append_scan_status(checksum, msg, repr(exp))


def url_n_email_extract(dat, relative_path):
    """Extract URLs and Emails from Source Code."""
    urls = set()
    emails = set()
    urllist = []
    url_n_file = []
    email_n_file = []
    # URL Extraction
    urllist = URL_REGEX.findall(dat.lower())
    for url in urllist:
        urls.add(url)
    if urls:
        url_n_file.append({
            'urls': list(urls),
            'path': escape(relative_path)})

    # Email Extraction
    for email in EMAIL_REGEX.findall(dat.lower()):
        if not email.startswith('//'):
            emails.add(email)
    if emails:
        email_n_file.append({
            'emails': list(emails),
            'path': escape(relative_path)})
    return urllist, url_n_file, email_n_file


# This is just the first sanity check that triggers generic_compare
@login_required
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


def open_firebase(checksum, url):
    # Detect Open Firebase Database
    try:
        invalid = 'Invalid Firebase URL'
        if not valid_host(url):
            logger.warning(invalid)
            return url, False
        purl = urlparse(url)
        if not purl.netloc.endswith('firebaseio.com'):
            logger.warning(invalid)
            return url, False
        base_url = '{}://{}/.json'.format(purl.scheme, purl.netloc)
        proxies, verify = upstream_proxy('https')
        headers = {
            'User-Agent': ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1)'
                           ' AppleWebKit/537.36 (KHTML, like Gecko) '
                           'Chrome/39.0.2171.95 Safari/537.36')}
        resp = requests.get(base_url, headers=headers,
                            proxies=proxies, verify=verify,
                            allow_redirects=False)
        if resp.status_code == 200:
            return base_url, True
    except Exception as exp:
        msg = 'Open Firebase DB detection failed'
        logger.warning(msg)
        append_scan_status(checksum, msg, repr(exp))
    return url, False


def firebase_analysis(checksum, urls):
    # Detect Firebase URL
    firebase_db = []
    logger.info('Detecting Firebase URL(s)')
    for url in urls:
        if 'firebaseio.com' not in url:
            continue
        returl, is_open = open_firebase(checksum, url)
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


def is_secret_key(inp):
    """Check if the key in the key/value pair is interesting."""
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


def strings_and_entropies(checksum, src, exts):
    """Get Strings and Entropies."""
    msg = 'Extracting String values and entropies from Code'
    logger.info(msg)
    append_scan_status(checksum, msg)
    data = {
        'strings': set(),
        'secrets': set(),
    }
    try:
        if not src.exists():
            return data
        excludes = ('\\u0', 'com.google.')
        eslash = ('Ljava', 'Lkotlin', 'kotlin', 'android')
        for p in src.rglob('*'):
            if p.suffix not in exts or not p.exists():
                continue
            matches = STRINGS_REGEX.finditer(
                p.read_text(encoding='utf-8', errors='ignore'),
                re.MULTILINE)
            for match in matches:
                string = match.group()
                if len(string) < 4:
                    continue
                if any(i in string for i in excludes):
                    continue
                if any(i in string and '/' in string for i in eslash):
                    continue
                if not string[0].isalnum():
                    continue
                data['strings'].add(string)
        if data['strings']:
            data['secrets'] = get_entropies(data['strings'])
    except Exception as exp:
        msg = 'Failed to extract String values and entropies from Code'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
    return data


def get_symbols(symbols):
    all_symbols = []
    for i in symbols:
        for _, val in i.items():
            all_symbols.extend(val)
    return list(set(all_symbols))


@login_required
@permission_required(Permissions.SCAN)
def scan_library(request, checksum):
    """Scan a shared library or framework from path name."""
    try:
        libchecksum = None
        if not is_md5(checksum):
            return print_n_send_error_response(
                request,
                'Invalid MD5')
        relative_path = request.GET['library']
        lib_dir = Path(settings.UPLD_DIR) / checksum

        sfile = lib_dir / relative_path
        if not is_safe_path(lib_dir.as_posix(), sfile.as_posix()):
            msg = 'Path Traversal Detected!'
            return print_n_send_error_response(request, msg)
        ext = sfile.suffix
        if not ext and 'Frameworks' in relative_path:
            # Force Dylib on Frameworks
            ext = '.dylib'
        if not sfile.exists():
            msg = 'Library File not found'
            return print_n_send_error_response(request, msg)
        with open(sfile, 'rb') as f:
            libchecksum = handle_uploaded_file(f, ext)
        if ext in [f'.{i}' for i in settings.IOS_EXTS]:
            static_analyzer = 'static_analyzer_ios'
        elif ext == '.appx':
            # Not applicable, but still set it
            static_analyzer = 'windows_static_analyzer'
        elif ext in [f'.{i}' for i in settings.ANDROID_EXTS]:
            static_analyzer = 'static_analyzer'
        else:
            msg = 'Extension not supported'
            return print_n_send_error_response(request, msg)
        data = {
            'analyzer': static_analyzer,
            'status': 'success',
            'hash': libchecksum,
            'scan_type': ext.replace('.', ''),
            'file_name': sfile.name,
        }
        add_to_recent_scan(data)
        return HttpResponseRedirect(f'/{static_analyzer}/{libchecksum}/')
    except Exception:
        msg = 'Failed to perform Static Analysis of library'
        logger.exception(msg)
        return print_n_send_error_response(request, msg)
