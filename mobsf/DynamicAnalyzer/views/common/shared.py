# -*- coding: utf_8 -*-
"""Common helpers for Android and iOS Dynamic Analysis."""
import logging
import os
import re
import json
import tarfile
import shutil
from pathlib import Path

from django.http import HttpResponse

from mobsf.MalwareAnalyzer.views.MalwareDomainCheck import (
    MalwareDomainCheck,
)
from mobsf.MobSF.utils import (
    EMAIL_REGEX,
    URL_REGEX,
    clean_filename,
    is_pipe_or_link,
)

logger = logging.getLogger(__name__)


def extract_urls_domains_emails(checksum, data):
    """Extract URLs, Domains and Emails."""
    # URL Extraction
    urls = re.findall(URL_REGEX, data.lower())
    if urls:
        urls = list(set(urls))
    else:
        urls = []
    # Domain Extraction and Malware Check
    logger.info('Performing Malware check on extracted domains')
    domains = MalwareDomainCheck().scan(
        checksum,
        urls)
    # Email Etraction Regex
    emails = set()
    for email in EMAIL_REGEX.findall(data.lower()):
        if email.startswith('//'):
            continue
        if email.endswith('.png'):
            continue
        emails.add(email)
    return urls, domains, emails


def safe_paths(tar_meta):
    """Safe filenames in windows."""
    for fh in tar_meta:
        fh.name = clean_filename(fh.name)
        yield fh


def untar_files(tar_loc, untar_dir):
    """Untar files."""
    logger.info('Extracting Tar files')
    # Extract Device Data
    if not tar_loc.exists():
        return False
    if untar_dir.exists():
        # fix for permission errors
        shutil.rmtree(untar_dir)
    else:
        os.makedirs(untar_dir)
    try:
        with tarfile.open(tar_loc.as_posix(), errorlevel=1) as tar:

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
    except (FileExistsError, tarfile.ReadError):
        logger.warning('Failed to extract tar file')
    except Exception:
        logger.exception('Tar extraction failed')
    return True


def get_app_files(app_dir, tarname):
    """Get files from device."""
    logger.info('Getting app files')
    all_files = {'xml': [], 'sqlite': [], 'others': [], 'plist': []}
    appdir = Path(app_dir)
    tar_loc = appdir / f'{tarname}.tar'
    untar_dir = appdir / 'DYNAMIC_DeviceData'
    success = untar_files(tar_loc, untar_dir)
    if not success:
        return all_files
    # Do Static Analysis on Data from Device
    try:
        untar_dir = untar_dir.as_posix()
        for dir_name, _, files in os.walk(untar_dir):
            for jfile in files:
                file_path = os.path.join(untar_dir, dir_name, jfile)
                fileparam = file_path.replace(f'{untar_dir}/', '')
                if is_pipe_or_link(file_path):
                    continue
                if jfile == 'lib':
                    pass
                else:
                    if jfile.endswith('.xml'):
                        all_files['xml'].append(
                            {'type': 'xml', 'file': fileparam})
                    elif jfile.endswith('.plist'):
                        all_files['plist'].append(
                            {'type': 'plist', 'file': fileparam})
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


def send_response(data, api=False):
    """Return JSON Response."""
    if api:
        return data
    return HttpResponse(
        json.dumps(data),
        content_type='application/json')


def invalid_params(api=False):
    """Standard response for invalid params."""
    msg = 'Invalid Parameters'
    logger.error(msg)
    data = {'status': 'failed', 'message': msg}
    if api:
        return data
    return send_response(data)


def is_attack_pattern(user_input):
    """Check for attacks."""
    atk_pattern = re.compile(r';|\$\(|\|\||&&')
    stat = re.findall(atk_pattern, user_input)
    if stat:
        logger.error('Possible RCE attack detected')
    return stat
