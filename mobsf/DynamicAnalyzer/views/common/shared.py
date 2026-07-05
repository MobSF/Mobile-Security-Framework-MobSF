# -*- coding: utf_8 -*-
"""Common helpers for Android and iOS Dynamic Analysis."""
import logging
import os
import re
import errno
import json
import tarfile
import shutil
from pathlib import Path

from django.http import HttpResponse

from mobsf.MalwareAnalyzer.views.MalwareDomainCheck import (
    MalwareDomainCheck,
)
from mobsf.MobSF.exceptions import PathTraversalError
from mobsf.MobSF.security import clean_filename, is_pipe_or_link
from mobsf.MobSF.utils import (
    EMAIL_REGEX,
    URL_REGEX,
)

logger = logging.getLogger(__name__)


def extract_urls_domains_emails(checksum, data):
    """Extract URLs, Domains and Emails."""
    # URL Extraction
    urls = re.findall(URL_REGEX, data)
    if urls:
        urls = list(set(urls))
    else:
        urls = []
    # Domain Extraction and Malware Check
    logger.info('Performing Malware check on extracted domains')
    # For domain extraction, use lowercased URLs
    domains = MalwareDomainCheck().scan(
        checksum,
        urls)
    # Email Extraction Regex
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


def onexc(func, path, exc_info):
    _, exc_value, _ = exc_info
    if exc_value.errno == errno.EACCES:  # Permission error
        try:
            os.chmod(path, 0o755)
            func(path)
        except Exception:
            pass
    elif exc_value.errno == errno.ENOTEMPTY:  # Directory not empty
        try:
            func(path)
        except Exception:
            pass
    else:
        raise


def untar_files(tar_loc, untar_dir):
    """Untar files."""
    logger.info('Extracting Tar files')
    try:
        # Extract Device Data
        if not tar_loc.exists():
            return False
        if untar_dir.exists():
            # fix for permission errors
            shutil.rmtree(untar_dir, onexc=onexc)
        else:
            os.makedirs(untar_dir)
        with tarfile.open(tar_loc.as_posix(), errorlevel=1) as tar:
            if hasattr(tarfile, 'data_filter'):
                # Python 3.12+ (PEP 706) / backported to 3.11.4, 3.10.12, 3.9.17.
                # Rejects symlinks outside destination, hardlinks, device files,
                # and absolute/traversal paths per-member before extraction.
                tar.extractall(
                    untar_dir,
                    members=safe_paths(tar),
                    filter='data')
            else:
                # Fallback for Python < 3.9.17 without the PEP 706 backport.
                # Manually reject symlinks and hardlinks, then use realpath
                # (not abspath) to verify the resolved path stays inside the
                # destination before extracting each member.
                safe_root = os.path.realpath(untar_dir)
                safe_members = []
                for member in safe_paths(tar):
                    if member.issym() or member.islnk():
                        logger.warning(
                            'Skipping link member in tar: %s', member.name)
                        continue
                    member_path = os.path.realpath(
                        os.path.join(safe_root, member.name))
                    if not (member_path.startswith(safe_root + os.sep)
                            or member_path == safe_root):
                        raise PathTraversalError(
                            'Attempted Path Traversal in Tar File')
                    safe_members.append(member)
                tar.extractall(untar_dir, members=iter(safe_members))
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
        content_type='application/json; charset=utf-8')


def invalid_params(api=False):
    """Standard response for invalid params."""
    msg = 'Invalid Parameters'
    logger.error(msg)
    data = {'status': 'failed', 'message': msg}
    if api:
        return data
    return send_response(data)
