# -*- coding: utf_8 -*-
"""Module for strings-method for java."""
import logging
import os
from pathlib import Path

from androguard.core.bytecodes import apk

from mobsf.StaticAnalyzer.views.common.shared_func import (
    is_secret_key,
    strings_and_entropies,
    url_n_email_extract,
)
from mobsf.StaticAnalyzer.views.common.entropy import (
    get_entropies,
)
from mobsf.MobSF.utils import (
    get_android_src_dir,
)

logger = logging.getLogger(__name__)
logging.getLogger('androguard').setLevel(logging.ERROR)


def strings_from_so(elf_strings):
    """Extract Strings from so file."""
    so_strings = []
    so_secrets = []
    so_urls = []
    so_urls_nf = []
    so_emails_nf = []
    try:
        for solib in elf_strings:
            for so, str_list in solib.items():
                so_strings.extend(str_list)
                # extract url, email
                so_str = ' '.join(str_list)
                su, suf, sem = url_n_email_extract(
                    so_str, so)
                so_urls.extend(su)
                so_urls_nf.extend(suf)
                so_emails_nf.extend(sem)
                # Entropies
                eps = get_entropies(so_str)
                if eps:
                    so_secrets.extend(eps)
    except Exception:
        logger.exception('Extracting Data from SO')
    return {
        'so_secrets': so_secrets,
        'so_strings': so_strings,
        'so_urls_list': so_urls,
        'so_urls_nf': so_urls_nf,
        'so_emails_nf': so_emails_nf,
    }


def strings_from_apk(app_file, app_dir, elf_strings):
    """Extract Strings from an APK file."""
    try:
        logger.info('Extracting Data from APK')
        dat = []
        secrets = []
        urls = []
        urls_nf = []
        emails_nf = []
        apk_file = os.path.join(app_dir, app_file)
        and_a = apk.APK(apk_file)
        rsrc = and_a.get_android_resources()
        if rsrc:
            pkg = rsrc.get_packages_names()[0]
            rsrc.get_strings_resources()
            for i in rsrc.values[pkg].keys():
                res_string = rsrc.values[pkg][i].get('string')
                if not res_string:
                    continue
                for duo in res_string:
                    cap_str = '"' + duo[0] + '" : "' + duo[1] + '"'
                    # Extract possible secret holding keys
                    if is_secret_key(duo[0] + '"') and ' ' not in duo[1]:
                        secrets.append(cap_str)
                    dat.append(cap_str)
            # Extract URLs and Emails from Android String Resources
            urls, urls_nf, emails_nf = url_n_email_extract(
                ''.join(dat), 'Android String Resource')
        # Extract URLs, Emails, and Secrets from .so files
        if elf_strings:
            elf_data = strings_from_so(elf_strings)
            urls.extend(elf_data['so_urls_list'])
            urls_nf.extend(elf_data['so_urls_nf'])
            emails_nf.extend(elf_data['so_emails_nf'])
            dat.extend(elf_data['so_strings'])
            secrets.extend(elf_data['so_secrets'])
        strings_dat = list(set(dat))
        return {
            'strings': strings_dat,
            'urls_list': urls,
            'url_nf': urls_nf,
            'emails_nf': emails_nf,
            'secrets': secrets,
        }
    except Exception:
        logger.exception('Extracting Data from APK')
        return {}


def strings_from_code(src_dir, typ, exts):
    """Extract Strings from Java/Kotlin code."""
    data = {
        'strings': set(),
        'secrets': set(),
    }
    try:
        src_dir = get_android_src_dir(Path(src_dir), typ)
        data = strings_and_entropies(src_dir, exts)
    except Exception:
        logger.exception('Extracting Data from Code')
    return data
