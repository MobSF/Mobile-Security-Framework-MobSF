# -*- coding: utf_8 -*-
"""Module for strings-method for java."""
import logging
from pathlib import Path

from mobsf.StaticAnalyzer.views.common.shared_func import (
    is_secret_key,
    strings_and_entropies,
    url_n_email_extract,
)
from mobsf.StaticAnalyzer.views.common.entropy import (
    get_entropies,
)
from mobsf.MobSF.utils import (
    append_scan_status,
    get_android_src_dir,
)

logger = logging.getLogger(__name__)


def strings_from_so(checksum, elf_strings):
    """Extract Strings from so file."""
    msg = 'Extracting String data from SO'
    logger.info(msg)
    append_scan_status(checksum, msg)
    sos = []
    try:
        for solib in elf_strings:
            for so, str_list in solib.items():
                if not str_list:
                    continue
                # extract url, email
                so_str = ' '.join(str_list)
                so_urls, so_urls_nf, so_emails_nf = url_n_email_extract(
                    so_str, so)
                sos.append({so: {
                    'secrets': list(get_entropies(so_str)),
                    'strings': list(set(str_list)),
                    'urls_list': so_urls,
                    'urls_nf': so_urls_nf,
                    'emails_nf': so_emails_nf,
                }})
    except Exception as exp:
        msg = 'Failed to extract String data from SO'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
    return sos


def strings_from_apk(checksum, apk):
    """Extract Strings from an APK."""
    dat = []
    secrets = []
    urls = []
    urls_nf = []
    emails_nf = []
    try:
        msg = 'Extracting String data from APK'
        logger.info(msg)
        append_scan_status(checksum, msg)
        rsrc = apk.get_android_resources()
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
    except Exception as exp:
        msg = 'Failed to extract String data from APK'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
    return {
        'strings': list(set(dat)),
        'urls_list': urls,
        'urls_nf': urls_nf,
        'emails_nf': emails_nf,
        'secrets': secrets,
    }


def strings_from_code(checksum, src_dir, typ, exts):
    """Extract Strings and Secrets from Java/Kotlin code."""
    msg = 'Extracting String data from Code'
    logger.info(msg)
    append_scan_status(checksum, msg)
    data = {
        'strings': set(),
        'secrets': set(),
    }
    try:
        src_dir = get_android_src_dir(Path(src_dir), typ)
        data = strings_and_entropies(checksum, src_dir, exts)
    except Exception as exp:
        msg = 'Failed to extract String data from Code'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
    return data


def get_strings_metadata(
        checksum, apk, app_dir, elf_strings, typ, exts, code_dic):
    """Get Strings, secrets, entropies, URLs, emails."""
    strings = {
        'strings_apk_res': {},
        'strings_so': [],
        'strings_code': {},
    }
    urls_list = []
    urls_n_files = []
    emails_n_files = []
    secrets = []
    if apk:
        # APK
        apk_res = strings_from_apk(checksum, apk)
        strings['strings_apk_res'] = apk_res['strings']
        urls_list.extend(apk_res['urls_list'])
        urls_n_files.extend(apk_res['urls_nf'])
        emails_n_files.extend(apk_res['emails_nf'])
        secrets.extend(apk_res['secrets'])
    if elf_strings:
        # ELF (.so) by file
        sos = strings_from_so(checksum, elf_strings)
        so_strings = []
        for so in sos:
            for so_file, s in so.items():
                so_strings.append({so_file: s['strings']})
                urls_list.extend(s['urls_list'])
                urls_n_files.extend(s['urls_nf'])
                emails_n_files.extend(s['emails_nf'])
                secrets.extend(s['secrets'])
        secrets = list(set(secrets))
        strings['strings_so'] = so_strings

    if exts:
        # Source Code
        code_res = strings_from_code(checksum, app_dir, typ, exts)
        strings['strings_code'] = list(code_res['strings'])
        secrets.extend(code_res['secrets'])

    code_dic['strings'] = strings
    code_dic['secrets'] = list(secrets)
    # Code Analysis has urls, urlsnfiles and emailsnfiles
    code_dic['urls'].extend(urls_n_files)
    code_dic['emails'].extend(emails_n_files)
    code_dic['urls_list'].extend(urls_list)
    code_dic['urls_list'] = list(set(code_dic['urls_list']))
