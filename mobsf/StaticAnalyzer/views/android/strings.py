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
    GOOGLE_API_KEY_REGEX,
    GOOGLE_APP_ID_REGEX,
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


def strings_from_apk(checksum, app_dic):
    """Extract Strings from an APK."""
    results = {
        'strings': [],
        'urls_list': [],
        'urls_nf': [],
        'emails_nf': [],
        'secrets': [],
        'firebase_creds': {},
    }
    try:
        msg = 'Extracting String data from APK'
        logger.info(msg)
        append_scan_status(checksum, msg)

        rsrc = app_dic.get('androguard_apk_resources')
        if rsrc:
            pkg = rsrc.get_packages_names()[0]
            rsrc.get_strings_resources()

            # Iterate over resource strings
            for _res_key, res_value in rsrc.values.get(pkg, {}).items():
                res_string = res_value.get('string')
                if not res_string:
                    continue

                for key, value in res_string:
                    if not value:
                        continue

                    # Extract Firebase credentials
                    if key == 'google_api_key' and GOOGLE_API_KEY_REGEX.match(value):
                        results['firebase_creds']['google_api_key'] = value
                    elif key == 'google_app_id' and GOOGLE_APP_ID_REGEX.match(value):
                        results['firebase_creds']['google_app_id'] = value

                    # Format and collect strings
                    formatted_str = f'"{key}" : "{value}"'
                    results['strings'].append(formatted_str)

                    # Check for possible secrets
                    if is_secret_key(key) and ' ' not in value:
                        results['secrets'].append(formatted_str)
        elif app_dic.get('apk_strings'):
            # No secret key check for APK strings
            results['strings'] = app_dic['apk_strings']
        else:
            msg = 'Failed to extract String data from APK'
            logger.warning(msg)
            append_scan_status(checksum, msg)
            return results

        # Extract URLs and Emails from collected strings
        results['strings'] = list(set(results['strings']))
        ul, u_nf, e_nf = url_n_email_extract(
            ''.join(results['strings']), 'Android String Resource')
        results['urls_list'], results['urls_nf'], results['emails_nf'] = ul, u_nf, e_nf

    except Exception as exp:
        msg = 'Failed to extract String data from APK'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))

    return results


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


def get_strings_metadata(app_dic, elf_strings, exts, code_dic):
    """Get Strings, secrets, entropies, URLs, emails."""
    checksum = app_dic['md5']
    typ = app_dic['zipped']
    app_dir = app_dic['app_dir']
    strings = {
        'strings_apk_res': {},
        'strings_so': [],
        'strings_code': {},
    }
    urls_list = []
    urls_n_files = []
    emails_n_files = []
    secrets = []
    if app_dic.get('androguard_string_resources') or app_dic.get('apk_strings'):
        # APK
        apk_res = strings_from_apk(checksum, app_dic)
        code_dic['firebase_creds'] = apk_res['firebase_creds']
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
