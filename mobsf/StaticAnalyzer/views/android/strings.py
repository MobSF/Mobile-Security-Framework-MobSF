# -*- coding: utf_8 -*-
"""Module for strings-method for java."""
import logging
import os
import re
from pathlib import Path

from androguard.core.bytecodes import apk

from mobsf.StaticAnalyzer.views.common.shared_func import (
    is_secret,
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


def strings_from_apk(app_file, app_dir, elf_strings):
    """Extract the strings from an app."""
    try:
        logger.info('Extracting Strings from APK')
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
                if res_string:
                    for duo in res_string:
                        cap_str = '"' + duo[0] + '" : "' + duo[1] + '"'
                        if is_secret(duo[0] + '"') and ' ' not in duo[1]:
                            secrets.append(cap_str)
                        dat.append(cap_str)
            data_string = ''.join(dat)
            urls, urls_nf, emails_nf = url_n_email_extract(
                data_string, 'Android String Resource')
        if elf_strings:
            for solib in elf_strings:
                for so, str_list in solib.items():
                    # add to strings from jar
                    dat.extend(str_list)
                    # extract url, email
                    so_str = ' '.join(str_list)
                    su, suf, sem = url_n_email_extract(
                        so_str, so)
                    urls.extend(su)
                    urls_nf.extend(suf)
                    emails_nf.extend(sem)
        strings_dat = list(set(dat))
        return {
            'strings': strings_dat,
            'urls_list': urls,
            'url_nf': urls_nf,
            'emails_nf': emails_nf,
            'secrets': secrets,
        }
    except Exception:
        logger.exception('Extracting Strings from APK')
        return {}


def strings_from_code(src_dir, typ, exts):
    """Extract Strings from code."""
    logger.info('Extracting Strings from Source Code')
    data = {
        'strings': set(),
        'secrets': set(),
    }
    try:
        src = get_android_src_dir(Path(src_dir), typ)
        if not src.exists():
            return data
        for p in src.rglob('*'):
            if p.suffix not in exts or not p.exists():
                continue
            str_regex = re.compile(r'\".{5,300}?\"')
            ascii_strs = re.findall(
                str_regex, p.read_text(encoding='utf-8'))
            if ascii_strs:
                data['strings'].update(ascii_strs)
        if data['strings']:
            data['secrets'] = get_entropies(data['strings'])
    except Exception:
        logger.exception('Extracting Strings from Code')
    return data
