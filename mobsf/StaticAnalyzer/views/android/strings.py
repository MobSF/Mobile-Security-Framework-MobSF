# -*- coding: utf_8 -*-
"""Module for strings-method for java."""
import logging
import os

from androguard.core.bytecodes import apk

from mobsf.StaticAnalyzer.views.shared_func import url_n_email_extract

logger = logging.getLogger(__name__)


def is_secret(inp):
    inp = inp.lower()
    """Check if captures string is a possible secret."""
    iden = (
        'api"', 'key"', 'api_"', 'secret"',
        'password"', 'aws', 'gcp', 's3',
        'token"', 'username"', 'user_name"', 'user"',
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


def strings_from_apk(app_file, app_dir, elf_strings):
    """Extract the strings from an app."""
    try:
        logger.info('Extracting Strings from APK')
        dat = []
        secrets = []
        apk_file = os.path.join(app_dir, app_file)
        and_a = apk.APK(apk_file)
        rsrc = and_a.get_android_resources()
        pkg = rsrc.get_packages_names()[0]
        rsrc.get_strings_resources()
        for i in rsrc.values[pkg].keys():
            res_string = rsrc.values[pkg][i].get('string')
            if res_string:
                for duo in res_string:
                    cap_str = '"' + duo[0] + '" : "' + duo[1] + '"'
                    if is_secret(duo[0] + '"'):
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
        return {'strings': strings_dat,
                'urls_list': urls,
                'url_nf': urls_nf,
                'emails_nf': emails_nf,
                'secrets': secrets,
                }
    except Exception:
        logger.exception('Extracting Strings from APK')
        return {}
