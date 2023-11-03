# -*- coding: utf_8 -*-
"""Module for iOS String Analysis."""
import io
import logging

from mobsf.StaticAnalyzer.views.common.entropy import (
    get_entropies,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    url_n_email_extract,
)


logger = logging.getLogger(__name__)


def extract_urls_n_email(src, all_files, strings):
    """IPA URL and Email Extraction."""
    email_n_file = []
    url_n_file = []
    url_list = []
    try:
        logger.info('Starting IPA URL and Email Extraction')
        all_files.append({'data': strings, 'name': 'IPA Strings Dump'})
        for file in all_files:
            if isinstance(file, dict):
                relative_src_path = file['name']
                dat = '\n'.join(file['data'])
            # Skip CodeResources and contents under Frameworks
            elif 'CodeResources' in file or '/Frameworks/' in file:
                continue
            elif file.endswith(('.nib', '.ttf', '.svg', '.woff2',
                                '.png', '.dylib', '.mobileprovision',
                                'Assets.car')):
                continue
            else:
                dat = ''
                relative_src_path = file.replace(src, '')
                with io.open(file,
                             mode='r',
                             encoding='utf8',
                             errors='ignore') as flip:
                    dat = flip.read()
            # Extract URLs and Emails from Plists
            urls, urls_nf, emails_nf = url_n_email_extract(
                dat, relative_src_path)
            url_list.extend(urls)
            url_n_file.extend(urls_nf)
            email_n_file.extend(emails_nf)
    except Exception:
        logger.exception('IPA URL and Email Extraction')
    return {
        'urls_list': list(set(url_list)),
        'urlnfile': url_n_file,
        'emailnfile': email_n_file,
    }


def get_strings_metadata(app_dict, bin_dict, all_files, dy_list):
    """Merge strings metadata."""
    # app_dict has secrets from plist secret analysis
    # bin_dict has strings from binary analysis
    urls_list = []
    urls_n_files = []
    emails_n_files = []
    secrets = []

    # IPA URL and Email Extract
    str_meta = extract_urls_n_email(
        app_dict['bin_dir'],
        all_files['files_long'],
        bin_dict['strings'])
    urls_list = str_meta['urls_list']
    urls_n_files = str_meta['urlnfile']
    emails_n_files = str_meta['emailnfile']

    if dy_list:
        # DYLIB (.dylib)/Framework by file
        dy_strings = []
        for dy in dy_list:
            for dy_file, s in dy.items():
                dy_strings.extend(s)
                dy_str = ' '.join(s)
                urls, urls_nf, emails_nf = url_n_email_extract(
                    dy_str, dy_file)
                urls_list.extend(urls)
                urls_n_files.extend(urls_nf)
                emails_n_files.extend(emails_nf)
                secrets.extend(get_entropies(dy_str))

        bin_dict['strings'].extend(dy_strings)
        bin_dict['strings'] = list(
            set(bin_dict['strings']))
        app_dict['secrets'].extend(secrets)
        app_dict['secrets'] = list(
            set(app_dict['secrets']))
    return {
        'urls_list': list(set(urls_list)),
        'urlnfile': urls_n_files,
        'emailnfile': emails_n_files,
    }
