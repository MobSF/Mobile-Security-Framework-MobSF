# -*- coding: utf_8 -*-
"""Module for strings-method for java."""
import logging
import os

from androguard.core.bytecodes import apk

from StaticAnalyzer.views.shared_func import url_n_email_extract

logger = logging.getLogger(__name__)


def strings_jar(app_file, app_dir):
    """Extract the strings from an app."""
    try:
        logger.info('Extracting Strings from APK')
        dat = []
        apk_file = os.path.join(app_dir, app_file)
        and_a = apk.APK(apk_file)
        rsrc = and_a.get_android_resources()
        pkg = rsrc.get_packages_names()[0]
        rsrc.get_strings_resources()
        for i in rsrc.values[pkg].keys():
            res_string = rsrc.values[pkg][i].get('string')
            if res_string:
                for duo in res_string:
                    dat.append('"' + duo[0] + '" : "' + duo[1] + '"')
        data_string = ''.join(dat)
        urls, urls_nf, emails_nf = url_n_email_extract(
            data_string, 'Android String Resource')
        return {'strings': dat,
                'urls_list': urls,
                'url_nf': urls_nf,
                'emails_nf': emails_nf,
                }
    except Exception:
        logger.exception('Extracting Strings from APK')
        return {}
