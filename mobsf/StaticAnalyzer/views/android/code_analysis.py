# -*- coding: utf_8 -*-
"""Module holding the functions for code analysis."""

import os
import logging
import tempfile
from pathlib import Path

from django.conf import settings

import yaml

from mobsf.MobSF.utils import (
    append_scan_status,
    filename_from_path,
    get_android_src_dir,
    settings_enabled,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    url_n_email_extract,
)
from mobsf.StaticAnalyzer.views.sast_engine import (
    niap_scan,
    scan,
)

logger = logging.getLogger(__name__)


def get_perm_rules(checksum, perm_rules, android_permissions):
    """Get applicable permission rules."""
    try:
        if not settings_enabled('PERM_MAPPING_ENABLED'):
            return None
        if not android_permissions:
            return None
        dynamic_rules = []
        with perm_rules.open('r') as perm_file:
            prules = yaml.load(perm_file, Loader=yaml.FullLoader)
        for p in prules:
            if p['id'] in android_permissions.keys():
                dynamic_rules.append(p)
        rules = yaml.dump(dynamic_rules)
        if rules:
            tmp = tempfile.NamedTemporaryFile(
                mode='w',
                delete=False)
            tmp.write(rules)
            tmp.close()
            return tmp
    except Exception as exp:
        msg = 'Getting Permission Rules'
        logger.error(msg)
        append_scan_status(checksum, msg, repr(exp))
    return None


def permission_transform(perm_mappings):
    """Simply permission mappings."""
    mappings = {}
    for k, v in perm_mappings.items():
        mappings[k] = v['files']
    return mappings


def code_analysis(checksum, app_dir, typ, manifest_file, android_permissions):
    """Perform the code analysis."""
    try:
        root = Path(settings.BASE_DIR) / 'StaticAnalyzer' / 'views'
        and_rules = root / 'android' / 'rules'
        code_rules = and_rules / 'android_rules.yaml'
        api_rules = and_rules / 'android_apis.yaml'
        perm_rules = and_rules / 'android_permissions.yaml'
        niap_rules = and_rules / 'android_niap.yaml'
        code_findings = {}
        api_findings = {}
        perm_mappings = {}
        email_n_file = []
        url_n_file = []
        url_list = []
        app_dir = Path(app_dir)
        src = get_android_src_dir(app_dir, typ).as_posix() + '/'
        skp = settings.SKIP_CLASS_PATH
        msg = f'Code Analysis Started on - {filename_from_path(src)}'
        logger.info(msg)
        append_scan_status(checksum, msg)
        # Code Analysis
        code_findings = scan(
            checksum,
            code_rules.as_posix(),
            {'.java', '.kt'},
            [src],
            skp)
        msg = 'Android SAST Completed'
        logger.info(msg)
        append_scan_status(checksum, msg)
        # API Analysis
        msg = 'Android API Analysis Started'
        logger.info(msg)
        append_scan_status(checksum, msg)
        api_findings = scan(
            checksum,
            api_rules.as_posix(),
            {'.java', '.kt'},
            [src],
            skp)
        # Permission Mapping
        rule_file = get_perm_rules(checksum, perm_rules, android_permissions)
        if rule_file:
            msg = 'Android Permission Mapping Started'
            logger.info(msg)
            append_scan_status(checksum, msg)
            perm_mappings = permission_transform(scan(
                checksum,
                rule_file.name,
                {'.java', '.kt'},
                [src],
                {}))
            msg = 'Android Permission Mapping Completed'
            logger.info(msg)
            append_scan_status(checksum, msg)
            os.unlink(rule_file.name)
        # NIAP Scan
        niap_findings = niap_scan(
            checksum,
            niap_rules.as_posix(),
            {'.java', '.xml'},
            [src],
            manifest_file,
            None)
        # Extract URLs and Emails
        for pfile in Path(src).rglob('*'):
            if (
                (pfile.suffix in ('.java', '.kt')
                    and any(skip_path in pfile.as_posix()
                            for skip_path in skp) is False)
            ):
                content = None
                try:
                    content = pfile.read_text('utf-8', 'ignore')
                    # Certain file path cannot be read in windows
                except Exception:
                    continue
                relative_java_path = pfile.as_posix().replace(src, '')
                urls, urls_nf, emails_nf = url_n_email_extract(
                    content, relative_java_path)
                url_list.extend(urls)
                url_n_file.extend(urls_nf)
                email_n_file.extend(emails_nf)
        msg = 'Finished Code Analysis, Email and URL Extraction'
        logger.info(msg)
        append_scan_status(checksum, msg)
        code_an_dic = {
            'api': api_findings,
            'perm_mappings': perm_mappings,
            'findings': code_findings,
            'niap': niap_findings,
            'urls_list': url_list,
            'urls': url_n_file,
            'emails': email_n_file,
        }
        return code_an_dic
    except Exception as exp:
        msg = 'Failed to perform code analysis'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
