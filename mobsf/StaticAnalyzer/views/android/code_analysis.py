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
    ChoiceEngine,
    SastEngine,
)
from mobsf.MalwareAnalyzer.views.android import (
    behaviour_analysis,
)
from mobsf.StaticAnalyzer.views.android import (
    sbom_analysis,
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
    result = {
        'api': {},
        'behaviour': {},
        'perm_mappings': {},
        'findings': {},
        'niap': {},
        'urls_list': [],
        'urls': [],
        'emails': [],
        'sbom': {},
    }
    try:
        root = Path(settings.BASE_DIR) / 'StaticAnalyzer' / 'views'
        and_rules = root / 'android' / 'rules'
        code_rules = and_rules / 'android_rules.yaml'
        api_rules = and_rules / 'android_apis.yaml'
        perm_rules = and_rules / 'android_permissions.yaml'
        niap_rules = and_rules / 'android_niap.yaml'
        app_dir = Path(app_dir)
        src = get_android_src_dir(app_dir, typ).as_posix() + '/'
        skp = settings.SKIP_CLASS_PATH
        msg = f'Code Analysis Started on - {filename_from_path(src)}'
        logger.info(msg)
        append_scan_status(checksum, msg)

        options = {
            'match_rules': code_rules.as_posix(),
            'match_extensions': {'.java', '.kt'},
            'ignore_paths': skp,
        }
        sast = SastEngine(options, src)
        # Read data once and pass it to all the analysis
        file_data = sast.read_files()

        # SBOM Analysis
        result['sbom'] = sbom_analysis.sbom(app_dir, file_data)
        msg = 'Android SBOM Analysis Completed'
        logger.info(msg)
        append_scan_status(checksum, msg)

        # Code Analysis
        result['findings'] = sast.run_rules(
            file_data, code_rules.as_posix())
        msg = 'Android SAST Completed'
        logger.info(msg)
        append_scan_status(checksum, msg)

        # API Analysis
        msg = 'Android API Analysis Started'
        logger.info(msg)
        append_scan_status(checksum, msg)
        sast = SastEngine(options, src)
        result['api'] = sast.run_rules(
            file_data, api_rules.as_posix())
        msg = 'Android API Analysis Completed'
        logger.info(msg)
        append_scan_status(checksum, msg)

        # Permission Mapping
        rule_file = get_perm_rules(
            checksum, perm_rules, android_permissions)
        if rule_file:
            msg = 'Android Permission Mapping Started'
            logger.info(msg)
            append_scan_status(checksum, msg)
            sast = SastEngine(options, src)
            result['perm_mappings'] = permission_transform(
                sast.run_rules(file_data, rule_file.name))
            msg = 'Android Permission Mapping Completed'
            logger.info(msg)
            append_scan_status(checksum, msg)
            os.unlink(rule_file.name)

        # Behavior Analysis
        sast = SastEngine(options, src)
        result['behaviour'] = behaviour_analysis.analyze(
            checksum, sast, file_data)

        # NIAP Scan
        if settings_enabled('NIAP_ENABLED'):
            msg = 'Running NIAP Analyzer'
            logger.info(msg)
            append_scan_status(checksum, msg)
            niap_options = {
                'choice_rules': niap_rules.as_posix(),
                'alternative_path': str(manifest_file) if manifest_file else '',
                'choice_extensions': {'.java', '.xml'},
                'ignore_paths': skp,
            }
            cengine = ChoiceEngine(niap_options, src)
            file_data = cengine.read_files()
            result['niap'] = cengine.run_rules(
                file_data, niap_rules.as_posix())
            msg = 'NIAP Analysis Completed'
            logger.info(msg)
            append_scan_status(checksum, msg)

        # Extract URLs and Emails
        msg = 'Extracting Emails and URLs from Source Code'
        logger.info(msg)
        append_scan_status(checksum, msg)
        for pfile in Path(src).rglob('*'):
            if (
                (pfile.suffix in ('.java', '.kt')
                    and any(skip_path in pfile.as_posix()
                            for skip_path in skp) is False
                    and pfile.is_file())
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
                result['urls_list'].extend(urls)
                result['urls'].extend(urls_nf)
                result['emails'].extend(emails_nf)
        msg = 'Email and URL Extraction Completed'
        logger.info(msg)
        append_scan_status(checksum, msg)
    except Exception as exp:
        msg = 'Failed to perform code analysis'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
    return result
