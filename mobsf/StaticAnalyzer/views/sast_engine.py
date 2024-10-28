# -*- coding: utf_8 -*-
"""SAST engine."""
import logging

from libsast import Scanner

from django.conf import settings

from mobsf.MobSF.utils import (
    append_scan_status,
    run_with_timeout,
    settings_enabled,
)

logger = logging.getLogger(__name__)


def scan(checksum, rule, extensions, paths, ignore_paths=None):
    """The libsast scan."""
    try:
        options = {
            'match_rules': rule,
            'match_extensions': extensions,
            'ignore_paths': ignore_paths,
            'show_progress': False}
        scanner = Scanner(options, paths)
        res = run_with_timeout(scanner.scan, settings.SAST_TIMEOUT)
        if res and res.get('pattern_matcher'):
            return format_findings(res['pattern_matcher'], paths[0])
    except Exception as exp:
        msg = 'libsast scan failed'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
    return {}


def niap_scan(checksum, rule, extensions, paths, apath, ignore_paths=None):
    """NIAP scan."""
    if not settings_enabled('NIAP_ENABLED'):
        return {}
    try:
        msg = 'Running NIAP Analyzer'
        logger.info(msg)
        append_scan_status(checksum, msg)
        if not apath:
            apath = ''
        options = {
            'choice_rules': rule,
            'alternative_path': apath,
            'choice_extensions': extensions,
            'ignore_paths': ignore_paths,
            'show_progress': False}
        scanner = Scanner(options, paths)
        res = run_with_timeout(scanner.scan, settings.SAST_TIMEOUT)
        if res and res.get('choice_matcher'):
            return res['choice_matcher']
    except Exception as exp:
        msg = 'NIAP Analyzer Failed'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
    return {}


def format_findings(findings, root):
    """Format findings."""
    for details in findings.values():
        tmp_dict = {}
        for file_meta in details['files']:
            file_meta['file_path'] = file_meta[
                'file_path'].replace(root, '', 1)
            file_path = file_meta['file_path']
            start = file_meta['match_lines'][0]
            end = file_meta['match_lines'][1]
            if start == end:
                match_lines = start
            else:
                exp_lines = []
                for i in range(start, end + 1):
                    exp_lines.append(i)
                match_lines = ','.join(str(m) for m in exp_lines)
            if file_path not in tmp_dict:
                tmp_dict[file_path] = str(match_lines)
            elif tmp_dict[file_path].endswith(','):
                tmp_dict[file_path] += str(match_lines)
            else:
                tmp_dict[file_path] += ',' + str(match_lines)
        details['files'] = tmp_dict
    return findings
