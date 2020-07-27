# -*- coding: utf_8 -*-
"""SAST engine."""
from libsast import Scanner


def scan(rule, extensions, paths, ignore_paths=None):
    """The libsast scan."""
    try:
        options = {
            'match_rules': rule,
            'sgrep_rules': None,
            'sgrep_extensions': None,
            'match_extensions': extensions,
            'ignore_filenames': None,
            'ignore_extensions': None,
            'ignore_paths': ignore_paths,
            'show_progress': False}
        scanner = Scanner(options, paths)
        res = scanner.scan()
        if res:
            return format_findings(res['pattern_matcher'], paths[0])
    except Exception:
        logger.exception('libsast scan')
    return {}


def format_findings(findings, root):
    """Format findings."""
    for details in findings.values():
        tmp_dict = {}
        for file_meta in details['files']:
            file_meta['file_path'] = file_meta[
                'file_path'].replace(root, '', 1)
            tmp_dict[file_meta['file_path']] = file_meta
        details['files'] = list(tmp_dict.values())
    return findings
