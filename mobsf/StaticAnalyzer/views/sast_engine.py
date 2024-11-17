# -*- coding: utf_8 -*-
"""SAST engine."""
import logging

from libsast import Scanner
from libsast.core_matcher.pattern_matcher import PatternMatcher
from libsast.core_matcher.choice_matcher import ChoiceMatcher
from libsast.common import get_worker_count

from django.conf import settings

from mobsf.MobSF.utils import (
    run_with_timeout,
)

logger = logging.getLogger(__name__)


class SastEngine:
    def __init__(self, options, path):
        self.root = path
        mp = 'billiard' if settings.ASYNC_ANALYSIS else 'default'
        # Override multiprocessing settings if set in the config
        mp = settings.MULTIPROCESSING if settings.MULTIPROCESSING else mp
        options['cpu_core'] = get_worker_count()
        options['multiprocessing'] = mp
        self.scan_paths = Scanner(options, [path]).get_scan_files()
        self.pattern_matcher = PatternMatcher(options)

    def scan(self):
        """Scan the files with given rules."""
        finds = run_with_timeout(
            self.pattern_matcher.scan,
            settings.SAST_TIMEOUT,
            self.scan_paths)
        return self.format_findings(finds)

    def read_files(self):
        """Read the files."""
        logger.info('Reading file contents for SAST')
        return self.pattern_matcher.read_file_contents(self.scan_paths)

    def run_rules(self, file_contents, rule_path):
        """Run the rules."""
        finds = run_with_timeout(
            self.pattern_matcher.regex_scan,
            settings.SAST_TIMEOUT,
            file_contents,
            rule_path)
        return self.format_findings(finds)

    def format_findings(self, findings):
        """Format the findings."""
        for details in findings.values():
            tmp_dict = {}
            for file_meta in details['files']:
                file_meta['file_path'] = file_meta[
                    'file_path'].replace(self.root, '', 1)
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


class ChoiceEngine:
    def __init__(self, options, path):
        self.root = path
        mp = 'billiard' if settings.ASYNC_ANALYSIS else 'default'
        options['cpu_core'] = get_worker_count()
        options['multiprocessing'] = mp
        self.scan_paths = Scanner(options, [path]).get_scan_files()
        self.choice_matcher = ChoiceMatcher(options)

    def read_files(self):
        """Read the files."""
        logger.info('Reading file contents for NIAP Scan')
        return self.choice_matcher.read_file_contents(self.scan_paths)

    def run_rules(self, file_contents, rule_path):
        """Run the rules."""
        return run_with_timeout(
            self.choice_matcher.regex_scan,
            settings.SAST_TIMEOUT,
            file_contents,
            rule_path)
