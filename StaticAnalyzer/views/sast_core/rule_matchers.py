# -*- coding: utf_8 -*-
"""Rule Matchers."""
import re
import logging
from enum import Enum


from StaticAnalyzer.views.sast_core.matchers import (
    InputCase,
    SingleRegex,
    SingleString,
)

from django.utils.html import escape

logger = logging.getLogger(__name__)


class _MatcherType(Enum):
    code = 1
    api = 2


def _add_code_findings(findings, file_path, rule):
    """Add Code Analysis Findings."""
    desc = rule['desc']
    if desc in findings:
        tmp_list = findings[desc]['path']
        if escape(file_path) not in tmp_list:
            tmp_list.append(escape(file_path))
            findings[desc]['path'] = tmp_list
    else:
        findings[desc] = {'path': [escape(file_path)],
                          'level': rule['level'].value,
                          'cvss': rule['cvss'],
                          'cwe': rule['cwe'],
                          'owasp': rule['owasp'],
                          'owasp-mstg': rule['owasp-mstg']}


def _add_apis_findings(findings, file_path, rule):
    """Add API Findings."""
    desc = rule['desc']
    if desc in findings:
        tmp_list = findings[desc]['path']
        if escape(file_path) not in tmp_list:
            tmp_list.append(escape(file_path))
            findings[desc]['path'] = tmp_list
    else:
        findings[desc] = {'path': [escape(file_path)]}


def api_rule_matcher(findings, perms, data, file_path, rules, match_command):
    _rule_matcher(_MatcherType.api, findings, perms,
                  data, file_path, rules, match_command)


def code_rule_matcher(findings, perms, data, file_path, rules, match_command):
    _rule_matcher(_MatcherType.code, findings, perms, data,
                  file_path, rules, match_command)


def _rule_matcher(matcher, findings, perms, data,
                  file_path, rules, match_command):
    """Static Analysis Rule Matcher."""
    try:
        if matcher == _MatcherType.code:
            add_finding = _add_code_findings
        elif matcher == _MatcherType.api:
            add_finding = _add_apis_findings
        for rule in rules:
            if rule['input_case'] == InputCase.lower:
                tmp_data = data.lower()
            elif rule['input_case'] == InputCase.upper:
                tmp_data = data.upper()
            elif rule['input_case'] == InputCase.exact:
                tmp_data = data
            if match_command.find_match(rule['type'], tmp_data, rule, perms):
                add_finding(findings, file_path, rule)
    except Exception:
        logger.exception('Error in Code Rule Processing')


def _add_bfindings(findings, desc, detailed_desc, rule):
    """Add Binary Analysis Findings."""
    findings[desc] = {'detailed_desc': detailed_desc,
                      'level': rule['level'].value,
                      'cvss': rule['cvss'],
                      'cwe': rule['cwe'],
                      'owasp': rule['owasp'],
                      'owasp-mstg': rule['owasp-mstg']}


def get_desc(desc_str, match):
    """Generate formatted detailed description with matches."""
    return desc_str.format(
        b', '.join(list(set(match))).decode('utf-8', 'ignore'))


def binary_rule_matcher(findings, data, ipa_rules):
    """Static Analysis Rule Matcher."""
    try:
        for rule in ipa_rules:

            # CASE CHECK
            if rule['input_case'] == InputCase.lower:
                tmp_data = data.lower()
            elif rule['input_case'] == InputCase.upper:
                tmp_data = data.upper()
            elif rule['input_case'] == InputCase.exact:
                tmp_data = data

            # MATCH TYPE
            if rule['type'] == SingleRegex.__name__:
                matched = re.findall(rule['match'], tmp_data)
                if matched:
                    detailed_desc = get_desc(
                        rule['detailed_desc'],
                        matched)
                    _add_bfindings(findings,
                                   rule['desc'],
                                   detailed_desc,
                                   rule)
                elif 'conditional' in rule:
                    detailed_desc = rule['conditional']['detailed_desc']
                    _add_bfindings(findings,
                                   rule['conditional']['desc'],
                                   detailed_desc,
                                   rule['conditional'])

            elif rule['type'] == SingleString.__name__:
                if rule['match'] in tmp_data:
                    _add_bfindings(findings,
                                   rule['desc'],
                                   rule['detailed_desc'],
                                   rule)
                elif 'conditional' in rule:
                    detailed_desc = rule['conditional']['detailed_desc']
                    _add_bfindings(findings,
                                   rule['conditional']['desc'],
                                   detailed_desc,
                                   rule['conditional'])
            else:
                logger.error('Binary rule Error\n%s', rule)
    except Exception:
        logger.exception('Error in Binary Rule Processing')
