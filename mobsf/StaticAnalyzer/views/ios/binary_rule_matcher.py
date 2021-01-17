# -*- coding: utf_8 -*-
"""Binary Analysis - Rule Matcher."""
import re
import logging

from mobsf.StaticAnalyzer.views.ios.rules import (
    ipa_rules,
)

logger = logging.getLogger(__name__)


def get_desc(desc_str, match):
    """Generate formatted detailed description with matches."""
    return desc_str.format(
        b', '.join(list(set(match))).decode('utf-8', 'ignore'))


def _add_bfindings(findings, desc, detailed_desc, rule):
    """Add Binary Analysis Findings."""
    findings[desc] = {'detailed_desc': detailed_desc,
                      'severity': rule['severity'],
                      'cvss': rule['cvss'],
                      'cwe': rule['cwe'],
                      'owasp-mobile': rule['owasp-mobile'],
                      'masvs': rule['masvs']}


def binary_rule_matcher(findings, symbols, classdump):
    """Static Analysis Rule Matcher."""
    try:
        data = classdump + '\n'.join(symbols).encode('utf-8')
        for rule in ipa_rules.IPA_RULES:

            # CASE CHECK
            if rule['input_case'] == 'lower':
                tmp_data = data.lower()
            elif rule['input_case'] == 'upper':
                tmp_data = data.upper()
            elif rule['input_case'] == 'exact':
                tmp_data = data

            # MATCH TYPE
            if rule['type'] == 'Regex':
                matched = re.findall(rule['pattern'], tmp_data)
                if matched:
                    detailed_desc = get_desc(
                        rule['detailed_desc'],
                        matched)
                    _add_bfindings(findings,
                                   rule['description'],
                                   detailed_desc,
                                   rule)

            else:
                logger.error('Binary rule Error\n%s', rule)
    except Exception:
        logger.exception('Error in Binary Rule Processing')
