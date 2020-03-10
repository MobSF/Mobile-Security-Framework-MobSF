"""Rule Matchers."""
import re
import logging
from enum import Enum

from StaticAnalyzer.views.rules_properties import (
    InputCase,
    Match,
    MatchType,
)

from django.utils.html import escape

logger = logging.getLogger(__name__)


class _MatcherType(Enum):
    code = 1
    api = 2


def _get_list_match_items(ruleset):
    """Get List of Match item."""
    match_list = []
    i = 1
    identifier = ruleset['type'].value
    if ruleset['match'] == Match.string_and_or:
        identifier = 'string_or'
    elif ruleset['match'] == Match.string_or_and:
        identifier = 'string_and'
    while identifier + str(i) in ruleset:
        match_list.append(ruleset[identifier + str(i)])
        i = i + 1
        if not (identifier + str(i)) in ruleset:
            break
    return match_list


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


def _add_findings(matcher, findings, file_path, rule):
    if matcher == _MatcherType.code:
        _add_code_findings(findings, file_path, rule)
    elif matcher == _MatcherType.api:
        _add_apis_findings(findings, file_path, rule)


def _match_regex_rule(rule, matcher, findings, perms, data,
                      file_path, tmp_data):
    if rule['match'] == Match.single_regex:
        if re.findall(rule['regex1'], tmp_data):
            _add_findings(matcher, findings, file_path, rule)
    elif rule['match'] == Match.regex_and:
        and_match_rgx = True
        match_list = _get_list_match_items(rule)
        for match in match_list:
            if bool(re.findall(match, tmp_data)) is False:
                and_match_rgx = False
                break
        if and_match_rgx:
            _add_findings(matcher, findings, file_path, rule)
    elif rule['match'] == Match.regex_or:
        match_list = _get_list_match_items(rule)
        for match in match_list:
            if re.findall(match, tmp_data):
                _add_findings(matcher, findings, file_path, rule)
                break
    elif rule['match'] == Match.regex_and_perm:
        if (rule['perm'] in perms
                and re.findall(rule['regex1'], tmp_data)):
            _add_findings(matcher, findings, file_path, rule)
    else:
        logger.error('Code Regex Rule Match Error\n %s', rule)


def _match_string_rule(rule, matcher, findings, perms, data,
                       file_path, tmp_data):
    if rule['match'] == Match.single_string:
        if rule['string1'] in tmp_data:
            _add_findings(matcher, findings, file_path, rule)
    elif rule['match'] == Match.string_and:
        and_match_str = True
        match_list = _get_list_match_items(rule)
        for match in match_list:
            if (match in tmp_data) is False:
                and_match_str = False
                break
        if and_match_str:
            _add_findings(matcher, findings, file_path, rule)
    elif rule['match'] == Match.string_or:
        match_list = _get_list_match_items(rule)
        for match in match_list:
            if match in tmp_data:
                _add_findings(matcher, findings, file_path, rule)
                break
    elif rule['match'] == Match.string_and_or:
        match_list = _get_list_match_items(rule)
        string_or_stat = False
        for match in match_list:
            if match in tmp_data:
                string_or_stat = True
                break
        if string_or_stat and (rule['string1'] in tmp_data):
            _add_findings(matcher, findings, file_path, rule)
    elif rule['match'] == Match.string_or_and:
        match_list = _get_list_match_items(rule)
        string_and_stat = True
        for match in match_list:
            if match in tmp_data is False:
                string_and_stat = False
                break
        if string_and_stat or (rule['string1'] in tmp_data):
            _add_findings(matcher, findings, file_path, rule)
    elif rule['match'] == Match.string_and_perm:
        if (rule['perm'] in perms
                and rule['string1'] in tmp_data):
            _add_findings(matcher, findings, file_path, rule)
    elif rule['match'] == Match.string_or_and_perm:
        match_list = _get_list_match_items(rule)
        string_or_ps = False
        for match in match_list:
            if match in tmp_data:
                string_or_ps = True
                break
        if (rule['perm'] in perms) and string_or_ps:
            _add_findings(matcher, findings, file_path, rule)
    elif rule['match'] == Match.string_and_not:
        if (rule['string1'] in tmp_data
                and rule['string2'] not in tmp_data):
            _add_findings(matcher, findings, file_path, rule)
    else:
        logger.error('Code String Rule Match Error\n%s', rule)


def _rule_matcher(matcher, findings, perms, data, file_path, rules):
    """Static Analysis Rule Matcher."""
    try:
        for rule in rules:

            # CASE CHECK
            if rule['input_case'] == InputCase.lower:
                tmp_data = data.lower()
            elif rule['input_case'] == InputCase.upper:
                tmp_data = data.upper()
            elif rule['input_case'] == InputCase.exact:
                tmp_data = data

            # MATCH TYPE
            if rule['type'] == MatchType.regex:
                _match_regex_rule(rule, matcher, findings, perms,
                                  data, file_path, tmp_data)

            elif rule['type'] == MatchType.string:
                _match_string_rule(rule, matcher, findings, perms,
                                   data, file_path, tmp_data)
            else:
                logger.error('Code Rule Error\n%s', rule)
    except Exception:
        logger.exception('Error in Code Rule Processing')


def api_rule_matcher(findings, perms, data, file_path, rules):
    _rule_matcher(_MatcherType.api, findings, perms, data, file_path, rules)


def code_rule_matcher(findings, perms, data, file_path, rules):
    _rule_matcher(_MatcherType.code, findings, perms, data, file_path, rules)


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
            if rule['type'] == MatchType.regex:
                if rule['match'] == Match.single_regex:
                    matched = re.findall(rule['regex1'], tmp_data)
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
                else:
                    logger.error('Binary Regex Rule Match Error\n %s', rule)
            elif rule['type'] == MatchType.string:
                if rule['match'] == Match.single_string:
                    if rule['string1'] in tmp_data:
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
                    logger.error('Binary String Rule Match Error\n%s', rule)
            else:
                logger.error('Binary Rule Error\n%s', rule)
    except Exception:
        logger.exception('Error in Binary Rule Processing')
