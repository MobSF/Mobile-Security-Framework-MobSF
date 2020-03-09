"""Rule Matchers."""
import re
import logging

from StaticAnalyzer.views.rules_properties import (
    InputCase,
    Match,
    MatchType,
)

from django.utils.html import escape

logger = logging.getLogger(__name__)


def get_list_match_items(ruleset):
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


def add_findings(findings, desc, file_path, rule):
    """Add Code Analysis Findings."""
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


def code_rule_matcher(findings, perms, data, file_path, code_rules):
    """Static Analysis Rule Matcher."""
    try:
        for rule in code_rules:

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
                    if re.findall(rule['regex1'], tmp_data):
                        add_findings(findings, rule[
                                     'desc'], file_path, rule)
                elif rule['match'] == Match.regex_and:
                    and_match_rgx = True
                    match_list = get_list_match_items(rule)
                    for match in match_list:
                        if bool(re.findall(match, tmp_data)) is False:
                            and_match_rgx = False
                            break
                    if and_match_rgx:
                        add_findings(findings, rule[
                                     'desc'], file_path, rule)
                elif rule['match'] == Match.regex_or:
                    match_list = get_list_match_items(rule)
                    for match in match_list:
                        if re.findall(match, tmp_data):
                            add_findings(findings, rule[
                                         'desc'], file_path, rule)
                            break
                elif rule['match'] == Match.regex_and_perm:
                    if (rule['perm'] in perms
                            and re.findall(rule['regex1'], tmp_data)):
                        add_findings(findings, rule[
                                     'desc'], file_path, rule)
                else:
                    logger.error('Code Regex Rule Match Error\n %s', rule)

            elif rule['type'] == MatchType.string:
                if rule['match'] == Match.single_string:
                    if rule['string1'] in tmp_data:
                        add_findings(findings, rule[
                                     'desc'], file_path, rule)
                elif rule['match'] == Match.string_and:
                    and_match_str = True
                    match_list = get_list_match_items(rule)
                    for match in match_list:
                        if (match in tmp_data) is False:
                            and_match_str = False
                            break
                    if and_match_str:
                        add_findings(findings, rule[
                                     'desc'], file_path, rule)
                elif rule['match'] == Match.string_or:
                    match_list = get_list_match_items(rule)
                    for match in match_list:
                        if match in tmp_data:
                            add_findings(findings, rule[
                                         'desc'], file_path, rule)
                            break
                elif rule['match'] == Match.string_and_or:
                    match_list = get_list_match_items(rule)
                    string_or_stat = False
                    for match in match_list:
                        if match in tmp_data:
                            string_or_stat = True
                            break
                    if string_or_stat and (rule['string1'] in tmp_data):
                        add_findings(findings, rule[
                                     'desc'], file_path, rule)
                elif rule['match'] == Match.string_or_and:
                    match_list = get_list_match_items(rule)
                    string_and_stat = True
                    for match in match_list:
                        if match in tmp_data is False:
                            string_and_stat = False
                            break
                    if string_and_stat or (rule['string1'] in tmp_data):
                        add_findings(findings, rule[
                                     'desc'], file_path, rule)
                elif rule['match'] == Match.string_and_perm:
                    if (rule['perm'] in perms
                            and rule['string1'] in tmp_data):
                        add_findings(findings, rule[
                                     'desc'], file_path, rule)
                elif rule['match'] == Match.string_or_and_perm:
                    match_list = get_list_match_items(rule)
                    string_or_ps = False
                    for match in match_list:
                        if match in tmp_data:
                            string_or_ps = True
                            break
                    if (rule['perm'] in perms) and string_or_ps:
                        add_findings(findings, rule[
                                     'desc'], file_path, rule)
                else:
                    logger.error('Code String Rule Match Error\n%s', rule)
            else:
                logger.error('Code Rule Error\n%s', rule)
    except Exception:
        logger.exception('Error in Code Rule Processing')


def add_bfindings(findings, desc, detailed_desc, rule):
    """Add Code Analysis Findings."""
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
                        add_bfindings(findings,
                                      rule['desc'],
                                      detailed_desc,
                                      rule)
                    elif 'conditional' in rule:
                        detailed_desc = rule['conditional']['detailed_desc']
                        add_bfindings(findings,
                                      rule['conditional']['desc'],
                                      detailed_desc,
                                      rule['conditional'])
                else:
                    logger.error('Binary Regex Rule Match Error\n %s', rule)
            elif rule['type'] == MatchType.string:
                if rule['match'] == Match.single_string:
                    if rule['string1'] in tmp_data:
                        add_bfindings(findings,
                                      rule['desc'],
                                      rule['detailed_desc'],
                                      rule)
                    elif 'conditional' in rule:
                        detailed_desc = rule['conditional']['detailed_desc']
                        add_bfindings(findings,
                                      rule['conditional']['desc'],
                                      detailed_desc,
                                      rule['conditional'])
                else:
                    logger.error('Binary String Rule Match Error\n%s', rule)
            else:
                logger.error('Binary Rule Error\n%s', rule)
    except Exception:
        logger.exception('Error in Binary Rule Processing')


def add_apis(api_findings, desc, file_path):
    """Add API Findings."""
    if desc in api_findings:
        tmp_list = api_findings[desc]['path']
        if escape(file_path) not in tmp_list:
            tmp_list.append(escape(file_path))
            api_findings[desc]['path'] = tmp_list
    else:
        api_findings[desc] = {'path': [escape(file_path)]}


def api_rule_matcher(api_findings, perms, data, file_path, api_rules):
    """Android API Analysis Rule Matcher."""
    try:
        for api in api_rules:

            # CASE CHECK
            if api['input_case'] == InputCase.lower:
                tmp_data = data.lower()
            elif api['input_case'] == InputCase.upper:
                tmp_data = data.upper()
            elif api['input_case'] == InputCase.exact:
                tmp_data = data

            # MATCH TYPE
            if api['type'] == MatchType.regex:
                if api['match'] == Match.single_regex:
                    if re.findall(api['regex1'], tmp_data):
                        add_apis(api_findings, api['desc'], file_path)
                elif api['match'] == Match.regex_and:
                    and_match_rgx = True
                    match_list = get_list_match_items(api)
                    for match in match_list:
                        if bool(re.findall(match, tmp_data)) is False:
                            and_match_rgx = False
                            break
                    if and_match_rgx:
                        add_apis(api_findings, api['desc'], file_path)
                elif api['match'] == Match.regex_or:
                    match_list = get_list_match_items(api)
                    for match in match_list:
                        if re.findall(match, tmp_data):
                            add_apis(api_findings, api['desc'], file_path)
                            break
                elif api['match'] == Match.regex_and_perm:
                    if (api['perm'] in perms
                            and re.findall(api['regex1'], tmp_data)):
                        add_apis(api_findings, api['desc'], file_path)
                else:
                    logger.error('API Regex Rule Match Error\n %s', api)

            elif api['type'] == MatchType.string:
                if api['match'] == Match.single_string:
                    if api['string1'] in tmp_data:
                        add_apis(api_findings, api['desc'], file_path)
                elif api['match'] == Match.string_and:
                    and_match_str = True
                    match_list = get_list_match_items(api)
                    for match in match_list:
                        if (match in tmp_data) is False:
                            and_match_str = False
                            break
                    if and_match_str:
                        add_apis(api_findings, api['desc'], file_path)
                elif api['match'] == Match.string_or:
                    match_list = get_list_match_items(api)
                    for match in match_list:
                        if match in tmp_data:
                            add_apis(api_findings, api['desc'], file_path)
                            break
                elif api['match'] == Match.string_and_or:
                    match_list = get_list_match_items(api)
                    string_or_stat = False
                    for match in match_list:
                        if match in tmp_data:
                            string_or_stat = True
                            break
                    if string_or_stat and (api['string1'] in tmp_data):
                        add_apis(api_findings, api['desc'], file_path)
                elif api['match'] == Match.string_or_and:
                    match_list = get_list_match_items(api)
                    string_and_stat = True
                    for match in match_list:
                        if match in tmp_data is False:
                            string_and_stat = False
                            break
                    if string_and_stat or (api['string1'] in tmp_data):
                        add_apis(api_findings, api['desc'], file_path)
                elif api['match'] == Match.string_and_perm:
                    if (api['perm'] in perms) and (api['string1'] in tmp_data):
                        add_apis(api_findings, api['desc'], file_path)
                elif api['match'] == Match.string_or_and_perm:
                    match_list = get_list_match_items(api)
                    string_or_ps = False
                    for match in match_list:
                        if match in tmp_data:
                            string_or_ps = True
                            break
                    if (api['perm'] in perms) and string_or_ps:
                        add_apis(api_findings, api['desc'], file_path)
                else:
                    logger.error('API String Rule Match Error\n%s', api)
            else:
                logger.error('API Rule Error\n%s', api)
    except Exception:
        logger.exception('Error in API Rule Processing')
