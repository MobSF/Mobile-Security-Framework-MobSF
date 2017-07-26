# -*- coding: utf_8 -*-
"""Module holding the functions for code analysis."""

import io
import shutil
import re
import os

from django.conf import settings
from django.utils.html import escape

from StaticAnalyzer.views.android import (
    android_rules,
    android_apis
)
from MalwareAnalyzer.views import malware_check

from MobSF.utils import (
    PrintException
)


def get_list_match_items(ruleset):
    """Get List of Match item"""
    match_list = []
    i = 1
    identifier = ruleset["type"]
    if ruleset["match"] == 'string_and_or':
        identifier = 'string_or'
    elif ruleset["match"] == 'string_or_and':
        identifier = 'string_and'
    while identifier + str(i) in ruleset:
        match_list.append(ruleset[identifier + str(i)])
        i = i + 1
        if identifier + str(i) in ruleset == False:
            break
    return match_list


def add_findings(findings, desc, file_path, level):
    """Add Code Analysis Findings"""
    if desc in findings:
        tmp_list = findings[desc]["path"]
        if escape(file_path) not in tmp_list:
            tmp_list.append(escape(file_path))
            findings[desc]["path"] = tmp_list
    else:
        findings[desc] = {"path": [escape(file_path)], "level": level}


def code_rule_matcher(findings, perms, data, file_path):
    """Android Static Analysis Rule Matcher"""
    try:
        rules = android_rules.RULES
        for rule in rules:

            # CASE CHECK
            if rule["input_case"] == "lower":
                tmp_data = data.lower()
            elif rule["input_case"] == "upper":
                tmp_data = data.upper()
            elif rule["input_case"] == "exact":
                tmp_data = data

            # MATCH TYPE
            if rule["type"] == "regex":
                if rule["match"] == 'single_regex':
                    if re.findall(rule["regex1"], tmp_data):
                        add_findings(findings, rule[
                                     "desc"], file_path, rule["level"])
                elif rule["match"] == 'regex_and':
                    and_match_rgx = True
                    match_list = get_list_match_items(rule)
                    for match in match_list:
                        if bool(re.findall(match, tmp_data)) is False:
                            and_match_rgx = False
                            break
                    if and_match_rgx:
                        add_findings(findings, rule[
                                     "desc"], file_path, rule["level"])
                elif rule["match"] == 'regex_or':
                    match_list = get_list_match_items(rule)
                    for match in match_list:
                        if re.findall(match, tmp_data):
                            add_findings(findings, rule[
                                         "desc"], file_path, rule["level"])
                            break
                elif rule["match"] == 'regex_and_perm':
                    if (rule["perm"] in perms) and (re.findall(rule["regex1"], tmp_data)):
                        add_findings(findings, rule[
                                     "desc"], file_path, rule["level"])
                else:
                    print "\n[ERROR] Code Regex Rule Match Error\n" + rule

            elif rule["type"] == "string":
                if rule["match"] == 'single_string':
                    if rule["string1"] in tmp_data:
                        add_findings(findings, rule[
                                     "desc"], file_path, rule["level"])
                elif rule["match"] == 'string_and':
                    and_match_str = True
                    match_list = get_list_match_items(rule)
                    for match in match_list:
                        if (match in tmp_data) is False:
                            and_match_str = False
                            break
                    if and_match_str:
                        add_findings(findings, rule[
                                     "desc"], file_path, rule["level"])
                elif rule["match"] == 'string_or':
                    match_list = get_list_match_items(rule)
                    for match in match_list:
                        if match in tmp_data:
                            add_findings(findings, rule[
                                         "desc"], file_path, rule["level"])
                            break
                elif rule["match"] == 'string_and_or':
                    match_list = get_list_match_items(rule)
                    string_or_stat = False
                    for match in match_list:
                        if match in tmp_data:
                            string_or_stat = True
                            break
                    if string_or_stat and (rule["string1"] in tmp_data):
                        add_findings(findings, rule[
                                     "desc"], file_path, rule["level"])
                elif rule["match"] == 'string_or_and':
                    match_list = get_list_match_items(rule)
                    string_and_stat = True
                    for match in match_list:
                        if match in tmp_data is False:
                            string_and_stat = False
                            break
                    if string_and_stat or (rule["string1"] in tmp_data):
                        add_findings(findings, rule[
                                     "desc"], file_path, rule["level"])
                elif rule["match"] == 'string_and_perm':
                    if (rule["perm"] in perms) and (rule["string1"] in tmp_data):
                        add_findings(findings, rule[
                                     "desc"], file_path, rule["level"])
                elif rule["match"] == 'string_or_and_perm':
                    match_list = get_list_match_items(rule)
                    string_or_ps = False
                    for match in match_list:
                        if match in tmp_data:
                            string_or_ps = True
                            break
                    if (rule["perm"] in perms) and string_or_ps:
                        add_findings(findings, rule[
                                     "desc"], file_path, rule["level"])
                else:
                    print "\n[ERROR] Code String Rule Match Error\n" + rule
            else:
                print "\n[ERROR] Code Rule Error\n", + rule
    except:
        PrintException("[ERROR] Error in Code Rule Processing")


def add_apis(api_findings, desc, file_path):
    """Add API Findings"""
    if desc in api_findings:
        tmp_list = api_findings[desc]["path"]
        if escape(file_path) not in tmp_list:
            tmp_list.append(escape(file_path))
            api_findings[desc]["path"] = tmp_list
    else:
        api_findings[desc] = {"path": [escape(file_path)]}


def api_rule_matcher(api_findings, perms, data, file_path):
    """Android API Analysis Rule Matcher"""
    try:
        apis_rule = android_apis.APIS
        for api in apis_rule:

            # CASE CHECK
            if api["input_case"] == "lower":
                tmp_data = data.lower()
            elif api["input_case"] == "upper":
                tmp_data = data.upper()
            elif api["input_case"] == "exact":
                tmp_data = data

            # MATCH TYPE
            if api["type"] == "regex":
                if api["match"] == 'single_regex':
                    if re.findall(api["regex1"], tmp_data):
                        add_apis(api_findings, api["desc"], file_path)
                elif api["match"] == 'regex_and':
                    and_match_rgx = True
                    match_list = get_list_match_items(api)
                    for match in match_list:
                        if bool(re.findall(match, tmp_data)) is False:
                            and_match_rgx = False
                            break
                    if and_match_rgx:
                        add_apis(api_findings, api["desc"], file_path)
                elif api["match"] == 'regex_or':
                    match_list = get_list_match_items(api)
                    for match in match_list:
                        if re.findall(match, tmp_data):
                            add_apis(api_findings, api["desc"], file_path)
                            break
                elif api["match"] == 'regex_and_perm':
                    if (api["perm"] in perms) and (re.findall(api["regex1"], tmp_data)):
                        add_apis(api_findings, api["desc"], file_path)
                else:
                    print "\n[ERROR] API Regex Rule Match Error\n" + api

            elif api["type"] == "string":
                if api["match"] == 'single_string':
                    if api["string1"] in tmp_data:
                        add_apis(api_findings, api["desc"], file_path)
                elif api["match"] == 'string_and':
                    and_match_str = True
                    match_list = get_list_match_items(api)
                    for match in match_list:
                        if (match in tmp_data) is False:
                            and_match_str = False
                            break
                    if and_match_str:
                        add_apis(api_findings, api["desc"], file_path)
                elif api["match"] == 'string_or':
                    match_list = get_list_match_items(api)
                    for match in match_list:
                        if match in tmp_data:
                            add_apis(api_findings, api["desc"], file_path)
                            break
                elif api["match"] == 'string_and_or':
                    match_list = get_list_match_items(api)
                    string_or_stat = False
                    for match in match_list:
                        if match in tmp_data:
                            string_or_stat = True
                            break
                    if string_or_stat and (api["string1"] in tmp_data):
                        add_apis(api_findings, api["desc"], file_path)
                elif api["match"] == 'string_or_and':
                    match_list = get_list_match_items(api)
                    string_and_stat = True
                    for match in match_list:
                        if match in tmp_data is False:
                            string_and_stat = False
                            break
                    if string_and_stat or (api["string1"] in tmp_data):
                        add_apis(api_findings, api["desc"], file_path)
                elif api["match"] == 'string_and_perm':
                    if (api["perm"] in perms) and (api["string1"] in tmp_data):
                        add_apis(api_findings, api["desc"], file_path)
                elif api["match"] == 'string_or_and_perm':
                    match_list = get_list_match_items(api)
                    string_or_ps = False
                    for match in match_list:
                        if match in tmp_data:
                            string_or_ps = True
                            break
                    if (api["perm"] in perms) and string_or_ps:
                        add_apis(api_findings, api["desc"], file_path)
                else:
                    print "\n[ERROR] API String Rule Match Error\n" + api
            else:
                print "\n[ERROR] API Rule Error\n", + api
    except:
        PrintException("[ERROR] Error in API Rule Processing")


def code_analysis(app_dir, md5, perms, typ):
    """Perform the code analysis."""
    try:
        print "[INFO] Static Android Code Analysis Started"
        code_findings = {}
        api_findings = {}
        email_n_file = []
        url_n_file = []
        url_list = []
        domains = {}

        if typ == "apk":
            java_src = os.path.join(app_dir, 'java_source/')
        elif typ == "studio":
            java_src = os.path.join(app_dir, 'app/src/main/java/')
        elif typ == "eclipse":
            java_src = os.path.join(app_dir, 'src/')
        print "[INFO] Code Analysis Started on - " + java_src
        # pylint: disable=unused-variable
        # Needed by os.walk
        for dir_name, sub_dir, files in os.walk(java_src):
            for jfile in files:
                jfile_path = os.path.join(java_src, dir_name, jfile)
                if "+" in jfile:
                    p_2 = os.path.join(java_src, dir_name,
                                       jfile.replace("+", "x"))
                    shutil.move(jfile_path, p_2)
                    jfile_path = p_2
                repath = dir_name.replace(java_src, '')
                if (
                        jfile.endswith('.java') and
                        any(re.search(cls, repath)
                            for cls in settings.SKIP_CLASSES) is False
                ):
                    dat = ''
                    with io.open(
                        jfile_path,
                        mode='r',
                        encoding="utf8",
                        errors="ignore"
                    ) as file_pointer:
                        dat = file_pointer.read()

                    # Code Analysis
                    # print "[INFO] Doing Code Analysis on - " + jfile_path
                    relative_java_path = jfile_path.replace(java_src, '')
                    code_rule_matcher(
                        code_findings, perms.keys(), dat, relative_java_path)
                    # API Check
                    api_rule_matcher(api_findings, perms.keys(),
                                     dat, relative_java_path)

                    # Initialize
                    urls = []
                    emails = []
                    # URLs Extraction My Custom regex
                    pattern = re.compile(
                        (
                            ur'((?:https?://|s?ftps?://|file://|javascript:|data:|www\d{0,3}[.])'
                            ur'[\w().=/;,#:@?&~*+!$%\'{}-]+)'
                        ),
                        re.UNICODE
                    )
                    urllist = re.findall(pattern, dat.lower())
                    url_list.extend(urllist)
                    uflag = 0
                    for url in urllist:
                        if url not in urls:
                            urls.append(url)
                            uflag = 1
                    if uflag == 1:
                        url_n_file.append(
                            {"urls": urls, "path": escape(relative_java_path)})

                    # Email Extraction Regex
                    regex = re.compile(r'[\w.-]+@[\w-]+\.[\w.]+')
                    eflag = 0
                    for email in regex.findall(dat.lower()):
                        if (email not in emails) and (not email.startswith('//')):
                            emails.append(email)
                            eflag = 1
                    if eflag == 1:
                        email_n_file.append(
                            {"emails": emails, "path": escape(relative_java_path)})

        # Domain Extraction and Malware Check
        print "[INFO] Performing Malware Check on extracted Domains"
        domains = malware_check(url_list)
        print "[INFO] Finished Code Analysis, Email and URL Extraction"
        code_an_dic = {
            'api': api_findings,
            'findings': code_findings,
            'urls': url_n_file,
            'domains': domains,
            'emails': email_n_file,
        }
        return code_an_dic
    except:
        PrintException("[ERROR] Performing Code Analysis")
