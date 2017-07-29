import os
import io
import shutil

from StaticAnalyzer.views.shared_func import (
    url_n_email_extract,
    api_rule_matcher,
    code_rule_matcher,
)
from StaticAnalyzer.views.ios import (
    ios_rules,
    ios_apis
)
from MalwareAnalyzer.views import malware_check
from MobSF.utils import (
    PrintException,
)


def ios_source_analysis(src):
    """iOS Objective-C Code Analysis"""
    try:
        print "[INFO] Starting iOS Source Code and PLIST Analysis"
        api_rules = ios_apis.CODE_APIS
        code_rules = ios_rules.CODE_RULES
        code_findings = {}
        api_findings = {}  
        email_n_file = []
        url_n_file = []
        url_list = []
        domains = {}

        for dirname, _, files in os.walk(src):
            for jfile in files:
                if jfile.endswith(".m"):

                    jfile_path = os.path.join(src, dirname, jfile)
                    if "+" in jfile:
                        new_path = os.path.join(
                            src, dirname, jfile.replace("+", "x"))
                        shutil.move(jfile_path, new_path)
                        jfile_path = new_path
                    dat = ''
                    with io.open(jfile_path, mode='r', encoding="utf8", errors="ignore") as flip:
                        dat = flip.read()

                    # Code Analysis
                    relative_src_path = jfile_path.replace(src, '')
                    code_rule_matcher(code_findings, [], dat, relative_src_path, code_rules)
                    # API Analysis
                    api_rule_matcher(api_findings, [], dat, relative_src_path, api_rules)

                    # Extract URLs and Emails
                    urls, urls_nf, emails_nf = url_n_email_extract(dat, relative_src_path)
                    url_list.extend(urls)
                    url_n_file.extend(urls_nf)
                    email_n_file.extend(emails_nf)      
        # Domain Extraction and Malware Check
        print "[INFO] Performing Malware Check on extracted Domains"
        domains = malware_check(list(set(url_list)))
        print "[INFO] Finished Code Analysis, Email and URL Extraction"
        code_analysis_dict = {
            'api': api_findings,
            'code_anal': code_findings,
            'urlnfile': url_n_file,
            'domains': domains,
            'emailnfile': email_n_file,
        }
        return code_analysis_dict

    except:
        PrintException("[ERROR] iOS Source Code Analysis")
