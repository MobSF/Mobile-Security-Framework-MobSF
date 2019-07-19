import io
import logging
import os
import shutil

from MalwareAnalyzer.views.domain_check import malware_check

from StaticAnalyzer.views.ios import ios_apis, ios_rules
from StaticAnalyzer.views.shared_func import (api_rule_matcher,
                                              code_rule_matcher,
                                              url_n_email_extract)

logger = logging.getLogger(__name__)


def ios_source_analysis(src):
    """IOS Objective-C Code Analysis."""
    try:
        logger.info('Starting iOS Source Code and PLIST Analysis')
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
                if jfile.endswith('.m'):

                    jfile_path = os.path.join(src, dirname, jfile)
                    if '+' in jfile:
                        new_path = os.path.join(
                            src, dirname, jfile.replace('+', 'x'))
                        shutil.move(jfile_path, new_path)
                        jfile_path = new_path
                    dat = ''
                    with io.open(jfile_path,
                                 mode='r',
                                 encoding='utf8',
                                 errors='ignore') as flip:
                        dat = flip.read()

                    # Code Analysis
                    relative_src_path = jfile_path.replace(src, '')
                    code_rule_matcher(code_findings, [], dat,
                                      relative_src_path, code_rules)
                    # API Analysis
                    api_rule_matcher(api_findings, [], dat,
                                     relative_src_path, api_rules)

                    # Extract URLs and Emails
                    urls, urls_nf, emails_nf = url_n_email_extract(
                        dat, relative_src_path)
                    url_list.extend(urls)
                    url_n_file.extend(urls_nf)
                    email_n_file.extend(emails_nf)
        urls_list = list(set(url_list))
        # Domain Extraction and Malware Check
        logger.info('Performing Malware Check on extracted Domains')
        domains = malware_check(urls_list)
        logger.info('Finished Code Analysis, Email and URL Extraction')
        code_analysis_dict = {
            'api': api_findings,
            'code_anal': code_findings,
            'urls_list': urls_list,
            'urlnfile': url_n_file,
            'domains': domains,
            'emailnfile': email_n_file,
        }
        return code_analysis_dict

    except Exception:
        logger.exception('iOS Source Code Analysis')
