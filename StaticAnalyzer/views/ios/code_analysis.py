import io
import logging
import os
import shutil
from enum import Enum

from MalwareAnalyzer.views.domain_check import malware_check

from StaticAnalyzer.views.ios.rules import (
    ios_apis,
    objc_rules,
    swift_rules,
)
from StaticAnalyzer.views.shared_func import (
    url_n_email_extract,
)
from StaticAnalyzer.views.sast_core.rule_matchers import (
    api_rule_matcher,
    code_rule_matcher,
)
from StaticAnalyzer.views.sast_core.matchers import MatchCommand

logger = logging.getLogger(__name__)


class _SourceType(Enum):
    swift = 'Swift'
    objc = 'Objective-C'
    swift_and_objc = 'Swift, Objective-C'
    nocode = 'No Code'


def ios_source_analysis(src):
    """IOS Objective-C and Swift Code Analysis."""
    try:
        logger.info('Starting iOS Source Code and PLIST Analysis')

        code_findings = {}
        api_findings = {}
        email_n_file = []
        url_n_file = []
        url_list = []
        domains = {}
        source_type = ''
        source_types = set()

        # Will inject the different pattern strategy
        # when it it will be requested
        match_command = MatchCommand()

        for dirname, _, files in os.walk(src):
            for jfile in files:

                if jfile.endswith('.m'):
                    api_rules = ios_apis.CODE_APIS
                    code_rules = objc_rules.OBJC_RULES
                    source_types.add(_SourceType.objc)
                elif jfile.endswith('.swift'):
                    api_rules = ios_apis.CODE_APIS
                    code_rules = swift_rules.SWIFT_RULES
                    source_types.add(_SourceType.swift)
                else:
                    continue

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
                                  relative_src_path, code_rules, match_command)
                # API Analysis
                api_rule_matcher(api_findings, [], dat,
                                 relative_src_path, api_rules, match_command)

                # Extract URLs and Emails
                urls, urls_nf, emails_nf = url_n_email_extract(
                    dat, relative_src_path)
                url_list.extend(urls)
                url_n_file.extend(urls_nf)
                email_n_file.extend(emails_nf)

        if not source_types:
            source_type = _SourceType.nocode.value
        elif len(source_types) > 1:
            source_type = _SourceType.swift_and_objc.value
        else:
            source_type = source_types.pop().value

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
            'source_type': source_type,
        }
        return code_analysis_dict

    except Exception:
        logger.exception('iOS Source Code Analysis')
