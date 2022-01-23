import logging
from pathlib import Path
from enum import Enum

from django.conf import settings

from mobsf.MalwareAnalyzer.views.MalwareDomainCheck import (
    MalwareDomainCheck,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    url_n_email_extract,
)
from mobsf.StaticAnalyzer.views.sast_engine import scan

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
        root = Path(settings.BASE_DIR) / 'StaticAnalyzer' / 'views'
        swift_rules = root / 'ios' / 'rules' / 'swift_rules.yaml'
        objective_c_rules = root / 'ios' / 'rules' / 'objective_c_rules.yaml'
        api_rules = root / 'ios' / 'rules' / 'ios_apis.yaml'
        code_findings = {}
        api_findings = {}
        email_n_file = []
        url_n_file = []
        url_list = []
        domains = {}
        source_type = ''
        source_types = set()

        # Code and API Analysis
        code_findings = scan(
            objective_c_rules.as_posix(),
            {'.m'},
            [src],
            settings.SKIP_CLASS_PATH)
        if code_findings:
            source_types.add(_SourceType.objc)
        code_findings.update(scan(
            swift_rules.as_posix(),
            {'.swift'},
            [src],
            settings.SKIP_CLASS_PATH))
        if code_findings:
            source_types.add(_SourceType.swift)
        api_findings = scan(
            api_rules.as_posix(),
            {'.m', '.swift'},
            [src],
            settings.SKIP_CLASS_PATH)

        # Extract URLs and Emails
        skp = settings.SKIP_CLASS_PATH
        for pfile in Path(src).rglob('*'):
            if (
                (pfile.suffix in ('.m', '.swift')
                    and any(skip_path in pfile.as_posix()
                            for skip_path in skp) is False
                    and pfile.is_dir() is False)
            ):
                relative_java_path = pfile.as_posix().replace(src, '')
                urls, urls_nf, emails_nf = url_n_email_extract(
                    pfile.read_text('utf-8', 'ignore'), relative_java_path)
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
        domains = MalwareDomainCheck().scan(urls_list)
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
