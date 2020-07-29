# -*- coding: utf_8 -*-
"""Module holding the functions for code analysis."""

import logging
from pathlib import Path

from django.conf import settings

from MobSF.utils import filename_from_path

from StaticAnalyzer.views.shared_func import (
    url_n_email_extract,
)
from StaticAnalyzer.views.sast_engine import scan

logger = logging.getLogger(__name__)


def code_analysis(app_dir, typ):
    """Perform the code analysis."""
    try:
        logger.info('Static Android Code Analysis Started')
        root = Path(settings.BASE_DIR) / 'StaticAnalyzer' / 'views'
        code_rules = root / 'android' / 'rules' / 'android_rules.yaml'
        api_rules = root / 'android' / 'rules' / 'android_apis.yaml'
        code_findings = {}
        api_findings = {}
        email_n_file = []
        url_n_file = []
        url_list = []
        app_dir = Path(app_dir)
        if typ == 'apk':
            src = app_dir / 'java_source'
        elif typ == 'studio':
            src = app_dir / 'app' / 'src' / 'main' / 'java'
            kt = app_dir / 'app' / 'src' / 'main' / 'kotlin'
            if not src.exists() and kt.exists():
                src = kt
        elif typ == 'eclipse':
            src = app_dir / 'src'
        src = src.as_posix() + '/'
        logger.info('Code Analysis Started on - %s',
                    filename_from_path(src))

        # Code and API Analysis
        code_findings = scan(
            code_rules.as_posix(),
            {'.java', '.kt'},
            [src],
            settings.SKIP_CLASS_PATH)
        api_findings = scan(
            api_rules.as_posix(),
            {'.java', '.kt'},
            [src],
            settings.SKIP_CLASS_PATH)

        skp = settings.SKIP_CLASS_PATH
        # Extract URLs and Emails
        for pfile in Path(src).rglob('*'):
            if (
                (pfile.suffix in ('.java', '.kt')
                    and any(skip_path in pfile.as_posix()
                            for skip_path in skp) is False)
            ):
                relative_java_path = pfile.as_posix().replace(src, '')
                urls, urls_nf, emails_nf = url_n_email_extract(
                    pfile.read_text('utf-8', 'ignore'), relative_java_path)
                url_list.extend(urls)
                url_n_file.extend(urls_nf)
                email_n_file.extend(emails_nf)
        logger.info('Finished Code Analysis, Email and URL Extraction')
        code_an_dic = {
            'api': api_findings,
            'findings': code_findings,
            'urls_list': url_list,
            'urls': url_n_file,
            'emails': email_n_file,
        }
        return code_an_dic
    except Exception:
        logger.exception('Performing Code Analysis')
