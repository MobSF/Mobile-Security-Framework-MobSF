# -*- coding: utf_8 -*-
"""iOS Dynamic Analysis."""
import logging
import json
from pathlib import Path

from mobsf.DynamicAnalyzer.views.common.shared import (
    extract_urls_domains_emails,
    get_app_files,
)

logger = logging.getLogger(__name__)


def get_screenshots(checksum, download_dir):
    """Get Screenshots."""
    screenshots = []
    screen_dir = Path(download_dir)
    for img in screen_dir.glob('*.png'):
        if (img.name.startswith(checksum)
                and 'sshot' in img.name):
            screenshots.append(img.name)
    return screenshots


def get_logs_data(app_dir, bundle_id):
    """Get Data for analysis."""
    data = []
    dump_file = Path(app_dir) / 'mobsf_dump_file.txt'
    fd_log_file = Path(app_dir) / 'mobsf_frida_out.txt'
    flows = Path.home() / '.httptools' / 'flows'
    web_file = flows / f'{bundle_id}.flow.txt'
    if dump_file.exists():
        data.append(dump_file.read_text('utf-8', 'ignore'))
    if fd_log_file.exists():
        data.append(fd_log_file.read_text('utf-8', 'ignore'))
    if web_file.exists():
        data.append(web_file.read_text('utf-8', 'ignore'))
    return '\n'.join(data)


def run_analysis(app_dir, bundle_id, checksum):
    """Run Dynamic File Analysis."""
    analysis_result = {}
    logger.info('Dynamic File Analysis')
    domains = {}
    # Collect Log data
    data = get_logs_data(app_dir, bundle_id)
    urls, domains, emails = extract_urls_domains_emails(
        checksum,
        data)
    # App data files analysis
    pfiles = get_app_files(app_dir, f'{checksum}-app-container')
    analysis_result['sqlite'] = pfiles['sqlite']
    analysis_result['plist'] = pfiles['plist']
    analysis_result['others'] = pfiles['others']
    analysis_result['urls'] = urls
    analysis_result['domains'] = domains
    analysis_result['emails'] = list(emails)
    return analysis_result


def ios_api_analysis(app_dir):
    """The iOS API Analysis."""
    dump = {
        'cookies': [],
        'crypto': [],
        'network': [],
        'files': [],
        'keychain': [],
        'logs': [],
        'credentials': [],
        'userdefaults': {},
        'pasteboard': [],
        'textinputs': [],
        'datadir': [],
        'sql': [],
        'json': [],
    }
    try:
        dump_file = app_dir / 'mobsf_dump_file.txt'
        if not dump_file.exists():
            return dump
        logger.info('Analyzing Frida Data Dump')
        data = dump_file.read_text(
            encoding='utf-8',
            errors='ignore').splitlines()
        for line in data:
            parsed = json.loads(line)
            if parsed.get('cookies'):
                dump['cookies'] = parsed['cookies']
            elif parsed.get('crypto'):
                dump['crypto'].append(parsed['crypto'])
            elif parsed.get('filename'):
                dump['files'].append(parsed['filename'])
            elif parsed.get('keychain'):
                dump['keychain'] = parsed['keychain']
            elif parsed.get('nslog'):
                dump['logs'].append(parsed['nslog'])
            elif parsed.get('credentialstorage'):
                dump['credentials'] = parsed['credentialstorage']
            elif parsed.get('nsuserdefaults'):
                dump['userdefaults'] = parsed['nsuserdefaults']
            elif (parsed.get('pasteboard')
                    and parsed.get('pasteboard') not in dump['pasteboard']):
                dump['pasteboard'].append(parsed['pasteboard'])
            elif parsed.get('textinput'):
                dump['textinputs'].append(parsed['textinput'])
            elif parsed.get('network'):
                dump['network'].append(parsed['network'])
            elif parsed.get('datadir'):
                dump['datadir'] = parsed['datadir']
            elif parsed.get('sql'):
                dump['sql'].append(parsed['sql'])
            elif parsed.get('json'):
                dump['json'].append(parsed['json'])
            dump['files'] = list(set(dump['files']))
            dump['logs'] = list(set(dump['logs']))
            if len(dump['network']) > 0:
                dump['network'] = list(
                    {v['url']: v for v in dump['network']}.values())
    except Exception:
        logger.exception('Analyzing dump data failed')
    return dump
