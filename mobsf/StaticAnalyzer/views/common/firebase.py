"""Firebase Analysis."""
import logging
from urllib.parse import urlparse

from mobsf.MobSF.utils import (
    append_scan_status,
    upstream_proxy,
    valid_host,
)

import requests


logger = logging.getLogger(__name__)
HIGH = 'high'
WARNING = 'warning'
INFO = 'info'
SECURE = 'secure'
FIREBASE_FINDINGS = {
    'firebase_db_open': {
        'title': 'Open Firebase database',
        'severity': HIGH,
        'description': (
            'The Firebase database at %s is exposed'
            ' to internet without any authentication'),
    },
    'firebase_db_exists': {
        'title': 'App talks to a Firebase database',
        'severity': INFO,
        'description': 'The app talks to Firebase database at %s',
    },
    'firebase_remote_config_enabled': {
        'title': 'Firebase Remote Config enabled',
        'severity': WARNING,
        'description': (
            'The Firebase Remote Config at %s is enabled.'
            ' Ensure that the configurations are not sensitive.'
            ' This is indicated by the response:\n\n%s'),
    },
    'firebase_remote_config_disabled': {
        'title': 'Firebase Remote Config disabled',
        'severity': SECURE,
        'description': (
            'Firebase Remote Config is disabled for %s.',
            ' This is indicated by the response:\n\n%s'),
    },
    'firebase_remote_config_failed': {
        'title': 'Firebase Remote Config check failed',
        'description': (
            'Failed to check for Firebase Remote Config.'
            ' Please verify this manually. Error:\n\n%s'),
        'severity': INFO,
    },
}


def firebase_analysis(checksum, code_an_dic):
    """Firebase Analysis."""
    urls = list(set(code_an_dic['urls_list']))
    findings = []
    finds = None
    logger.info('Starting Firebase Analysis')
    # Check for Firebase Database
    logger.info('Looking for Firebase URL(s)')
    for url in urls:
        if 'firebaseio.com' not in url:
            continue
        returl, is_open = open_firebase(checksum, url)
        if is_open:
            item = FIREBASE_FINDINGS['firebase_db_open']
            item['description'] = item['description'] % returl
            findings.append(item)
        else:
            item = FIREBASE_FINDINGS['firebase_db_exists']
            item['description'] = item['description'] % returl
            findings.append(item)
    # Check for Firebase Remote Config
    firebase_creds = code_an_dic.get('firebase_creds')
    finds = firebase_remote_config(checksum, firebase_creds)
    if finds:
        findings.extend(finds)
    return findings


def open_firebase(checksum, url):
    # Detect Open Firebase Database
    try:
        invalid = 'Invalid Firebase URL'
        if not valid_host(url):
            logger.warning(invalid)
            return url, False
        purl = urlparse(url)
        if not purl.netloc.endswith('firebaseio.com'):
            logger.warning(invalid)
            return url, False
        base_url = '{}://{}/.json'.format(purl.scheme, purl.netloc)
        proxies, verify = upstream_proxy('https')
        headers = {
            'User-Agent': ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1)'
                           ' AppleWebKit/537.36 (KHTML, like Gecko) '
                           'Chrome/39.0.2171.95 Safari/537.36')}
        resp = requests.get(base_url, headers=headers,
                            proxies=proxies, verify=verify,
                            allow_redirects=False)
        if resp.status_code == 200:
            return base_url, True
    except Exception as exp:
        msg = 'Open Firebase DB detection failed'
        logger.warning(msg)
        append_scan_status(checksum, msg, repr(exp))
    return url, False


def firebase_remote_config(checksum, creds):
    """Check for Firebase Remote Config."""
    url = None
    findings = []
    try:
        if not creds:
            return None
        google_api_key = creds.get('google_api_key')
        google_app_id = creds.get('google_app_id')

        if not (google_app_id and google_api_key):
            return None

        project_id = google_app_id.split(':')[1]
        if not project_id.isnumeric():
            return None

        # https://docs.emergetools.com/docs/firebase-remote-config-api-exposed
        # https://blog.deesee.xyz/android/automation/2019/08/03/
        # firebase-remote-config-dump.html
        logger.info('Checking for Firebase Remote Config')
        url = (f'https://firebaseremoteconfig.googleapis.com/v1/projects/'
               f'{project_id}/namespaces/firebase:fetch?key={google_api_key}')

        body = {
            'appId': google_app_id,
            'appInstanceId': 'required_but_unused_value',
        }

        proxies, verify = upstream_proxy('https')
        response = requests.post(
            url,
            timeout=4,
            json=body,
            proxies=proxies,
            verify=verify,
            allow_redirects=False)

        if response.status_code == 200:
            resp = response.json()
            if resp.get('state') == 'NO_TEMPLATE':
                item = FIREBASE_FINDINGS['firebase_remote_config_disabled']
                item['description'] = item['description'] % (url, resp)
                findings.append(item)
            else:
                item = FIREBASE_FINDINGS['firebase_remote_config_enabled']
                item['description'] = item['description'] % (url, resp)
                findings.append(item)
        else:
            item = FIREBASE_FINDINGS['firebase_remote_config_disabled']
            response_msg = f'The response code is {response.status_code}'
            item['description'] = item['description'] % (url, response_msg)
            findings.append(item)
    except Exception as exp:
        msg = 'Failed to check for Firebase Remote Config'
        logger.warning(msg)
        append_scan_status(checksum, msg, repr(exp))
        item = FIREBASE_FINDINGS['firebase_remote_config_failed']
        item['description'] = item['description'] % repr(exp)
        findings.append(item)
    return findings
