# -*- coding: utf_8 -*-
from google_play_scraper import app

from bs4 import BeautifulSoup

import requests

import logging

from django.conf import settings

from mobsf.MobSF.utils import (
    append_scan_status,
    upstream_proxy,
)

logger = logging.getLogger(__name__)


def get_app_details(app_dic, man_data):
    """Get App Details form PlayStore."""
    checksum = app_dic['md5']
    app_dic['playstore'] = {
        'error': True,
        'description': 'Failed to identify the package name',
    }
    try:
        # Check if Google Play Store is reachable
        # The library can cause timeout issue behind proxy
        try:
            proxies, verify = upstream_proxy('https')
            requests.get(settings.PLAYSTORE,
                         timeout=5,
                         proxies=proxies,
                         verify=verify)
        except Exception:
            logger.warning('Google Play Store is not reachable.'
                           ' Skipping Play Store lookup.')
            return

        if man_data.get('packagename'):
            package_id = man_data['packagename']
        elif app_dic.get('apk_features', {}).get('package'):
            package_id = app_dic['apk_features']['package']
        else:
            logger.warning('Package Name not found')
            return
        msg = f'Fetching Details from Play Store: {package_id}'
        logger.info(msg)
        append_scan_status(checksum, msg)
        det = app(package_id)
        det.pop('descriptionHTML', None)
        det.pop('comments', None)
        description = BeautifulSoup(det['description'], features='lxml')
        det['description'] = description.get_text()
        det['error'] = False
        if 'androidVersionText' not in det:
            det['androidVersionText'] = ''
    except Exception:
        det = app_search(checksum, package_id)
    app_dic['playstore'] = det


def app_search(checksum, app_id):
    """Get App Details from AppMonsta."""
    det = {'error': True}
    if not settings.APPMONSTA_API:
        return det
    msg = f'Fetching Details from AppMonsta: {app_id}'
    append_scan_status(checksum, msg)
    logger.info(msg)
    lookup_url = settings.APPMONSTA_URL
    req_url = '{}{}.json?country={}'.format(
        lookup_url, app_id, 'US')
    headers = {
        'User-Agent': ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) '
                       'AppleWebKit/537.36 (KHTML, like Gecko) '
                       'Chrome/39.0.2171.95 Safari/537.36'),
        'Accept-Encoding': 'deflate, gzip'}
    try:
        proxies, verify = upstream_proxy('https')
        req = requests.get(req_url,
                           timeout=5,
                           auth=(settings.APPMONSTA_API, 'X'),
                           headers=headers,
                           proxies=proxies,
                           verify=verify,
                           stream=True)
        resp = req.json()
        det['title'] = resp['app_name']
        det['score'] = resp.get('all_rating', '')
        det['installs'] = resp.get('downloads', '')
        det['price'] = resp.get('price', '')
        det['androidVersionText'] = resp.get('requires_os', '')
        det['genre'] = resp.get('genre', '')
        det['url'] = resp.get('store_url', '')
        det['developer'] = resp.get('publisher_name', '')
        det['developerId'] = resp.get('publisher_id', '')
        det['developerAddress'] = resp.get('publisher_address', '')
        det['developerWebsite'] = resp.get('publisher_url', '')
        det['developerEmail'] = resp.get('publisher_email', '')
        det['released'] = resp.get('release_date', '')
        det['privacyPolicy'] = resp.get('privacy_url', '')
        description = BeautifulSoup(resp.get('description', ''),
                                    features='lxml')
        det['description'] = description.get_text()
        det['error'] = False
        return det
    except Exception as exp:
        msg = 'Unable to get app details'
        append_scan_status(checksum, msg, repr(exp))
        logger.warning(msg)
        return det
