# -*- coding: utf_8 -*-
import logging
from urllib.parse import urlencode

from django.conf import settings

from mobsf.MobSF.security import (
    safe_request,
    sanitize_for_logging,
)
from mobsf.MobSF.utils import (
    append_scan_status,
    strict_package_check,
    upstream_proxy,
)

logger = logging.getLogger(__name__)


def app_search(checksum, app_id):
    """IOS Get App Details from App Store."""
    if not isinstance(app_id, str) or not strict_package_check(app_id):
        logger.warning(
            'Invalid bundle identifier for App Store lookup: %s',
            sanitize_for_logging(str(app_id)))
        return {'error': True}
    msg = f'Fetching Details from App Store: {app_id}'
    logger.info(msg)
    append_scan_status(checksum, msg)
    lookup_url = settings.ITUNES_URL
    query = urlencode({
        'bundleId': app_id,
        'country': 'us',
        'entity': 'software',
    })
    req_url = f'{lookup_url}?{query}'
    headers = {
        'User-Agent': ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) '
                       'AppleWebKit/537.36 (KHTML, like Gecko) '
                       'Chrome/39.0.2171.95 Safari/537.36')}
    try:
        det = {}
        proxies, verify = upstream_proxy('https')
        req = safe_request(
            'GET',
            req_url,
            timeout=5,
            max_response_size=2 * 1024 * 1024,
            headers=headers,
            proxies=proxies,
            verify=verify)
        resp = req.json()
        if resp['results']:
            det = resp['results'][0]
            return {
                'features': det['features'] or [],
                'icon': (det['artworkUrl512']
                         or det['artworkUrl100']
                         or det['artworkUrl60'] or ''),
                'developer_id': det['artistId'],
                'developer': det['artistName'],
                'developer_url': det['artistViewUrl'],
                'developer_website': det['sellerUrl'],
                'supported_devices': det['supportedDevices'],
                'title': det['trackName'],
                'app_id': det['bundleId'],
                'category': det['genres'] or [],
                'description': det['description'],
                'price': det['price'],
                'itunes_url': det['trackViewUrl'],
                'score': det['averageUserRating'],
                'error': False,
            }
        logger.warning('Unable to get app details.')
        return {'error': True}
    except Exception as exp:
        msg = 'Failed to get app details'
        logger.warning(msg)
        append_scan_status(checksum, msg, repr(exp))
        return {'error': True}
