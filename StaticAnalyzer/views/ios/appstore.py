# -*- coding: utf_8 -*-
import requests

import logging
logger = logging.getLogger(__name__)


def app_search(app_id):
    '''iOS Get App Details from App Store'''
    logger.info("Fetching Details from App Store: %s", app_id)
    lookup_url = 'https://itunes.apple.com/lookup'
    req_url = '{}?bundleId={}&country={}&entity=software'.format(
        lookup_url, app_id, 'us')
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
    try:
        req = requests.get(req_url, headers=headers)
        resp = req.json()
        if resp['results']:
            det = resp['results'][0]
        return {
            'features': det['features'] or [],
            'icon': det['artworkUrl512'] or det['artworkUrl100'] or det['artworkUrl60'] or '',
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
    except Exception as exp:
        logger.warning('Unable to get app details')
        return {'error': True}