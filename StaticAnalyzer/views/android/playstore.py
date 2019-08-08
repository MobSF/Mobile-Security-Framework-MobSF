# -*- coding: utf_8 -*-
from google_play_scraper import app

from bs4 import BeautifulSoup

import logging

logger = logging.getLogger(__name__)


def get_app_details(package_id):
    """Get App Details form PlayStore."""
    try:
        logger.info('Fetching Details from Play Store: %s', package_id)
        det = app(package_id)
        det.pop('descriptionHTML', None)
        det.pop('comments', None)
        description = BeautifulSoup(det['description'], features='lxml')
        det['description'] = description.get_text()
        det['error'] = False
    except Exception:
        logger.warning('Unable to get app details.')
        det = {'error': True}
    return det
