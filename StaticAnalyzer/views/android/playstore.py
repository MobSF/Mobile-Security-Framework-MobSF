# -*- coding: utf_8 -*-
import play_scraper

import logging
logger = logging.getLogger(__name__)


def get_app_details(package_id):
    '''Get App Details form PlayStore'''
    try:
        logger.info("Fetching Details from Play Store: %s", package_id)
        det = play_scraper.details(package_id)
        det["error"] = False
    except Exception as exp:
        logger.warning("Unable to get app details. %s", exp)
        det = {"error": True}
    return det
