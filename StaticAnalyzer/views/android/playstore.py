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
	except ValueError as vxp:
		logger.warning("%s", vxp)
		det = {"error": True}
	return det