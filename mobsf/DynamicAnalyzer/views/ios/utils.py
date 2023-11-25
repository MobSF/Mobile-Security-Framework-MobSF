"""iOS Dynamic Analysis common utils."""

import re
import logging

from django.conf import settings


logger = logging.getLogger(__name__)
SALT = 'i0s_m0bsf'


def is_instance_id(user_input):
    """Check if string is valid instance id."""
    reg = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    stat = re.match(reg, user_input)
    if not stat:
        logger.error('Invalid instance identifier')
    return stat


def common_check(instance_id):
    """Common checks for instance APIs."""
    if not getattr(settings, 'CORELLIUM_API_KEY', ''):
        return {
            'status': 'failed',
            'message': 'Missing Corellium API key'}
    elif not is_instance_id(instance_id):
        return {
            'status': 'failed',
            'message': 'Invalid instance identifier'}
    else:
        return None
