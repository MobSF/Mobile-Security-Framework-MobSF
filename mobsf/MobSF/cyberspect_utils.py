
import datetime
import base64
import logging
import os

import siphash

from django.conf import settings
from django.forms.models import model_to_dict
from django.utils import timezone
from django.http import JsonResponse
from django.core.handlers.wsgi import WSGIRequest

from mobsf.StaticAnalyzer.models import RecentScansDB

logger = logging.getLogger(__name__)


def make_api_response(data, status=200):
    """Make API response."""
    resp = JsonResponse(
        data=data,  # lgtm [py/stack-trace-exposure]
        status=status)
    resp['Content-Type'] = 'application/json; charset=utf-8'
    return resp


def is_admin(request):
    """Check if a user is admin."""
    if (not isinstance(request, WSGIRequest)):
        return False
    if ('role' in request.META and request.META['role'] == 'FULL_ACCESS'):
        return True
    if (not settings.ADMIN_USERS):
        return False
    if ('email' not in request.META):
        return False
    email = request.META['email']
    if (email and email in settings.ADMIN_USERS.split(',')):
        return True
    return False


def sso_email(request):
    """Get user email from SSO."""
    if ('email' in request.META) and (request.META['email']):
        return request.META['email']
    else:
        return None


def get_siphash(data):
    """Generate SipHash."""
    data_bytes = bytes.fromhex(data)
    tenant_id = os.getenv('TENANT_ID', 'df73ea3d2b91442a903b6043399b1353')
    sip = siphash.SipHash_2_4(bytes.fromhex(tenant_id), data_bytes)
    response = base64.b64encode(sip.digest()).decode('utf8').replace('=', '')
    return response


def get_usergroups(request):
    """Get user groups from SSO."""
    if (is_admin(request)):
        return settings.ADMIN_GROUP
    else:
        return settings.GENERAL_GROUP


def model_to_dict_str(instance):
    """Convert model to dict with string values."""
    result = model_to_dict(instance)
    for key, value in result.items():
        result[key] = str(value)
    return result


def tz(value):
    """Format datetime object with timezone."""
    if isinstance(value, datetime.datetime):
        return value.replace(tzinfo=datetime.timezone.utc)
    # Parse string into time zone aware datetime
    value = str(value).replace('T', ' ').replace('Z', '').replace('+00:00', '')
    unware_time = datetime.datetime.strptime(value, '%Y-%m-%d %H:%M:%S.%f')
    return unware_time.replace(tzinfo=datetime.timezone.utc)


def update_scan_timestamp(scan_hash):
    # Update the last scan time.
    tms = timezone.now()
    RecentScansDB.objects.filter(MD5=scan_hash).update(TIMESTAMP=tms)


def utcnow():
    """Return timezone aware UTC now."""
    return datetime.datetime.now(datetime.timezone.utc)
