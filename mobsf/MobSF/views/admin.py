# -*- coding: utf_8 -*-
import base64
import hashlib
import logging
import os
import traceback as tb

from django.conf import settings
from django.shortcuts import render
from django.views.decorators.http import require_http_methods

from mobsf.StaticAnalyzer.models import ApiKeys
from mobsf.MobSF.utils import (
    error_response,
    is_admin,
    sso_email,
    tz,
    utcnow,
)

logger = logging.getLogger(__name__)

def create_api_key(description, email, role, expire_date):
    """Create new APIKeys record."""
    random_bytes = os.urandom(32)
    api_key = base64.b64encode(random_bytes).decode('utf-8').replace('=', '')
    key_hash = hashlib.sha256(api_key.encode('utf-8')).hexdigest()
    new_db_obj = ApiKeys(
        KEY_HASH=key_hash,
        KEY_PREFIX=api_key[0:5],
        DESCRIPTION=description,
        EMAIL=email,
        ROLE=role,
        CREATE_DATE=utcnow(),
        EXPIRE_DATE=expire_date
    )
    new_db_obj.save()
    logger.info('New API key %s... created for %s', api_key[0:5], email)
    return (api_key, new_db_obj)


def get_api_keys():
    return ApiKeys.objects.all().values().order_by('EXPIRE_DATE')


def admin_view(request):
    if (not is_admin(request)):
        return error_response(request, 'Unauthorized')
    entries = []
    api_keys = get_api_keys()
    for entry in api_keys:
        if entry["ROLE"] == 1:
            entry["ROLE"] = "UPLOAD_ONLY"
        elif entry["ROLE"] == 2:
            entry["ROLE"] = "READ_ONLY"
        elif entry["ROLE"] == 3:
            entry["ROLE"] = "FULL_ACCESS"
        else:
            entry["ROLE"] = "NO_ACCESS"
        entry["KEY_PREFIX"] = entry["KEY_PREFIX"] + "******"
        entries.append(entry)
    context = {
        'title': 'Admin Settings',
        'entries': entries,
        'version': settings.MOBSF_VER,
        'tenant_static': settings.TENANT_STATIC_URL,
    }
    template = 'general/admin.html'
    return render(request, template, context)


@require_http_methods(['POST'])
def create_api_key_post(request):    
    try:
        if (not is_admin(request)):
            return error_response(request, 'Unauthorized')
    
        default_expire_date = utcnow()
        default_expire_date.replace(year=default_expire_date.year + 1)
        # Validate input parameters
        description = request.POST.get('description', '')
        email = request.POST.get('email', sso_email(request))
        role = request.POST.get('role', '') # Need to set default role
        expire_date = request.POST.get('expire_date', default_expire_date)

        if not description:
            return error_response(request, 'Missing parameter: description')
        
        return create_api_key(description, email, tz(role), expire_date)

    except Exception as exp:
        exmsg = ''.join(tb.format_exception(None, exp, exp.__traceback__))
        logger.error(exmsg)
        msg = str(exp)
        exp_doc = exp.__doc__
        return error_response(request, msg, False, exp_doc)