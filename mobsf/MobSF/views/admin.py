# -*- coding: utf_8 -*-
import base64
import hashlib
import logging
import os
import traceback as tb
import datetime
import json

from django.conf import settings
from django.shortcuts import render
from django.views.decorators.http import require_http_methods
from django.http import HttpResponse, HttpResponseRedirect

from mobsf.StaticAnalyzer.models import ApiKeys
from mobsf.MobSF.utils import (
    error_response,
    is_admin,
    sso_email,
    utcnow,
    utc_inc_years,
    utc_inc_90days,    
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
        EXPIRE_DATE=expire_date,
    )
    new_db_obj.save()
    logger.info('New API key %s... created for %s', api_key[0:5], email)
    return (api_key, new_db_obj)


def get_api_keys():
    return ApiKeys.objects.all().values().order_by('EXPIRE_DATE')

def delete_api_key(hash):
    db_obj = ApiKeys.objects.get(pk = hash)
    return db_obj.delete()    

def admin_view(request):
    if (not is_admin(request)):
        return error_response(request, 'Unauthorized')
    min = utc_inc_90days()
    default_exp_date = utc_inc_years(1)
    max = utc_inc_years(1)
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
        'sso_email': sso_email(request),
        'min_date': min.strftime("%Y-%m-%d"),
        'max_date': max.strftime("%Y-%m-%d"),
        'default_exp_date': default_exp_date.strftime("%Y-%m-%d"),
        'version': settings.MOBSF_VER,
        'tenant_static': settings.TENANT_STATIC_URL,
    }
    template = 'general/admin.html'
    return render(request, template, context)


@require_http_methods(['POST']) 
def create_api_key_post(request): #does this need ,api=False???
    try:
        if (not is_admin(request)):
            return error_response(request, 'Unauthorized')

        default_expire_date = utcnow()
        default_expire_date.replace(year=default_expire_date.year + 1)
        # Validate input parameters
        description = request.POST['description']
        email = request.POST['email']
        role = request.POST['role']
        expire_date = request.POST['expire_date']
        full_date_str = expire_date + " 12:00:00.000000 +0000"
        aware_date = datetime.datetime.strptime(full_date_str, "%Y-%m-%d %H:%M:%S.%f %z")

        if not description:
            return error_response(request, 'Missing parameter: description')
        api_key, db_obj = create_api_key(description, email, role, aware_date) ##strftime("%Y-%m-%d %H:%M:%S.%f%Z") '%Y-%m-%d %H:%M:%S.%f%Z
        payload = {"api_key": api_key}
        return HttpResponse(json.dumps(payload),
                            content_type='application/json',
                            status=200)                 
        #return HttpResponse(api_key)
        #return create_api_key(description, email, role, aware_date) ##strftime("%Y-%m-%d %H:%M:%S.%f%Z") '%Y-%m-%d %H:%M:%S.%f%Z

    except Exception as exp:
        exmsg = ''.join(tb.format_exception(None, exp, exp.__traceback__))
        logger.error(exmsg)
        msg = str(exp)
        exp_doc = exp.__doc__
        return error_response(request, msg, False, exp_doc)
    
@require_http_methods(['POST']) 
def delete_api_key_post(request): #does this need ,api=False???
    try:
        if (not is_admin(request)):
            return error_response(request, 'Unauthorized')

        hash = request.POST['id']
        
        if not hash:
            return error_response(request, 'Missing parameter: key_hash')
        count, item = delete_api_key(hash)
        logger.info('%s API Key(s) deleted by: %s',count, sso_email(request))
        logger.info('API Key deleted: %s',item )
        payload = {"keys_removed": count}
        return HttpResponse(json.dumps(payload),
                        content_type='application/json',status=200)                 
        #return HttpResponse(api_key)
        #return create_api_key(description, email, role, aware_date) ##strftime("%Y-%m-%d %H:%M:%S.%f%Z") '%Y-%m-%d %H:%M:%S.%f%Z

    except Exception as exp:
        exmsg = ''.join(tb.format_exception(None, exp, exp.__traceback__))
        logger.error(exmsg)
        msg = str(exp)
        exp_doc = exp.__doc__
        return error_response(request, msg, False, exp_doc)