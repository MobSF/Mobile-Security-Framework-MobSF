# -*- coding: utf_8 -*-
import base64
import hashlib
import logging
import os
import traceback as tb
import datetime
import json
import re

from django.conf import settings
from django.shortcuts import render
from django.views.decorators.http import require_http_methods
from django.http import HttpResponse

from mobsf.StaticAnalyzer.models import ApiKeys
from mobsf.MobSF.utils import (
    is_admin,
    print_n_send_error_response,
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
        EXPIRE_DATE=expire_date,
    )
    new_db_obj.save()
    logger.info('New API key %s... created for %s', api_key[0:5], email)
    return (api_key, new_db_obj)


def get_api_keys():
    return ApiKeys.objects.filter(REVOKED_DATE=None).values() \
        .order_by('EXPIRE_DATE')


def revoke_api_key(key_id):
    db_obj = ApiKeys.objects.get(ID=key_id)
    if db_obj:
        db_obj.REVOKED_DATE = utcnow()
        db_obj.save()
        return db_obj
    return None


def edit_api_key(key_id, description, email, role, expire_date):
    db_obj = ApiKeys.objects.get(ID=key_id)
    logger.info('API key ID %s edited by: %s', key_id, email)
    if db_obj:
        db_obj.REVOKED_DATE = None
        db_obj.DESCRIPTION = description
        db_obj.EMAIL = email
        db_obj.ROLE = role
        db_obj.EXPIRE_DATE = expire_date
        db_obj.save()
        return db_obj
    return None


def admin_view(request):
    if (not is_admin(request)):
        return print_n_send_error_response(request, 'Unauthorized')
    min_exp_date = utcnow() + datetime.timedelta(days=1)
    max_exp_date = utcnow() + datetime.timedelta(days=365)
    default_exp_date = utcnow() + datetime.timedelta(days=90)
    print(min_exp_date)
    print(max_exp_date)
    print(default_exp_date)
    entries = []
    api_keys = get_api_keys()
    for entry in api_keys:
        entry['ROLE_NAME'] = ApiKeys.Role(entry['ROLE']).name
        entry['KEY_PREFIX'] = entry['KEY_PREFIX'] + '******'
        entry['KEY_HASH'] = None
        entry['EXPIRED'] = entry['EXPIRE_DATE'] <= utcnow()
        entries.append(entry)
    context = {
        'title': 'Admin Settings',
        'entries': entries,
        'sso_email': sso_email(request),
        'min_date': min_exp_date.strftime('%Y-%m-%d'),
        'max_date': max_exp_date.strftime('%Y-%m-%d'),
        'default_exp_date': default_exp_date.strftime('%Y-%m-%d'),
        'version': settings.MOBSF_VER,
        'is_admin': is_admin(request),
    }
    template = 'general/admin.html'
    return render(request, template, context)


@require_http_methods(['POST'])
def create_api_key_post(request):
    try:
        if (not is_admin(request)):
            return print_n_send_error_response(request, 'Unauthorized')

        max_date = utcnow() + datetime.timedelta(days=365)
        # Validate input parameters
        description = request.POST['description']
        email = request.POST['email']
        role = request.POST['role']
        expire_date = request.POST['expire_date']
        full_date_str = expire_date + ' 00:00:00.001000 UTC'
        aware_date = datetime.datetime.strptime(full_date_str,
                                                '%Y-%m-%d %H:%M:%S.%f %Z')

        if not description:
            payload = {'msg': 'Missing parameter: description'}
            return HttpResponse(json.dumps(payload),
                                content_type='application/json', status=200)
        regx = ('^[\W]*([\w+\-.%]+@[\w\-.]+\.[A-Za-z]{2,4}[\W]*,{1}[\W]*)*'
                '([\w+\-.%]+@[\w\-.]+\.[A-Za-z]{2,4})[\W]*$')
        if not re.search(regx, email):
            payload = {'msg': 'Invalid email address was entered.'}
            return HttpResponse(json.dumps(payload),
                                content_type='application/json', status=200)
        if tz(aware_date) < tz(utcnow()):
            payload = {'msg': ('Invalid date was entered, '
                               'it must fall within the next year.')}
            return HttpResponse(json.dumps(payload),
                                content_type='application/json', status=200)
        if tz(aware_date) > tz(max_date):
            payload = {'msg': ('Invalid date was entered, '
                               'it must fall within the next year.')}
            return HttpResponse(json.dumps(payload),
                                content_type='application/json', status=200)
        api_key, db_obj = create_api_key(description, email, role,
                                         tz(aware_date))
        payload = {'api_key': api_key}
        return HttpResponse(json.dumps(payload),
                            content_type='application/json',
                            status=200)

    except Exception as exp:
        exmsg = ''.join(tb.format_exception(None, exp, exp.__traceback__))
        logger.error(exmsg)
        msg = str(exp)
        exp_doc = exp.__doc__
        return print_n_send_error_response(request, msg, False, exp_doc)


@require_http_methods(['POST'])
def revoke_api_key_post(request):
    try:
        if (not is_admin(request)):
            return print_n_send_error_response(request, 'Unauthorized')

        key_id = request.POST['id']
        if not key_id:
            return print_n_send_error_response(request,
                                               'Missing parameter: id')
        item = revoke_api_key(key_id)
        if item:
            logger.info('API key ID %s revoked by: %s', key_id,
                        sso_email(request))
            return HttpResponse('{}', content_type='application/json',
                                status=202)
        else:
            logger.info('Unable to find API key %s to revoke', key_id)
            return HttpResponse(json.dumps(key_id),
                                content_type='application/json', status=404)

    except Exception as exp:
        exmsg = ''.join(tb.format_exception(None, exp, exp.__traceback__))
        logger.error(exmsg)
        msg = str(exp)
        exp_doc = exp.__doc__
        return print_n_send_error_response(request, msg, False, exp_doc)


@require_http_methods(['POST'])
def edit_api_key_post(request):
    try:
        if (not is_admin(request)):
            return print_n_send_error_response(request, 'Unauthorized')

        max_date = utcnow() + datetime.timedelta(days=365)
        # Validate input parameters
        key_id = request.POST['id']
        description = request.POST['description']
        email = request.POST['email']
        role = request.POST['role']
        expire_date = request.POST['expire_date']
        full_date_str = expire_date + ' 00:00:00.000000 +0000'
        aware_date = datetime.datetime.strptime(full_date_str,
                                                '%Y-%m-%d %H:%M:%S.%f %z')

        if not description:
            payload = {'msg': 'Missing parameter: description'}
            return HttpResponse(json.dumps(payload),
                                content_type='application/json', status=200)
        regx = ('^[\W]*([\w+\-.%]+@[\w\-.]+\.[A-Za-z]{2,4}[\W]*,{1}[\W]*)*'
                '([\w+\-.%]+@[\w\-.]+\.[A-Za-z]{2,4})[\W]*$')
        if not re.search(regx, email):
            payload = {'msg': 'Invalid email address was entered.'}
            return HttpResponse(json.dumps(payload),
                                content_type='application/json', status=200)
        if tz(aware_date) < tz(utcnow()):
            payload = {'msg': ('Invalid date was entered, '
                               'it must fall within the next year.')}
            return HttpResponse(json.dumps(payload),
                                content_type='application/json', status=200)
        if tz(aware_date) > tz(max_date):
            payload = {'msg': ('Invalid date was entered, '
                               'it must fall within the next year.')}
            return HttpResponse(json.dumps(payload),
                                content_type='application/json', status=200)
        item = edit_api_key(key_id, description, email, role, tz(aware_date))
        if item:
            logger.info('API key ID %s details edited by: %s', key_id,
                        sso_email(request))
            payload = {'api_id': key_id}
            return HttpResponse(json.dumps(payload),
                                content_type='application/json', status=200)
        else:
            logger.info('Unable to find API key %s to edit', key_id)
            return HttpResponse(json.dumps(id),
                                content_type='application/json', status=404)

    except Exception as exp:
        exmsg = ''.join(tb.format_exception(None, exp, exp.__traceback__))
        logger.error(exmsg)
        msg = str(exp)
        exp_doc = exp.__doc__
        return print_n_send_error_response(request, msg, False, exp_doc)
