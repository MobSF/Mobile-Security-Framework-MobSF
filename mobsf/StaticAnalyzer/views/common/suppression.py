# -*- coding: utf_8 -*-
"""
Shared Functions for Suppression logic.

Module provide support for finding suppression
"""
import logging

from django.views.decorators.http import require_http_methods

from mobsf.StaticAnalyzer.models import (
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
)
from mobsf.DynamicAnalyzer.views.android.operations import (
    get_package_name,
    invalid_params,
    is_attack_pattern,
    send_response,
)
from mobsf.MobSF.utils import (
    is_md5,
    python_dict,
    python_list,
)
from mobsf.StaticAnalyzer.models import (
    SuppressFindings,
)

logger = logging.getLogger(__name__)


# AJAX

@require_http_methods(['POST'])
def suppress_by_rule_id(request, api=False):
    """Suppress finding by rule id."""
    data = {
        'status': 'failed',
        'message': 'Failed to suppress finding by rule id'}
    try:
        checksum = request.POST['checksum']
        rule = request.POST['rule']
        if not is_md5(checksum):
            return invalid_params(api)
        package = get_package_name(checksum)
        if not package or is_attack_pattern(rule):
            return invalid_params(api)
        sup_config = SuppressFindings.objects.filter(
            PACKAGE_NAME=package)
        if sup_config.exists():
            # Update Record
            sup_rules = set(
                python_list(sup_config[0].SUPPRESS_RULE_ID))
            if rule not in sup_rules:
                sup_rules.add(rule)
                sup_config.update(SUPPRESS_RULE_ID=sup_rules)
        else:
            # Create Record
            values = {
                'PACKAGE_NAME': package,
                'SUPPRESS_RULE_ID': [rule],
                'SUPPRESS_FILES': {},
                'SUPPRESS_TYPE': 'code',
            }
            SuppressFindings.objects.create(**values)
        return send_response({'status': 'ok'}, api)
    except Exception:
        logger.exception('Error suppressing finding by rule id')
    return send_response(data, api)

# AJAX


@require_http_methods(['POST'])
def suppress_by_files(request, api=False):
    """Suppress finding by files."""
    data = {
        'status': 'failed',
        'message': 'Failed to suppress finding by files'}
    try:
        checksum = request.POST['checksum']
        rule = request.POST['rule']
        files_to_suppress = []
        if not is_md5(checksum):
            return invalid_params(api)
        package = get_package_name(checksum)
        if not package or is_attack_pattern(rule):
            return invalid_params(api)
        sup_config = SuppressFindings.objects.filter(
            PACKAGE_NAME=package)
        # Do Lookups
        android_static_db = StaticAnalyzerAndroid.objects.filter(
            MD5=checksum)
        ios_static_db = StaticAnalyzerIOS.objects.filter(
            MD5=checksum)
        if android_static_db.exists():
            code_res = python_dict(android_static_db[0].CODE_ANALYSIS)
        elif ios_static_db.exists():
            code_res = python_dict(android_static_db[0].CODE_ANALYSIS)
        else:
            return send_response(data, api)
        files_to_suppress = list(code_res[rule]['files'].keys())
        if sup_config.exists():
            # Update Record
            old = python_dict(sup_config[0].SUPPRESS_FILES)
            old[rule] = files_to_suppress
            sup_config.update(SUPPRESS_FILES=old)
        else:
            # Create Record
            values = {
                'PACKAGE_NAME': package,
                'SUPPRESS_RULE_ID': [],
                'SUPPRESS_FILES': {rule: files_to_suppress},
                'SUPPRESS_TYPE': 'code',
            }
            SuppressFindings.objects.create(**values)
        return send_response({'status': 'ok'}, api)
    except Exception:
        logger.exception('Error suppressing finding by files')
    return send_response(data, api)
