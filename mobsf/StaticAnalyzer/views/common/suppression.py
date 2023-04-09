# -*- coding: utf_8 -*-
"""
Shared Functions for Suppression logic.

Module provide support for finding suppression
"""
import logging
from copy import copy, deepcopy

from django.views.decorators.http import require_http_methods

from mobsf.StaticAnalyzer.models import (
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
)
from mobsf.DynamicAnalyzer.views.android.operations import (
    invalid_params,
    is_attack_pattern,
    send_response,
)
from mobsf.MobSF.utils import (
    android_component,
    is_md5,
    python_dict,
    python_list,
)
from mobsf.StaticAnalyzer.models import (
    SuppressFindings,
)

logger = logging.getLogger(__name__)

HIGH = 'high'
WARNING = 'warning'
INFO = 'info'
SECURE = 'secure'
GOOD = 'good'
SUPPRESSED = 'suppressed'


def get_package(checksum):
    """Get package from checksum."""
    try:
        andpkg = StaticAnalyzerAndroid.objects.get(
            MD5=checksum)
        return andpkg.PACKAGE_NAME
    except Exception:
        pass
    try:
        iospkg = StaticAnalyzerIOS.objects.get(
            MD5=checksum)
        return iospkg.BUNDLE_ID
    except Exception:
        pass
    return None


# AJAX

@require_http_methods(['POST'])
def suppress_by_rule_id(request, api=False):
    """Suppress finding by rule id."""
    data = {
        'status': 'failed',
        'message': 'Failed to suppress finding by rule id'}
    try:
        if api:
            checksum = request.POST['hash']
        else:
            checksum = request.POST['checksum']
        rule = request.POST['rule']
        stype = request.POST['type']
        type_check = stype in {'code', 'manifest'}
        if not is_md5(checksum):
            return invalid_params(api)
        package = get_package(checksum)
        if not package or is_attack_pattern(rule) or not type_check:
            return invalid_params(api)
        sup_config = SuppressFindings.objects.filter(
            PACKAGE_NAME=package, SUPPRESS_TYPE=stype)
        if sup_config.exists():
            # Update Record
            sup_rules = set(
                python_list(sup_config[0].SUPPRESS_RULE_ID))
            if rule not in sup_rules:
                sup_rules.add(rule)
                sup_config.update(SUPPRESS_RULE_ID=list(sup_rules))
        else:
            # Create Record
            values = {
                'PACKAGE_NAME': package,
                'SUPPRESS_RULE_ID': [rule],
                'SUPPRESS_FILES': {},
                'SUPPRESS_TYPE': stype,
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
        if api:
            checksum = request.POST['hash']
        else:
            checksum = request.POST['checksum']
        rule = request.POST['rule']
        files_to_suppress = []
        old_files = []
        if not is_md5(checksum):
            return invalid_params(api)
        package = get_package(checksum)
        if not package or is_attack_pattern(rule):
            return invalid_params(api)
        sup_config = SuppressFindings.objects.filter(
            PACKAGE_NAME=package, SUPPRESS_TYPE='code')
        # Do Lookups
        android_static_db = StaticAnalyzerAndroid.objects.filter(
            MD5=checksum)
        ios_static_db = StaticAnalyzerIOS.objects.filter(
            MD5=checksum)
        if android_static_db.exists():
            code_res = python_dict(android_static_db[0].CODE_ANALYSIS)
        elif ios_static_db.exists():
            code_res = python_dict(ios_static_db[0].CODE_ANALYSIS)
        else:
            return send_response(data, api)
        files_to_suppress = list(code_res[rule]['files'].keys())
        if sup_config.exists():
            # Update Record
            old = python_dict(sup_config[0].SUPPRESS_FILES)
            # Empty dict or rule key not already present
            if not old or rule not in old:
                old[rule] = files_to_suppress
            else:
                old_files = old[rule]
                old[rule] = list(set(files_to_suppress + old_files))
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

# AJAX


@require_http_methods(['POST'])
def list_suppressions(request, api=False):
    """List Suppression Rules."""
    data = {
        'status': 'failed',
        'message': 'Failed to list suppression rules'}
    try:
        if api:
            checksum = request.POST['hash']
        else:
            checksum = request.POST['checksum']
        if not is_md5(checksum):
            return invalid_params(api)
        package = get_package(checksum)
        if not package:
            return invalid_params(api)

        data = []
        all_configs = SuppressFindings.objects.filter(
            PACKAGE_NAME=package)
        if all_configs.exists():
            data = list(all_configs.values())
            for i in data:
                i['SUPPRESS_RULE_ID'] = python_list(i['SUPPRESS_RULE_ID'])
                i['SUPPRESS_FILES'] = python_dict(i['SUPPRESS_FILES'])
        return send_response(
            {'status': 'ok', 'message': data},
            api)
    except Exception:
        logger.exception('Error listing suppression rules')
    return send_response(data, api)


# AJAX

@require_http_methods(['POST'])
def delete_suppression(request, api=False):
    """Delete suppression rule."""
    data = {
        'status': 'failed',
        'message': 'Failed to delete suppression rule'}
    try:
        if api:
            checksum = request.POST['hash']
        else:
            checksum = request.POST['checksum']
        rule = request.POST['rule']
        kind = request.POST['kind']
        stype = request.POST['type']
        type_check = stype in {'code', 'manifest'}
        if not is_md5(checksum):
            return invalid_params(api)
        package = get_package(checksum)
        if not package or is_attack_pattern(rule) or not type_check:
            return invalid_params(api)
        sup_config = SuppressFindings.objects.filter(
            PACKAGE_NAME=package, SUPPRESS_TYPE=stype)
        if sup_config.exists():
            if kind == 'rule':
                sup_rules = set(
                    python_list(sup_config[0].SUPPRESS_RULE_ID))
                if rule in sup_rules:
                    sup_rules.remove(rule)
                    sup_config.update(SUPPRESS_RULE_ID=list(sup_rules))
            elif kind == 'file':
                files_config = python_dict(sup_config[0].SUPPRESS_FILES)
                if rule in files_config:
                    del files_config[rule]
                    sup_config.update(SUPPRESS_FILES=files_config)
        return send_response({'status': 'ok'}, api)
    except Exception:
        logger.exception('Error deleting suppression rule')
    return send_response(data, api)


def process_suppression(data, package):
    """Process all suppression for code."""
    filtered = {}
    summary = {HIGH: 0, WARNING: 0, INFO: 0,
               SECURE: 0, SUPPRESSED: 0}
    if len(data) == 0:
        return {
            'findings': data,
            'summary': {},
        }
    filters = SuppressFindings.objects.filter(
        PACKAGE_NAME=package,
        SUPPRESS_TYPE='code')
    if not filters.exists():
        cleaned = data
    else:
        # Priority to rules
        filter_rules = python_list(filters[0].SUPPRESS_RULE_ID)
        if filter_rules:
            for k in data:
                if k not in filter_rules:
                    filtered[k] = data[k]
                else:
                    summary[SUPPRESSED] += 1
        else:
            filtered = deepcopy(data)

        # Process by files
        filter_files = python_dict(filters[0].SUPPRESS_FILES)
        cleaned = copy(filtered)
        if filter_files:
            for k in filtered:
                if k not in filter_files.keys():
                    continue
                for rem_file in filter_files[k]:
                    if rem_file in filtered[k]['files']:
                        del filtered[k]['files'][rem_file]
                        summary[SUPPRESSED] += 1
                # Remove rule_id with no files
                if len(filtered[k]['files']) == 0:
                    del cleaned[k]
    for v in cleaned.values():
        if 'severity' in v:
            # iOS binary code
            sev = v['severity']
        else:
            sev = v['metadata']['severity']
        if sev == HIGH:
            summary[HIGH] += 1
        elif sev == WARNING:
            summary[WARNING] += 1
        elif sev == INFO:
            summary[INFO] += 1
        elif sev == GOOD or sev == SECURE:
            summary[SECURE] += 1
    return {
        'findings': cleaned,
        'summary': summary,
    }


def process_suppression_manifest(data, package):
    """Process all suppression for manifest."""
    filtered = []
    summary = {HIGH: 0, WARNING: 0, INFO: 0, SUPPRESSED: 0}
    filters = SuppressFindings.objects.filter(
        PACKAGE_NAME=package,
        SUPPRESS_TYPE='manifest')
    if not filters.exists():
        filtered = data
    else:
        filter_rules = python_list(filters[0].SUPPRESS_RULE_ID)
        if filter_rules:
            for k in data:
                rule = k['rule']
                title = k['title']
                dynamic_rule = f'{android_component(title)}{rule}'
                if dynamic_rule not in filter_rules:
                    filtered.append(k)
                else:
                    summary[SUPPRESSED] += 1
        else:
            filtered = data
    for i in filtered:
        if i['severity'] == HIGH:
            summary[HIGH] += 1
        elif i['severity'] == WARNING:
            summary[WARNING] += 1
        elif ['severity'] == INFO:
            summary[INFO] += 1
    return {
        'manifest_findings': filtered,
        'manifest_summary': summary,
    }
