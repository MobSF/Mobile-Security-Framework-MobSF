# -*- coding: utf_8 -*-
"""
Shared Functions.

AppSec Dashboard
"""
import json
import logging

from django.http import HttpResponse
from django.shortcuts import render

from mobsf.MobSF import settings
from mobsf.MobSF.utils import (
    print_n_send_error_response,
)
from mobsf.StaticAnalyzer.models import (
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
)
from mobsf.StaticAnalyzer.views.android.db_interaction import (
    get_context_from_db_entry as adb)
from mobsf.StaticAnalyzer.views.ios.db_interaction import (
    get_context_from_db_entry as idb)

logger = logging.getLogger(__name__)


def get_android_dashboard(context, from_ctx=False):
    """Get Android AppSec Dashboard."""
    findings = {
        'high': [],
        'warning': [],
        'info': [],
        'secure': [],
        'total_trackers': None,
    }
    if from_ctx:
        data = context
    else:
        data = adb(context)
    # Certificate Analysis
    if 'certificate_findings' in data['certificate_analysis']:
        for i in data['certificate_analysis']['certificate_findings']:
            if i[0] == 'info':
                continue
            findings[i[0]].append({
                'title': i[2],
                'description': i[1],
                'section': 'certificate',
            })
    # Network Security
    for n in data['network_security']:
        desc = '\n'.join(n['scope'])
        desc = f'Scope:\n{desc}\n\n'
        title_parts = n['description'].split('.', 1)
        if len(title_parts) > 1:
            desc += title_parts[1].strip()
            title = title_parts[0]
        else:
            title = n['description']
        findings[n['severity']].append({
            'title': title,
            'description': desc,
            'section': 'network',
        })
    # Manifest Analysis
    for m in data['manifest_analysis']:
        if m['stat'] == 'info':
            continue
        title = m['title'].replace('<strong>', '')
        title = title.replace('</strong>', '')
        fmt = title.split('<br>', 1)
        if len(fmt) > 1:
            desc = fmt[1].replace('<br>', '') + '\n' + m['desc']
        else:
            desc = m['desc']
        findings[m['stat']].append({
            'title': fmt[0],
            'description': desc,
            'section': 'manifest',
        })
    # Code Analysis
    for cd in data['code_analysis'].values():
        if cd['metadata']['severity'] == 'good':
            sev = 'secure'
        else:
            sev = cd['metadata']['severity']
        desc = cd['metadata']['description']
        ref = cd['metadata'].get('ref', '')
        findings[sev].append({
            'title': cd['metadata']['description'],
            'description': f'{desc}\n{ref}',
            'section': 'code',
        })
    # Domains
    for domain, value in data['domains'].items():
        if value['bad'] == 'yes':
            findings['high'].append({
                'title': f'Malicious domain found - {domain}',
                'description': str(value['geolocation']),
                'section': 'domains',
            })
    # Firebase
    for fb in data['firebase_urls']:
        if fb['open']:
            fdb = fb['url']
            findings['high'].append({
                'title': 'Firebase DB is exposed publicly.',
                'description': (
                    f'The Firebase database at {fdb} is exposed'
                    ' to internet without any authentication'),
                'section': 'firebase',
            })
    # Trackers
    if 'trackers' in data['trackers']:
        findings['total_trackers'] = data['trackers']['total_trackers']
        t = len(data['trackers']['trackers'])
        findings['trackers'] = t
        if t > 4:
            findings['high'].append({
                'title': 'Application contains Privacy Trackers',
                'description': (
                    f'This app has more than {t} privacy trackers.'
                    ' Trackers can track device or users and can '
                    'are privacy concerns for end users.'),
                'section': 'trackers',
            })
        elif t > 0:
            findings['warning'].append({
                'title': 'Application contains Privacy Trackers',
                'description': (
                    f'This app has {t} privacy trackers.'
                    ' Trackers can track device or users and can '
                    'are privacy concerns for end users.'),
                'section': 'trackers',
            })
        else:
            findings['secure'].append({
                'title': 'This application has no privacy trackers',
                'description': (
                    'Unable to find privacy trackers during static analysis.'
                    ' This app does not include any trackers.'),
                'section': 'trackers',
            })
    # Possible Hardcoded Secrets
    secrets = data['secrets']
    if len(secrets) > 1:
        sec = '\n'.join(secrets)
        findings['warning'].append({
            'title': 'This app may contain hardcoded secrets',
            'description': (
                'The following secrets were identified from the app. '
                'Ensure that these are not secrets or private information.\n'
                f'{sec}'),
            'section': 'secrets',
        })
    high = len(findings.get('high'))
    warn = len(findings.get('warning'))
    sec = len(findings.get('secure'))
    total = high + warn + sec
    findings['security_score'] = int(100 - (
        ((high * 1) + (warn * .5) - (sec * .2)) / total) * 100)
    findings['app_name'] = data.get('app_name', '')
    findings['file_name'] = data.get('file_name', '')
    findings['version_name'] = data.get('version_name', '')
    findings['icon_found'] = data['icon_found']
    findings['hash'] = data['md5']
    return findings


def get_ios_dashboard(context, from_ctx=False):
    """Get iOS AppSec Dashboard."""
    findings = {
        'high': [],
        'warning': [],
        'info': [],
        'secure': [],
        'total_trackers': None,
    }
    if from_ctx:
        data = context
    else:
        data = idb(context)
    # Transport Security
    for n in data['ats_analysis']:
        findings[n['severity']].append({
            'title': n['issue'],
            'description': n['description'],
            'section': 'network',
        })
    # Binary Code Analysis
    for issue, cd in data['binary_analysis'].items():
        if cd['severity'] == 'good':
            sev = 'secure'
        else:
            sev = cd['severity']
        findings[sev].append({
            'title': issue,
            'description': str(cd['detailed_desc']),
            'section': 'binary',
        })
    # Macho Analysis
    ma = data['macho_analysis']
    if ma:
        nx = ma['nx']
        if nx['severity'] in {'high', 'warning'}:
            findings[nx['severity']].append({
                'title': 'NX bit is not set properly for this application',
                'description': nx['description'],
                'section': 'macho',
            })
        pie = ma['pie']
        if pie['severity'] in {'high', 'warning'}:
            findings[pie['severity']].append({
                'title': (
                    'PIE flag is not configured securely'
                    ' for this application binary'),
                'description': pie['description'],
                'section': 'macho',
            })
        stack_canary = ma['stack_canary']
        if stack_canary['severity'] in {'high', 'warning'}:
            findings[stack_canary['severity']].append({
                'title': (
                    'Stack Canary is not properly '
                    'configured for this application'),
                'description': stack_canary['description'],
                'section': 'macho',
            })
        arc = ma['arc']
        if arc['severity'] in {'high', 'warning'}:
            findings[arc['severity']].append({
                'title': 'Application binary is not compiled with ARC flag',
                'description': arc['description'],
                'section': 'macho',
            })
        rpath = ma['rpath']
        if rpath['severity'] in {'high', 'warning'}:
            findings[rpath['severity']].append({
                'title': 'Application binary has rpath set',
                'description': rpath['description'],
                'section': 'macho',
            })
        symbol = ma['symbol']
        if symbol['severity'] in {'high', 'warning'}:
            findings[symbol['severity']].append({
                'title': 'Application binary does not have symbols stripped',
                'description': symbol['description'],
                'section': 'macho',
            })
    # Code Analysis
    for cd in data['code_analysis'].values():
        if cd['metadata']['severity'] == 'good':
            sev = 'secure'
        else:
            sev = cd['metadata']['severity']
        desc = cd['metadata']['description']
        ref = cd['metadata'].get('ref', '')
        findings[sev].append({
            'title': cd['metadata']['description'],
            'description': f'{desc}\n{ref}',
            'section': 'code',
        })
    # Domains
    for domain, value in data['domains'].items():
        if value['bad'] == 'yes':
            findings['high'].append({
                'title': f'Malicious domain found - {domain}',
                'description': str(value['geolocation']),
                'section': 'domains',
            })
    # Firebase
    for fb in data['firebase_urls']:
        if fb['open']:
            fdb = fb['url']
            findings['high'].append({
                'title': 'Firebase DB is exposed publicly.',
                'description': (
                    f'The Firebase database at {fdb} is exposed'
                    ' to internet without any authentication'),
                'section': 'firebase',
            })
    # Trackers
    if 'trackers' in data['trackers']:
        findings['total_trackers'] = data['trackers']['total_trackers']
        t = len(data['trackers']['trackers'])
        findings['trackers'] = t
        if t > 4:
            findings['high'].append({
                'title': 'Application contains Privacy Trackers',
                'description': (
                    f'This app has more than {t} privacy trackers.'
                    ' Trackers can track device or users and can '
                    'are privacy concerns for end users.'),
                'section': 'trackers',
            })
        elif t > 0:
            findings['warning'].append({
                'title': 'Application contains Privacy Trackers',
                'description': (
                    f'This app has {t} privacy trackers.'
                    ' Trackers can track device or users and can '
                    'are privacy concerns for end users.'),
                'section': 'trackers',
            })
        else:
            findings['secure'].append({
                'title': 'This application has no privacy trackers',
                'description': (
                    'Unable to find privacy trackers during static analysis.'
                    ' This app does not include any trackers.'),
                'section': 'trackers',
            })
    # Possible Hardcoded Secrets
    secrets = data['secrets']
    if len(secrets) > 1:
        sec = '\n'.join(secrets)
        findings['warning'].append({
            'title': 'This app may contain hardcoded secrets',
            'description': (
                'The following secrets were identified from the app. '
                'Ensure that these are not secrets or private information.\n'
                f'{sec}'),
            'section': 'secrets',
        })
    high = len(findings.get('high'))
    warn = len(findings.get('warning'))
    sec = len(findings.get('secure'))
    total = high + warn + sec
    findings['security_score'] = int(100 - (
        ((high * 1) + (warn * .5) - (sec * .2)) / total) * 100)
    findings['app_name'] = data.get('app_name', '')
    findings['file_name'] = data.get('file_name', '')
    findings['version_name'] = data.get('app_version', '')
    findings['icon_found'] = data['icon_found']  # Does not exists for iOS
    findings['hash'] = data['md5']
    return findings


def appsec_dashboard(request, checksum, api=False):
    """Provide data for appsec dashboard."""
    try:
        android_static_db = StaticAnalyzerAndroid.objects.filter(
            MD5=checksum)
        ios_static_db = StaticAnalyzerIOS.objects.filter(
            MD5=checksum)
        if android_static_db.exists():
            context = get_android_dashboard(android_static_db)
        elif ios_static_db.exists():
            context = get_ios_dashboard(ios_static_db)
        else:
            if api:
                return {'not_found': 'Report not found or supported'}
            else:
                return HttpResponse(
                    json.dumps({'not_found': 'Report not found or supported'}),
                    content_type='application/json; charset=utf-8',
                    status=500)
        context['version'] = settings.MOBSF_VER
        context['title'] = 'AppSec Scorecard'
        if api:
            return context
        else:
            return render(
                request,
                'static_analysis/appsec_dashboard.html',
                context)
    except Exception as exp:
        logger.exception('Error Generating Application Security Dashboard')
        msg = str(exp)
        exp = exp.__doc__
        if api:
            return print_n_send_error_response(request, msg, True, exp)
        else:
            return print_n_send_error_response(request, msg, False, exp)
