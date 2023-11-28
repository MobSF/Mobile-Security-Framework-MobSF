# -*- coding: utf_8 -*-
"""Dynamic Analyzer Reporting."""
import logging
from pathlib import Path

from django.conf import settings
from django.shortcuts import render
from django.template.defaulttags import register

import mobsf.MalwareAnalyzer.views.Trackers as Trackers
from mobsf.DynamicAnalyzer.views.ios.analysis import (
    get_screenshots,
    ios_api_analysis,
    run_analysis,
)
from mobsf.DynamicAnalyzer.views.ios.utils import (
    common_check,
)
from mobsf.MobSF.utils import (
    base64_decode,
    is_md5,
    key,
    pretty_json,
    print_n_send_error_response,
    replace,
)


logger = logging.getLogger(__name__)
register.filter('key', key)
register.filter('replace', replace)
register.filter('pretty_json', pretty_json)
register.filter('base64_decode', base64_decode)


def ios_view_report(request, checksum, api=False):
    """Dynamic Analysis Report Generation."""
    logger.info('iOS Dynamic Analysis Report Generation')
    try:
        if not is_md5(checksum):
            # We need this check since checksum is not validated
            # in REST API
            return print_n_send_error_response(
                request,
                'Invalid Hash',
                api)
        instance_id = request.GET.get('instance_id')
        if instance_id and not common_check(instance_id):
            dev = instance_id
        else:
            dev = ''
        app_dir = Path(settings.UPLD_DIR) / checksum
        download_dir = settings.DWD_DIR
        tools_dir = settings.TOOLS_DIR
        frida_log = app_dir / 'mobsf_frida_out.txt'
        if not frida_log.exists():
            msg = ('Dynamic Analysis report is not available '
                   'for this app. Perform Dynamic Analysis '
                   'and generate the report.')
            return print_n_send_error_response(request, msg, api)
        dynamic_dump = ios_api_analysis(app_dir)
        dump_analaysis = run_analysis(app_dir, checksum)
        trk = Trackers.Trackers(app_dir, tools_dir)
        trackers = trk.get_trackers_domains_or_deps(
            dump_analaysis['domains'], None)
        screenshots = get_screenshots(checksum, download_dir)
        context = {
            'hash': checksum,
            'version': settings.MOBSF_VER,
            'title': 'iOS Dynamic Analysis Report',
            'instance_id': dev,
            'trackers': trackers,
            'screenshots': screenshots,
            'frida_logs': frida_log.exists(),
        }
        context.update(dynamic_dump)
        context.update(dump_analaysis)
        template = 'dynamic_analysis/ios/dynamic_report.html'
        if api:
            return context
        return render(request, template, context)
    except Exception as exp:
        logger.exception('Dynamic Analysis Report Generation')
        err = 'Error Generating Dynamic Analysis Report. ' + str(exp)
        return print_n_send_error_response(request, err, api)
