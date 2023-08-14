"""Handle (.so) Shared Object file."""
import logging

from django.conf import settings
from django.shortcuts import render

import mobsf.MalwareAnalyzer.views.VirusTotal as VirusTotal
from mobsf.MobSF.utils import (
    file_size,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    firebase_analysis,
    hash_gen,
    update_scan_timestamp,
)
from mobsf.StaticAnalyzer.views.android.binary_analysis import (
    elf_analysis,
)
from mobsf.StaticAnalyzer.views.android.strings import (
    get_strings_metadata,
)
from mobsf.StaticAnalyzer.models import (
    StaticAnalyzerAndroid,
)
from mobsf.StaticAnalyzer.views.android.db_interaction import (
    get_context_from_analysis,
    get_context_from_db_entry,
    save_or_update,
)
from mobsf.MalwareAnalyzer.views.MalwareDomainCheck import MalwareDomainCheck


logger = logging.getLogger(__name__)


def so_analysis(request, app_dic, rescan, api):
    app_dic['app_file'] = f'{app_dic["md5"]}.so'  # NEW FILENAME
    app_dic['app_path'] = (app_dic['app_dir'] / app_dic['app_file']).as_posix()
    app_dic['app_dir'] = app_dic['app_dir'].as_posix() + '/'
    db_entry = StaticAnalyzerAndroid.objects.filter(MD5=app_dic['md5'])
    if db_entry.exists() and not rescan:
        context = get_context_from_db_entry(db_entry)
    else:
        app_dic['size'] = f'{str(file_size(app_dic["app_path"]))}MB'
        app_dic['sha1'], app_dic['sha256'] = hash_gen(app_dic['app_path'])
        app_dic['files'] = []
        app_dic['certz'] = []
        app_dic['playstore'] = {'error': True}
        app_dic['manifest_file'] = None
        app_dic['parsed_xml'] = ''
        app_dic['mani'] = ''
        man_data_dic = {
            'services': [],
            'activities': [],
            'receivers': [],
            'providers': [],
            'libraries': [],
            'categories': [],
            'perm': {},
            'packagename': app_dic['app_name'],
            'mainactivity': '',
            'min_sdk': '',
            'max_sdk': '',
            'target_sdk': '',
            'androver': '',
            'androvername': '',
            'icons': [],
        }
        man_an_dic = {
            'manifest_anal': [],
            'exported_act': [],
            'exported_cnt': {
                'exported_activities': 0,
                'exported_services': 0,
                'exported_receivers': 0,
                'exported_providers': 0,
            },
            'browsable_activities': {},
            'permissions': {},
            'icon_hidden': True,
            'network_security': {
                'network_findings': [],
                'network_summary': {},
            },
        }
        cert_dic = {
            'certificate_info': '',
            'certificate_findings': [],
            'certificate_summary': {},
        }
        app_dic['real_name'] = ''
        elf_dict = elf_analysis(app_dic['app_dir'])
        apkid_results = {}
        tracker_res = {}
        code_an_dic = {
            'api': {},
            'findings': {},
            'niap': {},
            'urls_list': [],
            'urls': [],
            'emails': [],
        }
        quark_results = []

        # Get the strings and metadata from shared object
        get_strings_metadata(
            None,
            None,
            elf_dict['elf_strings'],
            None,
            None,
            code_an_dic)

        # Firebase DB Check
        code_an_dic['firebase'] = firebase_analysis(
            code_an_dic['urls_list'])
        # Domain Extraction and Malware Check
        logger.info(
            'Performing Malware Check on extracted Domains')
        code_an_dic['domains'] = MalwareDomainCheck().scan(
            code_an_dic['urls_list'])

        app_dic['zipped'] = 'so'
        app_dic['icon_hidden'] = True
        app_dic['icon_found'] = False
        logger.info('Connecting to Database')
        try:
            # SAVE TO DB
            if rescan:
                logger.info('Updating Database...')
                save_or_update(
                    'update',
                    app_dic,
                    man_data_dic,
                    man_an_dic,
                    code_an_dic,
                    cert_dic,
                    elf_dict['elf_analysis'],
                    apkid_results,
                    quark_results,
                    tracker_res,
                )
                update_scan_timestamp(app_dic['md5'])
            else:
                logger.info('Saving to Database')
                save_or_update(
                    'save',
                    app_dic,
                    man_data_dic,
                    man_an_dic,
                    code_an_dic,
                    cert_dic,
                    elf_dict['elf_analysis'],
                    apkid_results,
                    quark_results,
                    tracker_res,
                )
        except Exception:
            logger.exception('Saving to Database Failed')
        context = get_context_from_analysis(
            app_dic,
            man_data_dic,
            man_an_dic,
            code_an_dic,
            cert_dic,
            elf_dict['elf_analysis'],
            apkid_results,
            quark_results,
            tracker_res,
        )
    context['appsec'] = {}
    context['average_cvss'] = None
    context['dynamic_analysis_done'] = False
    context['virus_total'] = None
    if settings.VT_ENABLED:
        vt = VirusTotal.VirusTotal()
        context['virus_total'] = vt.get_result(
            app_dic['app_path'],
            app_dic['md5'])
    template = 'static_analysis/android_binary_analysis.html'
    if api:
        return context
    else:
        return render(request, template, context)
