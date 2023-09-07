# -*- coding: utf_8 -*-
"""
Compare Apps.

Module for comparing app results.
"""
import re
from collections import defaultdict
from copy import deepcopy

from django.shortcuts import render
from django.conf import settings
from django.utils.html import escape

from mobsf.MobSF.utils import print_n_send_error_response
from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid
from mobsf.StaticAnalyzer.views.android.db_interaction import (
    get_context_from_db_entry,
)


# The APKiD is pain because it really differs from the others
def diff_apkid(context: dict) -> None:
    apkid_keys = ['anti_vm', 'compiler', 'obfuscator',
                  'packer', 'dropper', 'manipulator',
                  'anti_disassembly', 'anti_debug', 'abnormal']

    context['apkid'] = {}
    context['apkid']['common'] = {}
    context['apkid']['only_first'] = {}
    context['apkid']['only_second'] = {}

    first_apkid, second_apkid = (context['first_app']['apkid'],
                                 context['second_app']['apkid'])
    first_error, second_error = first_apkid.get(
        'error', False), second_apkid.get('error', False)
    context['apkid_error'] = (first_error or second_error)
    if context['apkid_error']:
        return

    tmp_flat_results = {}
    for curr_app_str in ['first_app', 'second_app']:
        # Flatten the results per app (join all the dex files result into one)
        flat_results = defaultdict(list)
        for results in [dex_results for (dex_name, dex_results) in
                        context[curr_app_str]['apkid'].items()]:
            for apkid_key, key_results in results.items():
                flat_results[apkid_key] += key_results
                # Distinct list
                flat_results[apkid_key] = list(set(flat_results[apkid_key]))
        tmp_flat_results[curr_app_str] = deepcopy(flat_results)

    for key in apkid_keys:
        # The keys may be different between the two lists
        context['apkid']['common'][key] = [
            x for x in tmp_flat_results['first_app'][key] if x in
            tmp_flat_results['second_app'][key]]

        context['apkid']['only_first'][key] = [
            x for x in tmp_flat_results['first_app'][key] if x not in
            tmp_flat_results['second_app'][key]]

        context['apkid']['only_second'][key] = [
            x for x in tmp_flat_results['second_app'][key] if x not in
            tmp_flat_results['first_app'][key]]


def diff_browsable_activities(context, first_app, second_app):
    # Browsable activities are 'complex' objects that contains additional
    # fields that should be compared. The generic diffing performed above
    # only list which browsable activities are in common or present only in
    # one app. For the activities present in one app we can just pretty-print
    # the details but for common browsable activities we need to perform the
    # diffing also on sub-keys, like hosts and schemes.
    section = 'browsable_activities'
    common_activity = 'common_browsable_activities'
    browsable_activities_keys = ['schemes', 'mime_types', 'hosts', 'ports',
                                 'paths', 'path_prefixs', 'path_patterns']

    for act, _ in context[section]['common']:
        context[common_activity][act] = {}
        for key in browsable_activities_keys:
            context[common_activity][act][key] = {}

            context[common_activity][act][key]['common'] = [
                y for y in first_app[section][act][key] if y in
                second_app[section][act][key]
            ]

            context[common_activity][act][key]['only_first'] = [
                y for y in first_app[section][act][key] if y not in
                second_app[section][act][key]
            ]

            context[common_activity][act][key]['only_second'] = [
                y for y in second_app[section][act][key] if y not in
                first_app[section][act][key]
            ]


# suppose to get any 2 apps (android / ios / appx)
# and then figure out what to do with them
def generic_compare(request,
                    first_hash: str,
                    second_hash: str,
                    api: bool = False):
    # This context consists of specific lists and analysis
    # that is done on the classic ones
    # it will be filled during the different diff analysis
    context = {
        'title': 'Compare report',
        'version': settings.MOBSF_VER,
        'first_app': {},
        'second_app': {},
        'urls': {},
        'android_api': {},
        'permissions': {},
        'browsable_activities': {},
        'common_browsable_activities': {},
        'apkid': {},
    }
    static_fields = ['md5', 'file_name', 'size', 'icon_path',
                     'activities', 'services', 'providers',
                     'receivers', 'exported_count', 'apkid']

    # For now - support only android
    db_entry = StaticAnalyzerAndroid.objects.filter(MD5=first_hash)
    db_entry2 = StaticAnalyzerAndroid.objects.filter(MD5=second_hash)

    if not (db_entry.exists() and db_entry2.exists()):
        return print_n_send_error_response(
            request,
            'Currently you can only diff/compare android apps. '
            'One of the app has not completed static analysis or'
            ' they are not both android APK/ZIP.',
            api,
        )

    # First fetch the already done analysis on each of the apps
    # We don't want to return this whole context back to the user
    # because its a lot of data we don't use
    # it should help the performance I guess
    first_app = deepcopy(get_context_from_db_entry(db_entry))
    second_app = deepcopy(get_context_from_db_entry(db_entry2))

    # Second, fill the common static parts that
    # are missing in the classic analysis
    for curr_app, db_context in [('first_app', first_app),
                                 ('second_app', second_app)]:

        # format informative title
        context[curr_app]['name_ver'] = '{0} - {1}'.format(
            db_context['package_name'],
            db_context['version_name'])

        # Fill all the static information
        for static_attr in static_fields:
            context[curr_app][static_attr] = db_context[static_attr]

        # Get only the subject of the cert
        subject_regex = re.compile(r'Subject: .*')
        match = subject_regex.search(
            db_context['certificate_analysis']['certificate_info'])
        if match:
            context[curr_app]['cert_subject'] = match.group()
        else:
            context[curr_app]['cert_subject'] = 'No subject'

        # Some preparations so we have some sort of same structures
        # (urls are lists inside the list which mess things up...)
        tmp_list = []
        for url_obj in db_context['urls']:
            for url in url_obj['urls']:
                # urls can mess up the table because they can be really long,
                # so let's cut them
                # escape url
                url = escape(url)
                tmp_url = url[:70]
                while len(url) > 70:
                    url = url[70:]
                    tmp_url += '<br />'
                    tmp_url += url[:70]
                tmp_list.append(tmp_url)

        db_context['urls'] = list(set(deepcopy(tmp_list)))
        tmp_list.clear()

    # apkid check - we do it here just because
    # its really ugly inside the template
    # it has a dedicated function because the result
    # is more complicated then the others...
    diff_apkid(context)

    # Third, calculate some diffs
    for section, is_tuples in [
        ('permissions', True),
        ('android_api', True),
        ('browsable_activities', True),
        ('urls', False),
    ]:
        if is_tuples:
            context[section]['common'] = [
                (x, y) for (x, y) in first_app[section].items() if x in
                second_app[section].keys()]

            # Only first
            context[section]['only_first'] = [
                (x, y) for (x, y) in first_app[section].items() if x not in
                second_app[section].keys()]

            # Only Second
            context[section]['only_second'] = [
                (x, y) for (x, y) in second_app[section].items() if x not in
                first_app[section].keys()]
        else:
            context[section]['common'] = [
                x for x in first_app[section] if x in
                second_app[section]]

            context[section]['only_first'] = [
                x for x in first_app[section] if x not in
                second_app[section]]

            context[section]['only_second'] = [
                x for x in second_app[section] if x not in
                first_app[section]]

    diff_browsable_activities(context, first_app, second_app)

    template = 'static_analysis/compare.html'
    if api:
        return context
    else:
        return render(request, template, context)
