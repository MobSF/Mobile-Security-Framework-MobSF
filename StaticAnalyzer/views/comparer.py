# -*- coding: utf_8 -*-
"""
Module providing the shared functions for static analysis of iOS and Android
"""
import re
from copy import deepcopy

try:
    import pdfkit
except:
    print("[WARNING] wkhtmltopdf is not installed/configured properly. PDF Report Generation is disabled")
from django.shortcuts import render

from MobSF.utils import (
    print_n_send_error_response
)

from StaticAnalyzer.models import StaticAnalyzerAndroid

from StaticAnalyzer.views.android.db_interaction import (
    get_context_from_db_entry
)


# suppose to get any 2 apps (android / ios / appx) and then figure out what to do with them
def generic_compare(request, first_hash: str, second_hash: str, api: bool = False):
    # This context consists of specific lists and analysis that is done on the classic ones
    # it will be filled during the different diff analysis
    context = {
        'title': 'Compare report',
        'first_app': dict(),
        'second_app': dict(),
        'urls': dict(),
        'api': dict(),
        'permissions': dict()
    }
    static_fields = ['md5', 'name', 'size', 'icon_found', 'icon_hidden', 'act_count', 'e_act', 'serv_count', 'e_ser',
                     'bro_count', 'e_bro', 'prov_count', 'e_cnt']

    # For now - support only android
    db_entry = StaticAnalyzerAndroid.objects.filter(MD5=first_hash)
    db_entry2 = StaticAnalyzerAndroid.objects.filter(MD5=second_hash)

    if not (db_entry.exists() and db_entry2.exists()):
        return print_n_send_error_response(request, "One of the Hashes was not found in the DB", False)

    # First fetch the already done analysis on each of the apps
    # We don't want to return this whole context back to the user because its a lot of data we don't use
    # it should help the performance I guess
    first_app = deepcopy(get_context_from_db_entry(db_entry))
    second_app = deepcopy(get_context_from_db_entry(db_entry2))

    # Second, fill the mutual static parts that are missing in the classic analysis
    for curr_app, db_context in [('first_app', first_app), ('second_app', second_app)]:

        # format informative title
        context[curr_app]['name_ver'] = "{0} - {1}".format(db_context['packagename'],
                                                           db_context['androvername'])

        # Fill all the static information
        for static_attr in static_fields:
            context[curr_app][static_attr] = db_context[static_attr]

        # Get only the subject of the cert
        subject_regex = re.compile(r'.*Subject:([^<]+)</br>.*', re.DOTALL)
        match = subject_regex.match(db_context['certinfo'])
        if match:
            context[curr_app]['cert_subject'] = match.group(1)
        else:
            context[curr_app]['cert_subject'] = "No subject"

        # Some preparations so we have some sort of same structures
        # (urls are lists inside the list which mess things up...)
        tmp_list = list()
        for url_obj in db_context['urls']:
            for url in url_obj['urls']:
                # urls can mess up the table because they can be really long, so let's cut them
                tmp_url = url[:70]
                while len(url) > 70:
                    url = url[70:]
                    tmp_url += '<br />'
                    tmp_url += url[:70]
                tmp_list.append(tmp_url)

        db_context['urls'] = deepcopy(tmp_list)
        tmp_list.clear()

    # Third, calculate some diffs
    for section, is_tuples in [
        ('permissions', True),
        ('api', True),
        ('urls', False)
    ]:
        if is_tuples:
            context[section]['mutual'] = [(x, y) for (x, y) in first_app[section].items() if x in
                                          second_app[section].keys()]

            # Only first
            context[section]['only_first'] = [(x, y) for (x, y) in first_app[section].items() if x not in
                                              second_app[section].keys()]

            # Only Second
            context[section]['only_second'] = [(x, y) for (x, y) in second_app[section].items() if x not in
                                               first_app[section].keys()]
        else:
            context[section]['mutual'] = [x for x in first_app[section] if x in
                                          second_app[section]]

            context[section]['only_first'] = [x for x in first_app[section] if x not in
                                              second_app[section]]

            context[section]['only_second'] = [x for x in second_app[section] if x not in
                                               first_app[section]]

    template = "static_analysis/compare.html"
    if api:
        return context
    else:
        return render(request, template, context)
