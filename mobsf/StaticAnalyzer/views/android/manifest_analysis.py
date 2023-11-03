# -*- coding: utf_8 -*-
# flake8: noqa
"""Module for android manifest analysis."""
import logging


from mobsf.StaticAnalyzer.views.android import (
    android_manifest_desc,
    network_security,
)


logger = logging.getLogger(__name__)
ANDROID_4_2_LEVEL = 17
ANDROID_5_0_LEVEL = 21
ANDROID_8_0_LEVEL = 26
ANDROID_MANIFEST_FILE = 'AndroidManifest.xml'


def get_browsable_activities(node, ns):
    """Get Browsable Activities."""
    try:
        browse_dic = {}
        schemes = []
        mime_types = []
        hosts = []
        ports = []
        paths = []
        path_prefixs = []
        path_patterns = []
        catg = node.getElementsByTagName('category')
        for cat in catg:
            if cat.getAttribute(f'{ns}:name') == 'android.intent.category.BROWSABLE':
                data_tag = node.getElementsByTagName('data')
                for data in data_tag:
                    scheme = data.getAttribute(f'{ns}:scheme')
                    if scheme and scheme not in schemes:
                        schemes.append(scheme)
                    mime = data.getAttribute(f'{ns}:mimeType')
                    if mime and mime not in mime_types:
                        mime_types.append(mime)
                    host = data.getAttribute(f'{ns}:host')
                    if host and host not in hosts:
                        hosts.append(host)
                    port = data.getAttribute(f'{ns}:port')
                    if port and port not in ports:
                        ports.append(port)
                    path = data.getAttribute(f'{ns}:path')
                    if path and path not in paths:
                        paths.append(path)
                    path_prefix = data.getAttribute(f'{ns}:pathPrefix')
                    if path_prefix and path_prefix not in path_prefixs:
                        path_prefixs.append(path_prefix)
                    path_pattern = data.getAttribute(f'{ns}:pathPattern')
                    if path_pattern and path_pattern not in path_patterns:
                        path_patterns.append(path_pattern)
        schemes = [scheme + '://' for scheme in schemes]
        browse_dic['schemes'] = schemes
        browse_dic['mime_types'] = mime_types
        browse_dic['hosts'] = hosts
        browse_dic['ports'] = ports
        browse_dic['paths'] = paths
        browse_dic['path_prefixs'] = path_prefixs
        browse_dic['path_patterns'] = path_patterns
        browse_dic['browsable'] = bool(browse_dic['schemes'])
        return browse_dic
    except Exception:
        logger.exception('Getting Browsable Activities')


def manifest_analysis(mfxml, ns, man_data_dic, src_type, app_dir):
    """Analyse manifest file."""
    # pylint: disable=C0301
    try:
        logger.info('Manifest Analysis Started')
        exp_count = dict.fromkeys(['act', 'ser', 'bro', 'cnt'], 0)
        applications = mfxml.getElementsByTagName('application')
        data_tag = mfxml.getElementsByTagName('data')
        intents = mfxml.getElementsByTagName('intent-filter')
        actions = mfxml.getElementsByTagName('action')
        granturipermissions = mfxml.getElementsByTagName(
            'grant-uri-permission')
        permissions = mfxml.getElementsByTagName('permission')
        ret_value = []
        ret_list = []
        exported = []
        browsable_activities = {}
        permission_dict = {}
        do_netsec = False
        debuggable = False
        # PERMISSION
        for permission in permissions:
            if permission.getAttribute(f'{ns}:protectionLevel'):
                protectionlevel = permission.getAttribute(
                    f'{ns}:protectionLevel')
                if protectionlevel == '0x00000000':
                    protectionlevel = 'normal'
                elif protectionlevel == '0x00000001':
                    protectionlevel = 'dangerous'
                elif protectionlevel == '0x00000002':
                    protectionlevel = 'signature'
                elif protectionlevel == '0x00000003':
                    protectionlevel = 'signatureOrSystem'

                permission_dict[permission.getAttribute(
                    f'{ns}:name')] = protectionlevel
            elif permission.getAttribute(f'{ns}:name'):
                permission_dict[permission.getAttribute(
                    f'{ns}:name')] = 'normal'
        # GENERAL
        if man_data_dic['min_sdk'] and int(man_data_dic['min_sdk']) < ANDROID_8_0_LEVEL:
            minsdk = man_data_dic.get('min_sdk')
            ret_list.append(('vulnerable_os_version', (minsdk,), ()))
        # APPLICATIONS
        # Handle multiple application tags in AAR
        backupDisabled = False
        for application in applications:
            # Esteve 23.07.2016 - begin - identify permission at the
            # application level
            if application.getAttribute(f'{ns}:permission'):
                perm_appl_level_exists = True
                perm_appl_level = application.getAttribute(
                    f'{ns}:permission')
            else:
                perm_appl_level_exists = False
            # End
            if application.getAttribute(f'{ns}:usesCleartextTraffic') == 'true':
                ret_list.append(('clear_text_traffic', (), ()))
            if application.getAttribute(f'{ns}:directBootAware') == 'true':
                ret_list.append(('direct_boot_aware', (), ()))
            if application.getAttribute(f'{ns}:networkSecurityConfig'):
                item = application.getAttribute(f'{ns}:networkSecurityConfig')
                ret_list.append(('has_network_security', (item,), ()))
                do_netsec = item
            if application.getAttribute(f'{ns}:debuggable') == 'true':
                ret_list.append(('app_is_debuggable', (), ()))
                debuggable = True
            if application.getAttribute(f'{ns}:allowBackup') == 'true':
                ret_list.append(('app_allowbackup', (), ()))
            elif application.getAttribute(f'{ns}:allowBackup') == 'false':
                backupDisabled = True
            else:
                if not backupDisabled:
                    ret_list.append(('allowbackup_not_set', (), ()))
            if application.getAttribute(f'{ns}:testOnly') == 'true':
                ret_list.append(('app_in_test_mode', (), ()))
            for node in application.childNodes:
                an_or_a = ''
                if node.nodeName == 'activity':
                    itemname = 'Activity'
                    cnt_id = 'act'
                    an_or_a = 'n'
                    browse_dic = get_browsable_activities(node, ns)
                    if browse_dic['browsable']:
                        browsable_activities[node.getAttribute(
                            f'{ns}:name')] = browse_dic
                elif node.nodeName == 'activity-alias':
                    itemname = 'Activity-Alias'
                    cnt_id = 'act'
                    an_or_a = 'n'
                    browse_dic = get_browsable_activities(node, ns)
                    if browse_dic['browsable']:
                        browsable_activities[node.getAttribute(
                            f'{ns}:name')] = browse_dic
                elif node.nodeName == 'provider':
                    itemname = 'Content Provider'
                    cnt_id = 'cnt'
                elif node.nodeName == 'receiver':
                    itemname = 'Broadcast Receiver'
                    cnt_id = 'bro'
                elif node.nodeName == 'service':
                    itemname = 'Service'
                    cnt_id = 'ser'
                else:
                    itemname = 'NIL'
                item = ''

                # Task Affinity
                if (
                        itemname in ['Activity', 'Activity-Alias'] and
                        node.getAttribute(f'{ns}:taskAffinity')
                ):
                    item = node.getAttribute(f'{ns}:name')
                    ret_list.append(('task_affinity_set', (item,), ()))

                # LaunchMode
                try:
                    affected_sdk = int(
                        man_data_dic['min_sdk']) < ANDROID_5_0_LEVEL
                except Exception:
                    # in case min_sdk is not defined we assume vulnerability
                    affected_sdk = True

                if (
                        affected_sdk and
                        itemname in ['Activity', 'Activity-Alias'] and
                        (node.getAttribute(f'{ns}:launchMode') == 'singleInstance'
                            or node.getAttribute(f'{ns}:launchMode') == 'singleTask')):
                    item = node.getAttribute(f'{ns}:name')
                    ret_list.append(('non_standard_launchmode', (item,), ()))
                # Exported Check
                item = ''
                is_inf = False
                is_perm_exist = False
                # Esteve 23.07.2016 - begin - initialise variables to identify
                # the existence of a permission at the component level that
                # matches a permission at the manifest level
                prot_level_exist = False
                protlevel = ''
                # End
                if itemname != 'NIL':
                    if node.getAttribute(f'{ns}:exported') == 'true':
                        perm = ''
                        item = node.getAttribute(f'{ns}:name')
                        if node.getAttribute(f'{ns}:permission'):
                            # permission exists
                            perm = ('<strong>Permission: </strong>'
                                    + node.getAttribute(f'{ns}:permission'))
                            is_perm_exist = True
                        if item != man_data_dic['mainactivity']:
                            if is_perm_exist:
                                prot = ''
                                if node.getAttribute(f'{ns}:permission') in permission_dict:
                                    prot = ('</br><strong>protectionLevel: </strong>'
                                            + permission_dict[node.getAttribute(f'{ns}:permission')])
                                    # Esteve 23.07.2016 - begin - take into account protection level of the permission when claiming that a component is protected by it;
                                    # - the permission might not be defined in the application being analysed, if so, the protection level is not known;
                                    # - activities (or activity-alias) that are exported and have an unknown or normal or dangerous protection level are
                                    # included in the EXPORTED data structure for further treatment; components in this situation are also
                                    # counted as exported.
                                    prot_level_exist = True
                                    protlevel = permission_dict[
                                        node.getAttribute(f'{ns}:permission')]
                                if prot_level_exist:
                                    if protlevel == 'normal':
                                        ret_list.append(
                                            ('exported_protected_permission_normal', (itemname, item, perm + prot), (an_or_a, itemname)))
                                        if itemname in ['Activity', 'Activity-Alias']:
                                            exported.append(item)
                                        exp_count[cnt_id] = exp_count[
                                            cnt_id] + 1
                                    elif protlevel == 'dangerous':
                                        ret_list.append(
                                            ('exported_protected_permission_dangerous', (itemname, item, perm + prot), (an_or_a, itemname)))
                                        if itemname in ['Activity', 'Activity-Alias']:
                                            exported.append(item)
                                        exp_count[cnt_id] = exp_count[
                                            cnt_id] + 1
                                    elif protlevel == 'signature':
                                        ret_list.append(
                                            ('exported_protected_permission_signature', (itemname, item, perm + prot), (an_or_a, itemname)))
                                    elif protlevel == 'signatureOrSystem':
                                        ret_list.append(
                                            ('exported_protected_permission_signatureorsystem', (itemname, item, perm + prot), (an_or_a, itemname)))
                                else:
                                    ret_list.append(
                                        ('exported_protected_permission_not_defined', (itemname, item, perm), (an_or_a, itemname)))
                                    if itemname in ['Activity', 'Activity-Alias']:
                                        exported.append(item)
                                    exp_count[cnt_id] = exp_count[cnt_id] + 1
                                # Esteve 23.07.2016 - end
                            else:
                                # Esteve 24.07.2016 - begin - At this point, we are dealing with components that do not have a permission neither at the component level nor at the
                                # application level. As they are exported, they
                                # are not protected.
                                if perm_appl_level_exists is False:
                                    ret_list.append(
                                        ('explicitly_exported', (itemname, item), (an_or_a, itemname)))
                                    if itemname in ['Activity', 'Activity-Alias']:
                                        exported.append(item)
                                    exp_count[cnt_id] = exp_count[cnt_id] + 1
                                # Esteve 24.07.2016 - end
                                # Esteve 24.07.2016 - begin - At this point, we are dealing with components that have a permission at the application level, but not at the component
                                #  level. Two options are possible:
                                #        1) The permission is defined at the manifest level, which allows us to differentiate the level of protection as
                                #           we did just above for permissions specified at the component level.
                                #        2) The permission is not defined at the manifest level, which means the protection level is unknown, as it is not
                                # defined in the analysed application.
                                else:
                                    perm = '<strong>Permission: </strong>' + perm_appl_level
                                    prot = ''
                                    if perm_appl_level in permission_dict:
                                        prot = ('</br><strong>protectionLevel: </strong>'
                                                + permission_dict[perm_appl_level])
                                        prot_level_exist = True
                                        protlevel = permission_dict[
                                            perm_appl_level]
                                    if prot_level_exist:
                                        if protlevel == 'normal':
                                            ret_list.append(
                                                ('exported_protected_permission_normal_app_level', (itemname, item, perm + prot), (an_or_a, itemname)))
                                            if itemname in ['Activity', 'Activity-Alias']:
                                                exported.append(item)
                                            exp_count[cnt_id] = exp_count[
                                                cnt_id] + 1
                                        elif protlevel == 'dangerous':
                                            ret_list.append(
                                                ('exported_protected_permission_dangerous_app_level', (itemname, item, perm + prot), (an_or_a, itemname)))
                                            if itemname in ['Activity', 'Activity-Alias']:
                                                exported.append(item)
                                            exp_count[cnt_id] = exp_count[
                                                cnt_id] + 1
                                        elif protlevel == 'signature':
                                            ret_list.append(
                                                ('exported_protected_permission', (itemname, item, perm + prot), (an_or_a, itemname)))
                                        elif protlevel == 'signatureOrSystem':
                                            ret_list.append(
                                                ('exported_protected_permission_signatureorsystem_app_level', (itemname, item, perm + prot), (an_or_a, itemname)))
                                    else:
                                        ret_list.append(
                                            ('exported_protected_permission_app_level', (itemname, item, perm), (an_or_a, itemname)))
                                        if itemname in ['Activity', 'Activity-Alias']:
                                            exported.append(item)
                                        exp_count[cnt_id] = exp_count[
                                            cnt_id] + 1
                                # Esteve 24.07.2016 - end

                    elif node.getAttribute(f'{ns}:exported') != 'false':
                        # Check for Implicitly Exported
                        # Logic to support intent-filter
                        intentfilters = node.childNodes
                        for i in intentfilters:
                            inf = i.nodeName
                            if inf == 'intent-filter':
                                is_inf = True
                        if is_inf:
                            item = node.getAttribute(f'{ns}:name')
                            if node.getAttribute(f'{ns}:permission'):
                                # permission exists
                                perm = ('<strong>Permission: </strong>'
                                        + node.getAttribute(f'{ns}:permission'))
                                is_perm_exist = True
                            if item != man_data_dic['mainactivity']:
                                if is_perm_exist:
                                    prot = ''
                                    if node.getAttribute(f'{ns}:permission') in permission_dict:
                                        prot = ('</br><strong>protectionLevel: </strong>'
                                                + permission_dict[node.getAttribute(f'{ns}:permission')])
                                        # Esteve 24.07.2016 - begin - take into account protection level of the permission when claiming that a component is protected by it;
                                        # - the permission might not be defined in the application being analysed, if so, the protection level is not known;
                                        # - activities (or activity-alias) that are exported and have an unknown or normal or dangerous protection level are
                                        #  included in the EXPORTED data structure for further treatment; components in this situation are also
                                        #  counted as exported.
                                        prot_level_exist = True
                                        protlevel = permission_dict[
                                            node.getAttribute(f'{ns}:permission')]
                                        if prot_level_exist:
                                            if protlevel == 'normal':
                                                ret_list.append(
                                                    ('exported_protected_permission_normal', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                if itemname in ['Activity', 'Activity-Alias']:
                                                    exported.append(item)
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                            elif protlevel == 'dangerous':
                                                ret_list.append(
                                                    ('exported_protected_permission_dangerous', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                if itemname in ['Activity', 'Activity-Alias']:
                                                    exported.append(item)
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                            elif protlevel == 'signature':
                                                ret_list.append(
                                                    ('exported_protected_permission_signature', (itemname, item, perm + prot), (an_or_a, itemname)))
                                            elif protlevel == 'signatureOrSystem':
                                                ret_list.append(
                                                    ('exported_protected_permission_signatureorsystem', (itemname, item, perm + prot), (an_or_a, itemname)))
                                    else:
                                        ret_list.append(
                                            ('exported_protected_permission_not_defined', (itemname, item, perm), (an_or_a, itemname)))
                                        if itemname in ['Activity', 'Activity-Alias']:
                                            exported.append(item)
                                        exp_count[cnt_id] = exp_count[
                                            cnt_id] + 1
                                    # Esteve 24.07.2016 - end
                                else:
                                    # Esteve 24.07.2016 - begin - At this point, we are dealing with components that do not have a permission neither at the component level nor at the
                                    # application level. As they are exported,
                                    # they are not protected.
                                    if perm_appl_level_exists is False:
                                        ret_list.append(
                                            ('exported_intent_filter_exists', (itemname, item), (an_or_a, itemname, itemname)))
                                        if itemname in ['Activity', 'Activity-Alias']:
                                            exported.append(item)
                                        exp_count[cnt_id] = exp_count[
                                            cnt_id] + 1
                                    # Esteve 24.07.2016 - end
                                    # Esteve 24.07.2016 - begin - At this point, we are dealing with components that have a permission at the application level, but not at the component
                                    # level. Two options are possible:
                                    # 1) The permission is defined at the manifest level, which allows us to differentiate the level of protection as
                                    #  we did just above for permissions specified at the component level.
                                    # 2) The permission is not defined at the manifest level, which means the protection level is unknown, as it is not
                                    #  defined in the analysed application.
                                    else:
                                        perm = '<strong>Permission: </strong>' + perm_appl_level
                                        prot = ''
                                        if perm_appl_level in permission_dict:
                                            prot = ('</br><strong>protectionLevel: </strong>'
                                                    + permission_dict[perm_appl_level])
                                            prot_level_exist = True
                                            protlevel = permission_dict[
                                                perm_appl_level]
                                        if prot_level_exist:
                                            if protlevel == 'normal':
                                                ret_list.append(
                                                    ('exported_protected_permission_normal_app_level', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                if itemname in ['Activity', 'Activity-Alias']:
                                                    exported.append(item)
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                            elif protlevel == 'dangerous':
                                                ret_list.append(
                                                    ('exported_protected_permission_dangerous_app_level', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                if itemname in ['Activity', 'Activity-Alias']:
                                                    exported.append(item)
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                            elif protlevel == 'signature':
                                                ret_list.append(
                                                    ('exported_protected_permission', (itemname, item, perm + prot), (an_or_a, itemname)))
                                            elif protlevel == 'signatureOrSystem':
                                                ret_list.append(
                                                    ('exported_protected_permission_signatureorsystem_app_level', (itemname, item, perm + prot), (an_or_a, itemname)))
                                        else:
                                            ret_list.append(
                                                ('exported_protected_permission_app_level', (itemname, item, perm), (an_or_a, itemname)))
                                            if itemname in ['Activity', 'Activity-Alias']:
                                                exported.append(item)
                                            exp_count[cnt_id] = exp_count[
                                                cnt_id] + 1
                                    # Esteve 24.07.2016 - end
                                    # Esteve 29.07.2016 - begin The component is not explicitly exported (android:exported is not 'true'). It is not implicitly exported either (it does not
                                    # make use of an intent filter). Despite that, it could still be exported by default, if it is a content provider and the android:targetSdkVersion
                                    # is older than 17 (Jelly Bean, Android version 4.2). This is true regardless of the system's API level.
                                    # Finally, it must also be taken into account that, if the minSdkVersion is greater or equal than 17, this check is unnecessary, because the
                                    # app will not be run on a system where the
                                    # system's API level is below 17.
                        else:
                            if man_data_dic['min_sdk'] and man_data_dic['target_sdk'] and int(man_data_dic['min_sdk']) < ANDROID_4_2_LEVEL:
                                if itemname == 'Content Provider' and int(man_data_dic['target_sdk']) < ANDROID_4_2_LEVEL:
                                    perm = ''
                                    item = node.getAttribute(f'{ns}:name')
                                    if node.getAttribute(f'{ns}:permission'):
                                        # permission exists
                                        perm = ('<strong>Permission: </strong>'
                                                + node.getAttribute(f'{ns}:permission'))
                                        is_perm_exist = True
                                    if is_perm_exist:
                                        prot = ''
                                        if node.getAttribute(f'{ns}:permission') in permission_dict:
                                            prot = ('</br><strong>protectionLevel: </strong>'
                                                    + permission_dict[node.getAttribute(f'{ns}:permission')])
                                            prot_level_exist = True
                                            protlevel = permission_dict[
                                                node.getAttribute(f'{ns}:permission')]
                                        if prot_level_exist:
                                            if protlevel == 'normal':
                                                ret_list.append(
                                                    ('exported_provider_normal', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                            elif protlevel == 'dangerous':
                                                ret_list.append(
                                                    ('exported_provider_danger', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                            elif protlevel == 'signature':
                                                ret_list.append(
                                                    ('exported_provider_signature', (itemname, item, perm + prot), (an_or_a, itemname)))
                                            elif protlevel == 'signatureOrSystem':
                                                ret_list.append(
                                                    ('exported_provider_signatureorsystem', (itemname, item, perm + prot), (an_or_a, itemname)))
                                        else:
                                            ret_list.append(
                                                ('exported_provider_unknown', (itemname, item, perm), (an_or_a, itemname)))
                                            exp_count[cnt_id] = exp_count[
                                                cnt_id] + 1
                                    else:
                                        if perm_appl_level_exists is False:
                                            ret_list.append(
                                                ('exported_provider', (itemname, item), (an_or_a, itemname)))
                                            exp_count[cnt_id] = exp_count[
                                                cnt_id] + 1
                                        else:
                                            perm = '<strong>Permission: </strong>' + perm_appl_level
                                            prot = ''
                                            if perm_appl_level in permission_dict:
                                                prot = ('</br><strong>protectionLevel: </strong>'
                                                        + permission_dict[perm_appl_level])
                                                prot_level_exist = True
                                                protlevel = permission_dict[
                                                    perm_appl_level]
                                            if prot_level_exist:
                                                if protlevel == 'normal':
                                                    ret_list.append(
                                                        ('exported_provider_normal_app', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                    exp_count[cnt_id] = exp_count[
                                                        cnt_id] + 1
                                                elif protlevel == 'dangerous':
                                                    ret_list.append(
                                                        ('exported_provider_danger_appl', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                    exp_count[cnt_id] = exp_count[
                                                        cnt_id] + 1
                                                elif protlevel == 'signature':
                                                    ret_list.append(
                                                        ('exported_provider_signature_appl', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                elif protlevel == 'signatureOrSystem':
                                                    ret_list.append(
                                                        ('exported_provider_signatureorsystem_app', (itemname, item, perm + prot), (an_or_a, itemname)))
                                            else:
                                                ret_list.append(
                                                    ('exported_provider_unknown_app', (itemname, item, perm), (an_or_a, itemname)))
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                    # Esteve 29.07.2016 - end
                                    # Esteve 08.08.2016 - begin - If the content provider does not target an API version lower than 17, it could still be exported by default, depending
                                    # on the API version of the platform. If it was below 17, the content
                                    # provider would be exported by default.
                                else:
                                    if itemname == 'Content Provider' and int(man_data_dic['target_sdk']) >= 17:
                                        perm = ''
                                        item = node.getAttribute(
                                            f'{ns}:name')
                                        if node.getAttribute(f'{ns}:permission'):
                                            # permission exists
                                            perm = ('<strong>Permission: </strong>'
                                                    + node.getAttribute(f'{ns}:permission'))
                                            is_perm_exist = True
                                        if is_perm_exist:
                                            prot = ''
                                            if node.getAttribute(f'{ns}:permission') in permission_dict:
                                                prot = ('</br><strong>protectionLevel: </strong>'
                                                        + permission_dict[node.getAttribute(f'{ns}:permission')])
                                                prot_level_exist = True
                                                protlevel = permission_dict[
                                                    node.getAttribute(f'{ns}:permission')]
                                            if prot_level_exist:
                                                if protlevel == 'normal':
                                                    ret_list.append(
                                                        ('exported_provider_normal_new', (itemname, item, perm + prot), (itemname)))
                                                    exp_count[cnt_id] = exp_count[
                                                        cnt_id] + 1
                                                if protlevel == 'dangerous':
                                                    ret_list.append(
                                                        ('exported_provider_danger_new', (itemname, item, perm + prot), (itemname)))
                                                    exp_count[cnt_id] = exp_count[
                                                        cnt_id] + 1
                                                if protlevel == 'signature':
                                                    ret_list.append(
                                                        ('exported_provider_signature_new', (itemname, item, perm + prot), (itemname)))
                                                if protlevel == 'signatureOrSystem':
                                                    ret_list.append(
                                                        ('exported_provider_signatureorsystem_new', (itemname, item, perm + prot), (an_or_a, itemname)))
                                            else:
                                                ret_list.append(
                                                    ('exported_provider_unknown_new', (itemname, item, perm), (itemname)))
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                        else:
                                            if perm_appl_level_exists is False:
                                                ret_list.append(
                                                    ('exported_provider_2', (itemname, item), (an_or_a, itemname)))
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                            else:
                                                perm = '<strong>Permission: </strong>' + perm_appl_level
                                                prot = ''
                                                if perm_appl_level in permission_dict:
                                                    prot = ('</br><strong>protectionLevel: </strong>'
                                                            + permission_dict[perm_appl_level])
                                                    prot_level_exist = True
                                                    protlevel = permission_dict[
                                                        perm_appl_level]
                                                if prot_level_exist:
                                                    if protlevel == 'normal':
                                                        ret_list.append(
                                                            ('exported_provider_normal_app_new', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                        exp_count[cnt_id] = exp_count[
                                                            cnt_id] + 1
                                                    elif protlevel == 'dangerous':
                                                        ret_list.append(
                                                            ('exported_provider_danger_app_new', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                        exp_count[cnt_id] = exp_count[
                                                            cnt_id] + 1
                                                    elif protlevel == 'signature':
                                                        ret_list.append(
                                                            ('exported_provider_signature_app_new', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                    elif protlevel == 'signatureOrSystem':
                                                        ret_list.append(
                                                            ('exported_provider_signatureorsystem_app_new', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                else:
                                                    ret_list.append(
                                                        ('exported_provider_unknown_app_new', (itemname, item, perm), (an_or_a, itemname)))
                                                    exp_count[cnt_id] = exp_count[
                                                        cnt_id] + 1
                                    # Esteve 08.08.2016 - end

        # GRANT-URI-PERMISSIONS
        for granturi in granturipermissions:
            if granturi.getAttribute(f'{ns}:pathPrefix') == '/':
                ret_list.append(
                    ('improper_provider_permission', ('pathPrefix=/',), ()))
            elif granturi.getAttribute(f'{ns}:path') == '/':
                ret_list.append(('improper_provider_permission', ('path=/',), ()))
            elif granturi.getAttribute(f'{ns}:pathPattern') == '*':
                ret_list.append(('improper_provider_permission', ('path=*',), ()))
        # DATA
        for data in data_tag:
            if data.getAttribute(f'{ns}:scheme') == 'android_secret_code':
                xmlhost = data.getAttribute(f'{ns}:host')
                ret_list.append(('dialer_code_found', (xmlhost,), ()))

            elif data.getAttribute(f'{ns}:port'):
                dataport = data.getAttribute(f'{ns}:port')
                ret_list.append(('sms_receiver_port_found', (dataport,), ()))
        # INTENTS
        for intent in intents:
            if intent.getAttribute(f'{ns}:priority').isdigit():
                value = intent.getAttribute(f'{ns}:priority')
                if int(value) > 100:
                    ret_list.append(
                        ('high_intent_priority_found', (value,), ()))
        # ACTIONS
        for action in actions:
            if action.getAttribute(f'{ns}:priority').isdigit():
                value = action.getAttribute(f'{ns}:priority')
                if int(value) > 100:
                    ret_list.append(
                        ('high_action_priority_found', (value,), ()))
        for a_key, t_name, t_desc in ret_list:
            a_template = android_manifest_desc.MANIFEST_DESC.get(a_key)
            if a_template:
                ret_value.append({
                    'rule': a_key,
                    'title': a_template['title'] % t_name,
                    'severity': a_template['level'],
                    'description': a_template['description'] % t_desc,
                    'name': a_template['name'] % t_name,
                    'component': t_name,
                })
            else:
                logger.warning("No template found for key '%s'", a_key)

        for category in man_data_dic['categories']:
            if category == 'android.intent.category.LAUNCHER':
                break

        permissions = {}
        for k, permission in man_data_dic['perm'].items():
            permissions[k] = (
                {
                    'status': permission[0],
                    'info': permission[1],
                    'description': permission[2],
                })
        # Prepare return dict
        exported_comp = {
            'exported_activities': exp_count['act'],
            'exported_services': exp_count['ser'],
            'exported_receivers': exp_count['bro'],
            'exported_providers': exp_count['cnt'],
        }
        man_an_dic = {
            'manifest_anal': ret_value,
            'exported_act': exported,
            'exported_cnt': exported_comp,
            'browsable_activities': browsable_activities,
            'permissions': permissions,
            'network_security': network_security.analysis(
                app_dir,
                do_netsec,
                debuggable,
                src_type),
        }
        return man_an_dic
    except Exception:
        logger.exception('Performing Manifest Analysis')
