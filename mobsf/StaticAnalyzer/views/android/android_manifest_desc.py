MANIFEST_DESC = {
    'clear_text_traffic': {
        'title': ('Clear text traffic is Enabled For App'
                  '<br>[android:usesCleartextTraffic=true]'),
        'level': 'high',
        'description': ('The app intends to use cleartext network traffic,'
                        ' such as cleartext HTTP, FTP stacks, DownloadManager,'
                        ' and MediaPlayer. The default value for'
                        ' apps that target API level 27 or lower is "true". '
                        'Apps that target API level 28 or higher default to'
                        ' "false". The key reason for avoiding cleartext'
                        ' traffic is the lack of confidentiality, '
                        'authenticity, and protections against tampering; '
                        'a network attacker can eavesdrop on transmitted '
                        'data and also modify it without being detected.'),
        'name': ('Clear text traffic is Enabled For App '
                 '[android:usesCleartextTraffic=true]'),
    },
    'direct_boot_aware': {
        'title': 'App is direct-boot aware <br>[android:directBootAware=true]',
        'level': 'info',
        'description': ('This app can run before the user unlocks the device. '
                        'If you\'re using a custom subclass of Application, '
                        'and if any component inside your application is '
                        'direct - boot aware, then your entire custom '
                        'application is considered to be direct - boot aware.'
                        'During Direct Boot, your application can only access'
                        ' the data that is stored'
                        ' in device protected storage.'),
        'name': 'App is direct-boot aware [android:directBootAware=true]',
    },
    'has_network_security': {
        'title': ('App has a Network Security Configuration'
                  '<br>[android:networkSecurityConfig=%s]'),
        'level': 'info',
        'description': ('The Network Security Configuration feature lets apps'
                        ' customize their network security settings in a safe,'
                        ' declarative configuration file without modifying '
                        'app code. These settings can be configured for '
                        'specific domains and for a specific app. '),
        'name': ('App has a Network Security Configuration '
                 '[android:networkSecurityConfig=%s]'),
    },
    'vulnerable_os_version': {
        'title': ('App can be installed on a vulnerable Android version'
                  '<br>[minSdk=%s]'),
        'level': 'warning',
        'description': ('This application can be installed on an older version'
                        ' of android that has multiple unfixed '
                        'vulnerabilities. Support an Android version > 8, '
                        'API 26 to receive reasonable security updates.'),
        'name': ('App can be installed on a vulnerable Android version'
                 '[minSdk=%s]'),
    },
    'app_is_debuggable': {
        'title': 'Debug Enabled For App<br>[android:debuggable=true]',
        'level': 'high',
        'description': ('Debugging was enabled on the app which makes it '
                        'easier for reverse engineers to hook a debugger to'
                        ' it. This allows dumping a stack trace and accessing'
                        ' debugging helper classes.'),
        'name': 'Debug Enabled For App [android:debuggable=true]',
    },
    'app_allowbackup': {
        'title': ('Application Data can be Backed up'
                  '<br>[android:allowBackup=true]'),
        'level': 'warning',
        'description': ('This flag allows anyone to backup your application'
                        ' data via adb. It allows users who have enabled USB'
                        ' debugging to copy application data off of the'
                        ' device.'),
        'name': 'Application Data can be Backed up [android:allowBackup=true]',
    },
    'allowbackup_not_set': {
        'title': ('Application Data can be Backed up<br>[android:allowBackup]'
                  ' flag is missing.'),
        'level': 'warning',
        'description': ('The flag [android:allowBackup] should be set to false'
                        '. By default it is set to true and allows anyone to '
                        'backup your application data via adb. It allows users'
                        ' who have enabled USB debugging to copy application '
                        'data off of the device.'),
        'name': ('Application Data can be Backed up [android:allowBackup] flag'
                 ' is missing.'),
    },
    'app_in_test_mode': {
        'title': 'Application is in Test Mode <br>[android:testOnly=true]',
        'level': 'high',
        'description': ('It may expose functionality or data outside of itself'
                        ' that would cause a security hole.'),
        'name': 'Application is in Test Mode [android:testOnly=true]',
    },
    'task_affinity_set': {
        'title': 'TaskAffinity is set for activity <br>(%s)',
        'level': 'warning',
        'description': ('If taskAffinity is set, then other application'
                        ' could read the Intents sent to Activities '
                        'belonging to another task. Always use the default'
                        ' setting keeping the affinity as the package name'
                        ' in order to prevent sensitive information inside'
                        ' sent or received Intents from being read by '
                        'another application.'),
        'name': 'TaskAffinity is set for Activity (%s)',
    },
    'non_standard_launchmode': {
        'title': 'Launch Mode of activity (%s) is not standard.',
        'level': 'high',
        'description': ('An Activity should not be having the launch mode'
                        ' attribute set to "singleTask/singleInstance" as '
                        'it becomes root Activity and it is possible for'
                        ' other applications to read the contents of the'
                        ' calling Intent. So it is required to use the'
                        ' "standard" launch mode attribute when sensitive'
                        ' information is included in an Intent.'),
        'name': 'Launch Mode of activity (%s) is not standard.',
    },
    'improper_provider_permission': {
        'title': 'Improper Content Provider Permissions<br>[%s]',
        'level': 'high',
        'description': ('A content provider permission was set to allows'
                        ' access from any other app on the device. '
                        'Content providers may contain sensitive '
                        'information about an app and therefore '
                        'should not be shared.'),
        'name': 'Improper Content Provider Permissions',
    },
    'dialer_code_found': {
        'title': ('Dailer Code: %s Found'
                  ' <br>[android:scheme="android_secret_code"]'),
        'level': 'warning',
        'description': ('A secret code was found in the manifest. These codes,'
                        ' when entered into the dialer grant access to hidden'
                        ' content that may contain sensitive information.'),
        'name': ('Dailer Code: %s Found.'
                 ' [android:scheme="android_secret_code"]'),
    },
    'sms_receiver_port_found': {
        'title': 'Data SMS Receiver Set on Port: %s Found<br>[android:port]',
        'level': 'warning',
        'description': ('A binary SMS receiver is configured to listen on a'
                        ' port. Binary SMS messages sent to a device are '
                        'processed by the application in whichever way the'
                        ' developer choses. The data in this SMS should be'
                        ' properly validated by the application. Furthermore,'
                        ' the application should assume that the SMS being'
                        ' received is from an untrusted source.'),
        'name': 'Data SMS Receiver Set on Port: %s Found. [android:port]',
    },
    'high_intent_priority_found': {
        'title': 'High Intent Priority (%s)<br>[android:priority]',
        'level': 'warning',
        'description': ('By setting an intent priority higher than another'
                        ' intent, the app effectively overrides '
                        'other requests.'),
        'name': 'High Intent Priority (%s). [android:priority]',
    },
    'high_action_priority_found': {
        'title': 'High Action Priority (%s)<br>[android:priority] ',
        'level': 'warning',
        'description': ('By setting an action priority higher than'
                        ' another action, the app effectively '
                        'overrides other requests.'),
        'name': 'High Action Priority (%s). [android:priority]',
    },
    'exported_protected_permission_signature': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission.'
                  '<br>%s<br>[android:exported=true]'),
        'level': 'info',
        'description': ('A%s %s is found to be exported, but'
                        ' is protected by permission.'),
        'name': ('%s %s is Protected by a permission.'
                 ' [%s] [android:exported=true]'),
    },
    'exported_protected_permission_normal': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, but'
                  ' the protection level of the permission should be checked.'
                  '<br>%s <br>[android:exported=true]'),
        'level': 'warning',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device. It is protected by a '
                        'permission. However, the protection level of the'
                        '  permission is set to normal. This means that a '
                        'malicious application can request and obtain'
                        ' the permission and interact with the component.'
                        ' If it was set to signature, only applications '
                        'signed with the same certificate could obtain '
                        'the permission.'),
        'name': ('%s %s is Protected by a permission,'
                 ' but the protection level of'
                 ' the permission should be checked.'
                 ' [%s] [android:exported=true]'),
    },
    'exported_protected_permission_dangerous': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, but'
                  ' the protection level of the permission should be checked.'
                  '<br>%s <br>[android:exported=true]'),
        'level': 'warning',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device. It is protected by a'
                        ' permission. However, the protection level of the'
                        ' permission is set to dangerous. This means that a'
                        ' malicious application can request and obtain the'
                        ' permission and interact with the component. If it'
                        ' was set to signature, only applications signed with'
                        ' the same certificate could obtain the permission.'),
        'name': ('%s %s is Protected by a permission,'
                 ' but the protection level of'
                 ' the permission should be checked.'
                 ' [%s] [android:exported=true]'),
    },
    'exported_protected_permission_signatureorsystem': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, but'
                  ' the protection level of the permission should be checked.'
                  '<br>%s <br>[android:exported=true]'),
        'level': 'info',
        'description': ('A%s %s is found to be exported, but is protected by'
                        ' a permission. However, the protection level of the'
                        ' permission is set to signatureOrSystem. It is '
                        'recommended that signature level is used instead. '
                        'Signature level should suffice for most purposes, '
                        'and does not depend on where the applications are '
                        'installed on the device.'),
        'name': ('%s %s is Protected by a permission,'
                 ' but the protection level of'
                 ' the permission should be checked.'
                 ' [%s] [android:exported=true]'),
    },
    'exported_protected_permission_not_defined': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, but'
                  ' the protection level of the permission should be checked.'
                  '<br>%s <br>[android:exported=true]'),
        'level': 'warning',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device. It is protected by a '
                        'permission which is not defined in the analysed '
                        'application. As a result, the protection level of the'
                        ' permission should be checked where it is defined. If'
                        ' it is set to normal or dangerous, a malicious '
                        'application can request and obtain the permission and'
                        ' interact with the component. If it is set to '
                        'signature, only applications signed with the same '
                        'certificate can obtain the permission.'),
        'name': ('%s %s is Protected by a permission,'
                 ' but the protection level '
                 'of the permission should be '
                 'checked. [%s] [android:exported=true]'),
    },
    'exported_protected_permission_normal_app_level': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' the application level, but the protection level of the '
                  'permission should be checked.<br>%s <br>'
                  '[android:exported=true]'),
        'level': 'warning',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device.  It is protected by a '
                        'permission at the application level. However, the'
                        ' protection level of the permission is set to normal.'
                        ' This means that a malicious application can request '
                        'and obtain the permission and interact with the '
                        'component. If it was set to signature, only '
                        'applications signed with the same certificate '
                        'could obtain the permission.'),
        'name': ('%s %s is Protected by a permission at the application level,'
                 ' but the protection level of the permission should be '
                 'checked. [%s] [android:exported=true]'),
    },
    'exported_protected_permission_dangerous_app_level': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' the application level, but the protection level of the '
                  'permission should be checked.'
                  '<br>%s <br>[android:exported=true]'),
        'level': 'warning',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device. It is protected by a '
                        'permission at the application level. However, the '
                        'protection level of the permission is set to '
                        'dangerous. This means that a malicious application '
                        'can request and obtain the permission and interact '
                        'with the component. If it was set to signature, '
                        'only applications signed with the same certificate'
                        ' could obtain the permission.'),
        'name': ('%s %s is Protected by a permission'
                 ' at the application level, but'
                 ' the protection level of the permission should be '
                 'checked. [%s] [android:exported=true]'),
    },
    'exported_protected_permission': {
        'title': ('<strong>%s</strong> (%s)  Protected by a permission at'
                  ' the application level.<br>%s<br>[android:exported=true]'),
        'level': 'info',
        'description': ('A%s %s is found to be exported, but is protected by'
                        ' a permission at the application level.'),
        'name': ('%s %s Protected by a permission at the application level.'
                 ' [%s] [android:exported=true]'),
    },
    'exported_protected_permission_signatureorsystem_app_level': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at '
                  'the application level, but the protection level of the '
                  'permission should be checked.'
                  '<br>%s <br>[android:exported=true]'),
        'level': 'info',
        'description': ('A%s %s is found to be exported, but is protected '
                        'by a permission at the application level. However,'
                        ' the protection level of the permission is set to'
                        ' signatureOrSystem. It is recommended that '
                        'signature level is used instead. Signature level'
                        ' should suffice for most purposes, and does not '
                        'depend on where the applications are installed'
                        ' on the device.'),
        'name': ('%s %s is Protected by a permission'
                 ' at the application level, but'
                 ' the protection level of the permission should be checked.'
                 ' [%s] [android:exported=true]'),
    },
    'exported_protected_permission_app_level': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission'
                  ' at the application, but the protection level of the '
                  'permission should be checked.'
                  '<br>%s <br>[android:exported=true]'),
        'level': 'warning',
        'description': ('A%s %s is found to be shared with other apps on '
                        'the device therefore leaving it accessible to any'
                        ' other application on the device. It is protected'
                        ' by a permission at the application level which is'
                        ' not defined in the analysed application. As a'
                        ' result, the protection level of the permission'
                        ' should be checked where it is defined. If it is'
                        ' set to normal or dangerous, a malicious application'
                        ' can request and obtain the permission and interact'
                        ' with the component. If it is set to signature, only'
                        ' applications signed with the same certificate can'
                        ' obtain the permission.'),
        'name': ('%s %s is Protected by a permission'
                 ' at the application, but the'
                 ' protection level of the permission should be checked.'
                 ' [%s] [android:exported=true]'),
    },
    'explicitly_exported': {
        'title': ('<strong>%s</strong> (%s) is not Protected.'
                  ' <br>[android:exported=true]'),
        'level': 'high',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device.'),
        'name': '%s %s is not Protected. [android:exported=true]',
    },
    'exported_intent_filter_exists': {
        'title': ('<strong>%s</strong> (%s) is not Protected.<br>'
                  'An intent-filter exists.'),
        'level': 'warning',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other '
                        'application on the device. The presence of '
                        'intent-filter indicates that the %s'
                        ' is explicitly exported.'),
        'name': '%s %s is not Protected.An intent-filter exists.',
    },
    'exported_provider': {
        'title': ('<strong>%s</strong> (%s) is not Protected. <br>'
                  '[Content Provider, targetSdkVersion < 17]'),
        'level': 'warning',
        'description': ('A%s %s is found to be shared with other apps'
                        ' on the device therefore leaving it accessible '
                        'to any other application on the device. It is '
                        'a Content Provider that targets an API level '
                        'under 17, which makes it exported by default,'
                        ' regardless of the API level of the system '
                        'that the application runs on.'),
        'name': ('%s %s is not Protected.'
                 ' [Content Provider, targetSdkVersion < 17]'),
    },
    'exported_provider_2': {
        'title': ('<strong>%s</strong> (%s) would not be Protected if the'
                  ' application ran on a device where the the API level was'
                  ' less than 17. <br>[Content Provider, '
                  'targetSdkVersion >= 17]'),
        'level': 'warning',
        'description': ('The Content Provider(%s %s) would be exported if the'
                        ' application ran on a device where the the API level '
                        'was less than 17. In that situation, it would be '
                        'shared with other apps on the device therefore '
                        'leaving it accessible to any other application '
                        'on the device.'),
        'name': ('%s %s would not be Protected if'
                 ' the application ran on a device'
                 ' where the the API level was less than 17.'
                 ' [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_normal': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, but'
                  ' the protection level of the permission should be checked.'
                  '<br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'warning',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device. It is protected by a '
                        'permission. However, the protection level of the'
                        ' permission is set to normal. This means that a '
                        'malicious application can request and obtain '
                        'the permission and interact with the component. '
                        'If it was set to signature, only applications signed '
                        'with the same certificate could obtain '
                        'the permission.'),
        'name': ('%s %s is Protected by a permission,'
                 ' but the protection level'
                 ' of the permission should be checked.'
                 ' [%s] [Content Provider,'
                 ' targetSdkVersion < 17]'),
    },
    'exported_provider_danger': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, '
                  'but the protection level of the permission should be '
                  'checked.<br>%s <br>[Content Provider, '
                  'targetSdkVersion < 17]'),
        'level': 'warning',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device. It is protected by a '
                        'permission. However, the protection level of the '
                        'permission is set to dangerous. This means that a '
                        'malicious application can request and obtain the '
                        'permission and interact with the component. If it'
                        ' was set to signature, only applications signed with'
                        ' the same certificate could obtain '
                        'the permission.'),
        'name': ('%s %s is Protected by a permission,'
                 ' but the protection level of '
                 'the permission should be checked. [%s] [Content Provider, '
                 'targetSdkVersion < 17]'),
    },
    'exported_provider_signature': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission.'
                  '<br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'info',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device. It is '
                        'protected by permission.'),
        'name': ('%s %s is Protected by a permission. [%s] [Content Provider, '
                 'targetSdkVersion < 17]'),
    },
    'exported_provider_signatureorsystem': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission,'
                  ' but the protection level of the permission should be '
                  'checked.<br>%s <br>[Content Provider, '
                  'targetSdkVersion < 17]'),
        'level': 'info',
        'description': ('A%s %s is found to be exported, but is protected by'
                        ' a permission. However, the protection level of the'
                        ' permission is set to signatureOrSystem. It is'
                        ' recommended that signature level is used instead.'
                        ' Signature level should suffice for most purposes,'
                        ' and does not depend on where the applications are'
                        ' installed on the device.'),
        'name': ('%s %s is Protected by a permission,'
                 ' but the protection level of '
                 'the permission should be checked. [%s] [Content Provider, '
                 'targetSdkVersion < 17]'),
    },
    'exported_provider_unknown': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, but'
                  ' the protection level of the permission should be checked.'
                  '<br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'warning',
        'description': ('A%s %s is found to be shared with other apps on the '
                        'device therefore leaving it accessible to any other '
                        'application on the device. It is protected by a '
                        'permission which is not defined in the analysed '
                        'application. As a result, the protection level of the'
                        ' permission should be checked where it is defined. If'
                        ' it is set to normal or dangerous, a malicious '
                        'application can request and obtain the permission and'
                        ' interact with the component. If it is set to '
                        'signature, only applications signed with the same '
                        'certificate can obtain the permission.'),
        'name': ('%s %s is Protected by a permission,'
                 ' but the protection level of'
                 ' the permission should be checked. [%s] [Content Provider,'
                 ' targetSdkVersion < 17]'),
    },
    'exported_provider_normal_app': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' the application level, but the protection level of the'
                  ' permission should be checked.'
                  '<br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'warning',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device. It is protected by a'
                        ' permission at the application level. However, the'
                        ' protection level of the permission is set to normal.'
                        ' This means that a malicious application can request'
                        ' and obtain the permission and interact with the'
                        ' component. If it was set to signature, only '
                        'applications signed with the same certificate could'
                        ' obtain the permission.'),
        'name': ('%s %s is Protected by a permission'
                 ' at the application level, but'
                 ' the protection level of the permission should be checked.'
                 ' [%s] [Content Provider, targetSdkVersion < 17]'),
    },
    'exported_provider_danger_appl': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at '
                  'the application level, but the protection level of the '
                  'permission should be checked.'
                  '<br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'warning',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device. It is protected by a '
                        'permission at the application level. However, the '
                        'protection level of the permission is set to '
                        'dangerous. This means that a malicious application'
                        ' can request and obtain the permission and interact'
                        ' with the component. If it was set to signature, '
                        'only applications signed with the same certificate'
                        ' could obtain the permission.'),
        'name': ('%s %s is Protected by a permission'
                 ' at the application level, but'
                 ' the protection level of the permission should be checked.'
                 '[%s] [Content Provider, targetSdkVersion < 17]'),
    },
    'exported_provider_signature_appl': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' the application level.<br>%s <br>[Content Provider,'
                  ' targetSdkVersion < 17]'),
        'level': 'info',
        'description': ('A%s %s is found to be shared with other apps on'
                        ' the device therefore leaving it accessible to any'
                        ' other application on the device. It is protected '
                        'by permission at the application level.'),
        'name': ('%s %s is Protected by a permission at the application level.'
                 '[%s] [Content Provider, targetSdkVersion < 17]'),
    },
    'exported_provider_signatureorsystem_app': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' the application level, but the protection level of the'
                  ' permission should be checked.'
                  '<br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'info',
        'description': ('A%s %s is found to be exported, but is protected by'
                        ' a permission at the application level. However, the'
                        ' protection level of the permission is set to '
                        'signatureOrSystem. It is recommended that signature '
                        'level is used instead. Signature level should suffice'
                        ' for most purposes, and does not depend on where the'
                        ' applications are installed on the device.'),
        'name': ('%s %s is Protected by a permission'
                 ' at the application level, '
                 'but the protection level of the permission should be '
                 'checked. [%s] [Content Provider, targetSdkVersion < 17]'),
    },
    'exported_provider_unknown_app': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' application level, but the protection level of the '
                  'permission should be checked.<br>%s '
                  '<br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'warning',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device. It is protected by a '
                        'permission at application level which is not defined'
                        ' in the analysed application. As a result, the '
                        'protection level of the permission should be checked'
                        ' where it is defined. If it is set to normal or '
                        'dangerous, a malicious application can request and'
                        ' obtain the permission and interact with the '
                        'component. If it is set to signature, only '
                        'applications signed with the same certificate '
                        'can obtain the permission.'),
        'name': ('%s %s is Protected by a permission at application level, but'
                 ' the protection level of the permission should be checked.'
                 ' [%s] [Content Provider, targetSdkVersion < 17]'),
    },
    'exported_provider_normal_new': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, '
                  'but the protection level of the permission should be '
                  'checked if the application runs on a device where the '
                  'the API level is less than 17'
                  '<br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'warning',
        'description': ('The Content Provider (%s) would be exported if the'
                        ' application ran on a device where the the API level'
                        ' was less than 17. In that situation, it would still'
                        ' be protected by a permission. However, the '
                        'protection level of the permission is set to normal. '
                        'This means that a malicious application could request'
                        ' and obtain the permission and interact with the'
                        ' component. If it was set to signature, only'
                        ' applications signed with the same certificate '
                        'could obtain the permission.'),
        'name': ('%s %s is Protected by a permission,'
                 ' but the protection level of'
                 ' the permission should be checked if the application runs '
                 'on a device where the the API level is less than 17 '
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_danger_new': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission,'
                  ' but the protection level of the permission should be '
                  'checked if the application runs on a device where '
                  'the API level is less than 17.<br>%s <br>'
                  '[Content Provider, targetSdkVersion >= 17]'),
        'level': 'warning',
        'description': ('The Content Provider(%s) would be exported if the'
                        ' application ran on a device where the the API level'
                        ' was less than 17. In that situation, it would still'
                        ' be protected by a permission. However, the '
                        'protection level of the permission is set to'
                        ' dangerous. This means that a malicious application'
                        ' could request and obtain the permission and interact'
                        ' with the component. If it was set to signature, only'
                        ' applications signed with the same certificate could'
                        ' obtain the permission.'),
        'name': ('%s %s is Protected by a permission'
                 ', but the protection level of'
                 ' the permission should be checked if the application runs on'
                 ' a device where the the API level is less than 17.'
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_signature_new': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission.'
                  '<br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'info',
        'description': ('The Content Provider(%s) would be exported if the'
                        ' application ran on a device where the the API level'
                        ' was less than 17. Nevertheless, it is protected '
                        'by a permission.'),
        'name': ('%s %s is Protected by a permission.'
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_signatureorsystem_new': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, but'
                  ' the protection level of the permission should be checked.'
                  '<br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'info',
        'description': ('The Content Provider(%s) would be exported if the '
                        'application ran on a device where the API level was'
                        ' less than 17. In that situation, it would still '
                        'be protected by a permission. However, the protection'
                        ' level of the permission is set to signatureOrSystem.'
                        ' It is recommended that signature level is used '
                        'instead. Signature level should suffice for most'
                        ' purposes, and does not depend on where the'
                        ' applications are installed on the device.'),
        'name': ('%s %s is Protected by a permission,'
                 ' but the protection level of'
                 ' the permission should be checked.'
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_unknown_new': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, but'
                  ' the protection level of the permission should be checked'
                  ' if the application runs on a device where the the API '
                  'level is less than 17.<br>%s <br>'
                  '[Content Provider, targetSdkVersion >= 17]'),
        'level': 'warning',
        'description': ('The Content Provider(%s) would be exported if the'
                        ' application ran on a device where the the API level'
                        ' was less than 17. In that situation, it would still'
                        ' be protected by a permission which is not defined in'
                        ' the analysed application. As a result, the '
                        'protection level of the permission should be '
                        'checked where it is defined. If it is set to normal'
                        ' or dangerous, a malicious application can request'
                        ' and obtain the permission and interact with the '
                        'component. If it is set to signature, only '
                        'applications signed with the same certificate'
                        ' can obtain the permission.'),
        'name': ('%s %s is Protected by a permission, but the'
                 ' protection level of the permission should be'
                 ' checked if the application runs'
                 ' on a device where the the API level is less than 17.'
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_normal_app_new': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' the application level, but the protection level of the'
                  ' permission should be checked if the application runs on'
                  ' a device where the the API level is less than 17'
                  '<br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'warning',
        'description': ('The Content Provider (%s) would be exported if the'
                        ' application ran on a device where the the API '
                        'level was less than 17. In that situation, it'
                        ' would still be protected by a permission. '
                        'However, the protection level of the permission'
                        ' is set to normal. This means that a malicious'
                        ' application could request and obtain the '
                        'permission and interact with the component. '
                        'If it was set to signature, only applications '
                        'signed with the same certificate could obtain'
                        ' the permission.'),
        'name': ('%s %s is Protected by a permission at the application level '
                 'should be checked, but the protection level of the '
                 'permission if the application runs on a device where'
                 ' the the API level is less than 17.'
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_danger_app_new': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' the application level, but the protection level of the'
                  ' permission should be checked if the application runs on'
                  ' a device where the the API level is less than 17.'
                  '<br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'warning',
        'description': ('The Content Provider(%s) would be exported if the'
                        ' application ran on a device where the the API '
                        'level was less than 17. In that situation, it'
                        ' would still be protected by a permission. However,'
                        ' the protection level of the permission is set to'
                        ' dangerous. This means that a malicious application'
                        ' could request and obtain the permission and interact'
                        ' with the component. If it was set to signature, only'
                        ' applications signed with the same certificate could'
                        ' obtain the permission.'),
        'name': ('%s %s is Protected by a permission at the application'
                 ' level, but the protection level of the'
                 ' permission should be checked'
                 ' if the application runs on a device where the the API level'
                 ' is less than 17. [%s] '
                 '[Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_signature_app_new': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' the application level.<br>%s<br>'
                  '[Content Provider, targetSdkVersion >= 17]'),
        'level': 'info',
        'description': ('The Content Provider(%s) would be exported if the'
                        ' application ran on a device where the the API '
                        'level was less than 17. Nevertheless, it is '
                        'protected by a permission.'),
        'name': ('%s %s is Protected by a permission at the application level.'
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_signatureorsystem_app_new': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' the application level, but the protection level of the'
                  ' permission should be checked.'
                  '<br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'info',
        'description': ('The Content Provider(%s) would be exported if the'
                        ' application ran on a device where the API level was'
                        ' less than 17. In that situation, it would still be'
                        ' protected by a permission. However, the protection'
                        ' level of the permission is set to signatureOrSystem.'
                        ' It is recommended that signature level is used'
                        ' instead. Signature level should suffice for most'
                        ' purposes, and does not depend on where the '
                        'applications are installed on the device.'),
        'name': ('%s %s is Protected by a permission at the application'
                 ' level but the protection level of the permission'
                 ' should be checked.'
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_unknown_app_new': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at '
                  'the application level, but the protection level of the '
                  'permission should be checked  if the application runs on'
                  ' a device where the the API level is less than 17.'
                  '<br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'warning',
        'description': ('The Content Provider(%s) would be exported if the'
                        ' application ran on a device where the the API level'
                        ' was less than 17. In that situation, it would still'
                        ' be protected by a permission which is not defined '
                        'in the analysed application. As a result, the'
                        ' protection level of the permission should be checked'
                        ' where it is defined. If it is set to normal or'
                        ' dangerous, a malicious application can request'
                        ' and obtain the permission and interact with the'
                        ' component. If it is set to signature, only '
                        'applications signed with the same certificate'
                        ' can obtain the permission.'),
        'name': ('%s %s is Protected by a permission at the application level,'
                 ' but the protection level of the permission should be'
                 ' checked  if the application runs on a device where the'
                 ' the API level is less than 17.'
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
}
