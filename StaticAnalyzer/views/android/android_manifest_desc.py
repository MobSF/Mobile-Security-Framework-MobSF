MANIFEST_DESC = {
    'a_debuggable': {
        'title': 'Debug Enabled For App <br>[android:debuggable=true]',
        'level': 'high',
        'description': ('Debugging was enabled on the app which makes it '
                        'easier for reverse engineers to hook a debugger to'
                        ' it. This allows dumping a stack trace and accessing'
                        ' debugging helper classes.'),
        'name': 'Debug Enabled For App [android:debuggable=true]',
    },
    'a_allowbackup': {
        'title': ('Application Data can be Backed up'
                  '<br>[android:allowBackup=true]'),
        'level': 'medium',
        'description': ('This flag allows anyone to backup your application'
                        ' data via adb. It allows users who have enabled USB'
                        ' debugging to copy application data off of the'
                        ' device.'),
        'name': 'Application Data can be Backed up [android:allowBackup=true]',
    },
    'a_allowbackup_miss': {
        'title': ('Application Data can be Backed up<br>[android:allowBackup]'
                  ' flag is missing.'),
        'level': 'medium',
        'description': ('The flag [android:allowBackup] should be set to false'
                        '. By default it is set to true and allows anyone to '
                        'backup your application data via adb. It allows users'
                        ' who have enabled USB debugging to copy application '
                        'data off of the device.'),
        'name': ('Application Data can be Backed up [android:allowBackup] flag'
                 ' is missing.'),
    },
    'a_testonly': {
        'title': 'Application is in Test Mode <br>[android:testOnly=true]',
        'level': 'high',
        'description': ('It may expose functionality or data outside of itself'
                        ' that would cause a security hole.'),
        'name': 'Application is in Test Mode [android:testOnly=true]',
    },
    'a_taskaffinity': {
        'title': 'TaskAffinity is set for Activity </br>(%s)',
        'level': 'high',
        'description': ('If taskAffinity is set, then other application'
                        ' could read the Intents sent to Activities '
                        'belonging to another task. Always use the default'
                        ' setting keeping the affinity as the package name'
                        ' in order to prevent sensitive information inside'
                        ' sent or received Intents from being read by '
                        'another application.'),
        'name': 'TaskAffinity is set for Activity',
    },
    'a_launchmode': {
        'title': 'Launch Mode of Activity (%s) is not standard.',
        'level': 'high',
        'description': ('An Activity should not be having the launch mode'
                        ' attribute set to "singleTask/singleInstance" as '
                        'it becomes root Activity and it is possible for'
                        ' other applications to read the contents of the'
                        ' calling Intent. So it is required to use the'
                        ' "standard" launch mode attribute when sensitive'
                        ' information is included in an Intent.'),
        'name': 'Launch Mode of Activity is not standard.',
    },
    'a_prot_sign': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission.'
                  '</br>%s<br>[android:exported=true]'),
        'level': 'info',
        'description': ('A%s %s is found to be exported, but'
                        ' is protected by permission.'),
        'name': 'is Protected by a permission.[android:exported=true]',
    },
    'a_prot_normal': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, but'
                  ' the protection level of the permission should be checked.'
                  '</br>%s <br>[android:exported=true]'),
        'level': 'high',
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
        'name': ('is Protected by a permission, but the protection level of '
                 'the permission should be checked.[android:exported=true]'),
    },
    'a_prot_danger': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, but'
                  ' the protection level of the permission should be checked.'
                  '</br>%s <br>[android:exported=true]'),
        'level': 'high',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device. It is protected by a'
                        ' permission. However, the protection level of the'
                        ' permission is set to dangerous. This means that a'
                        ' malicious application can request and obtain the'
                        ' permission and interact with the component. If it'
                        ' was set to signature, only applications signed with'
                        ' the same certificate could obtain the permission.'),
        'name': ('is Protected by a permission, but the protection level of'
                 ' the permission should be checked.[android:exported=true]'),
    },
    'a_prot_sign_sys': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, but'
                  ' the protection level of the permission should be checked.'
                  '</br>%s <br>[android:exported=true]'),
        'level': 'info',
        'description': ('A%s %s is found to be exported, but is protected by'
                        ' a permission. However, the protection level of the'
                        ' permission is set to signatureOrSystem. It is '
                        'recommended that signature level is used instead. '
                        'Signature level should suffice for most purposes, '
                        'and does not depend on where the applications are '
                        'installed on the device.'),
        'name': ('is Protected by a permission, but the protection level of'
                 ' the permission should be checked.[android:exported=true]'),
    },
    'a_prot_unknown': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, but'
                  ' the protection level of the permission should be checked.'
                  '</br>%s <br>[android:exported=true]'),
        'level': 'high',
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
        'name': ('is Protected by a permission, but the protection level '
                 'of the permission should be '
                 'checked.[android:exported=true]'),
    },
    'a_prot_normal_appl': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' the application level, but the protection level of the '
                  'permission should be checked.</br>%s <br>'
                  '[android:exported=true]'),
        'level': 'high',
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
        'name': ('is Protected by a permission at the application level,'
                 ' but the protection level of the permission should be '
                 'checked.[android:exported=true]'),
    },
    'a_prot_danger_appl': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' the application level, but the protection level of the '
                  'permission should be checked.'
                  '</br>%s <br>[android:exported=true]'),
        'level': 'high',
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
        'name': ('is Protected by a permission at the application level, but'
                 ' the protection level of the permission should be '
                 'checked.[android:exported=true]'),
    },
    'a_prot_sign_appl': {
        'title': ('<strong>%s</strong> (%s)  Protected by a permission at'
                  ' the application level.</br>%s<br>[android:exported=true]'),
        'level': 'info',
        'description': ('A%s %s is found to be exported, but is protected by'
                        ' a permission at the application level.'),
        'name': ('Protected by a permission at the application level.'
                 '[android:exported=true]'),
    },
    'a_prot_sign_sys_appl': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at '
                  'the application level, but the protection level of the '
                  'permission should be checked.'
                  '</br>%s <br>[android:exported=true]'),
        'level': 'info',
        'description': ('A%s %s is found to be exported, but is protected '
                        'by a permission at the application level. However,'
                        ' the protection level of the permission is set to'
                        ' signatureOrSystem. It is recommended that '
                        'signature level is used instead. Signature level'
                        ' should suffice for most purposes, and does not '
                        'depend on where the applications are installed'
                        ' on the device.'),
        'name': ('is Protected by a permission at the application level, but'
                 ' the protection level of the permission should be checked.'
                 '[android:exported=true]'),
    },
    'a_prot_unknown_appl': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission'
                  ' at the application, but the protection level of the '
                  'permission should be checked.'
                  '</br>%s <br>[android:exported=true]'),
        'level': 'high',
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
        'name': ('is Protected by a permission at the application, but the'
                 ' protection level of the permission should be checked.'
                 '[android:exported=true]'),
    },
    'a_not_protected': {
        'title': ('<strong>%s</strong> (%s) is not Protected.'
                  ' <br>[android:exported=true]'),
        'level': 'high',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device.'),
        'name': 'is not Protected. [android:exported=true]',
    },
    'a_not_protected_filter': {
        'title': ('<strong>%s</strong> (%s) is not Protected.<br>'
                  'An intent-filter exists.'),
        'level': 'high',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other '
                        'application on the device. The presence of '
                        'intent-filter indicates that the %s'
                        ' is explicitly exported.'),
        'name': 'is not Protected.An intent-filter exists.',
    },
    'c_not_protected': {
        'title': ('<strong>%s</strong> (%s) is not Protected. <br>'
                  '[[Content Provider, targetSdkVersion < 17]'),
        'level': 'high',
        'description': ('A%s %s is found to be shared with other apps'
                        ' on the device therefore leaving it accessible '
                        'to any other application on the device. It is '
                        'a Content Provider that targets an API level '
                        'under 17, which makes it exported by default,'
                        ' regardless of the API level of the system '
                        'that the application runs on.'),
        'name': 'is not Protected.[[Content Provider, targetSdkVersion < 17]',
    },
    'c_not_protected2': {
        'title': ('<strong>%s</strong> (%s) would not be Protected if the'
                  ' application ran on a device where the the API level was'
                  ' less than 17. <br>[Content Provider, '
                  'targetSdkVersion >= 17]'),
        'level': 'high',
        'description': ('The Content Provider(%s %s) would be exported if the'
                        ' application ran on a device where the the API level '
                        'was less than 17. In that situation, it would be '
                        'shared with other apps on the device therefore '
                        'leaving it accessible to any other application '
                        'on the device.'),
        'name': ('would not be Protected if the application ran on a device'
                 ' where the the API level was less than 17.[Content Provider,'
                 ' targetSdkVersion >= 17]'),
    },
    'c_prot_normal': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, but'
                  ' the protection level of the permission should be checked.'
                  '</br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'high',
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
        'name': ('is Protected by a permission, but the protection level'
                 ' of the permission should be checked.[Content Provider,'
                 ' targetSdkVersion < 17]'),
    },
    'c_prot_danger': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, '
                  'but the protection level of the permission should be '
                  'checked.</br>%s <br>[Content Provider, '
                  'targetSdkVersion < 17]'),
        'level': 'high',
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
        'name': ('is Protected by a permission, but the protection level of '
                 'the permission should be checked.[Content Provider, '
                 'targetSdkVersion < 17]'),
    },
    'c_prot_sign': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission.'
                  '</br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'info',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device. It is '
                        'protected by permission.'),
        'name': ('is Protected by a permission.[Content Provider, '
                 'targetSdkVersion < 17]'),
    },
    'c_prot_sign_sys': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission,'
                  ' but the protection level of the permission should be '
                  'checked.</br>%s <br>[Content Provider, '
                  'targetSdkVersion < 17]'),
        'level': 'info',
        'description': ('A%s %s is found to be exported, but is protected by'
                        ' a permission. However, the protection level of the'
                        ' permission is set to signatureOrSystem. It is'
                        ' recommended that signature level is used instead.'
                        ' Signature level should suffice for most purposes,'
                        ' and does not depend on where the applications are'
                        ' installed on the device.'),
        'name': ('is Protected by a permission, but the protection level of '
                 'the permission should be checked.[Content Provider, '
                 'targetSdkVersion < 17]'),
    },
    'c_prot_unknown': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, but'
                  ' the protection level of the permission should be checked.'
                  '</br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'high',
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
        'name': ('is Protected by a permission, but the protection level of'
                 ' the permission should be checked.[Content Provider,'
                 ' targetSdkVersion < 17]'),
    },
    'c_prot_normal_appl': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' the application level, but the protection level of the'
                  ' permission should be checked.'
                  '</br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'high',
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
        'name': ('is Protected by a permission at the application level, but'
                 ' the protection level of the permission should be checked.'
                 '[Content Provider, targetSdkVersion < 17]'),
    },
    'c_prot_danger_appl': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at '
                  'the application level, but the protection level of the '
                  'permission should be checked.'
                  '</br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'high',
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
        'name': ('is Protected by a permission at the application level, but'
                 ' the protection level of the permission should be checked.'
                 '[Content Provider, targetSdkVersion < 17]'),
    },
    'c_prot_sign_appl': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' the application level.</br>%s <br>[Content Provider,'
                  ' targetSdkVersion < 17]'),
        'level': 'info',
        'description': ('A%s %s is found to be shared with other apps on'
                        ' the device therefore leaving it accessible to any'
                        ' other application on the device. It is protected '
                        'by permission at the application level.'),
        'name': ('is Protected by a permission at the application level.'
                 '[Content Provider, targetSdkVersion < 17]'),
    },
    'c_prot_sign_sys_appl': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' the application level, but the protection level of the'
                  ' permission should be checked.'
                  '</br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'info',
        'description': ('A%s %s is found to be exported, but is protected by'
                        ' a permission at the application level. However, the'
                        ' protection level of the permission is set to '
                        'signatureOrSystem. It is recommended that signature '
                        'level is used instead. Signature level should suffice'
                        ' for most purposes, and does not depend on where the'
                        ' applications are installed on the device.'),
        'name': ('is Protected by a permission at the application level, '
                 'but the protection level of the permission should be '
                 'checked.[Content Provider, targetSdkVersion < 17]'),
    },
    'c_prot_unknown_appl': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' application level, but the protection level of the '
                  'permission should be checked.</br>%s '
                  '<br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'high',
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
        'name': ('is Protected by a permission at application level, but'
                 ' the protection level of the permission should be checked.'
                 '[Content Provider, targetSdkVersion < 17]'),
    },
    'c_prot_normal_new': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, '
                  'but the protection level of the permission should be '
                  'checked if the application runs on a device where the '
                  'the API level is less than 17'
                  '</br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'high',
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
        'name': ('is Protected by a permission, but the protection level of'
                 ' the permission should be checked if the application runs '
                 'on a device where the the API level is less than 17 '
                 '[Content Provider, targetSdkVersion >= 17]'),
    },
    'c_prot_danger_new': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission,'
                  ' but the protection level of the permission should be '
                  'checked if the application runs on a device where '
                  'the API level is less than 17.</br>%s <br>'
                  '[Content Provider, targetSdkVersion >= 17]'),
        'level': 'high',
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
        'name': ('is Protected by a permission, but the protection level of'
                 ' the permission should be checked if the application runs on'
                 ' a device where the the API level is less than 17.'
                 '[Content Provider, targetSdkVersion >= 17]'),
    },
    'c_prot_sign_new': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission.'
                  '</br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'info',
        'description': ('The Content Provider(%s) would be exported if the'
                        ' application ran on a device where the the API level'
                        ' was less than 17. Nevertheless, it is protected '
                        'by a permission.'),
        'name': ('is Protected by a permission.'
                 '[Content Provider, targetSdkVersion >= 17]'),
    },
    'c_prot_sign_sys_new': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, but'
                  ' the protection level of the permission should be checked.'
                  '</br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
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
        'name': ('is Protected by a permission, but the protection level of'
                 ' the permission should be checked.'
                 '[Content Provider, targetSdkVersion >= 17]'),
    },
    'c_prot_unknown_new': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, but'
                  ' the protection level of the permission should be checked'
                  '  if the application runs on a device where the the API '
                  'level is less than 17.</br>%s <br>'
                  '[Content Provider, targetSdkVersion >= 17]'),
        'level': 'high',
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
        'name': ('is Protected by a permission, but the protection level of'
                 ' the permission should be checked  if the application runs'
                 ' on a device where the the API level is less than 17.'
                 '[Content Provider, targetSdkVersion >= 17]'),
    },
    'c_prot_normal_new_appl': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' the application level, but the protection level of the'
                  ' permission should be checked if the application runs on'
                  ' a device where the the API level is less than 17'
                  '</br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'high',
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
        'name': ('is Protected by a permission at the application level '
                 'should be checked, but the protection level of the '
                 'permission if the application runs on a device where'
                 ' the the API level is less than 17.'
                 '[Content Provider, targetSdkVersion >= 17]'),
    },
    'c_prot_danger_new_appl': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' the application level, but the protection level of the'
                  ' permission should be checked if the application runs on'
                  ' a device where the the API level is less than 17.'
                  '</br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'high',
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
        'name': ('is Protected by a permission at the application level, but'
                 ' the protection level of the permission should be checked '
                 'if the application runs on a device where the the API level '
                 'is less than 17.[Content Provider, targetSdkVersion >= 17]'),
    },
    'c_prot_sign_new_appl': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' the application level.</br>%s<br>'
                  '[Content Provider, targetSdkVersion >= 17]'),
        'level': 'info',
        'description': ('The Content Provider(%s) would be exported if the'
                        ' application ran on a device where the the API '
                        'level was less than 17. Nevertheless, it is '
                        'protected by a permission.'),
        'name': ('is Protected by a permission at the application level.'
                 '[Content Provider, targetSdkVersion >= 17]'),
    },
    'c_prot_sign_sys_new_appl': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' the application level, but the protection level of the'
                  ' permission should be checked.'
                  '</br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
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
        'name': ('is Protected by a permission at the application level, but'
                 ' the protection level of the permission should be checked.'
                 '[Content Provider, targetSdkVersion >= 17]'),
    },
    'c_prot_unknown_new_appl': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at '
                  'the application level, but the protection level of the '
                  'permission should be checked  if the application runs on'
                  ' a device where the the API level is less than 17.'
                  '</br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'high',
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
        'name': ('is Protected by a permission at the application level,'
                 ' but the protection level of the permission should be'
                 ' checked  if the application runs on a device where the'
                 ' the API level is less than 17.'
                 '[Content Provider, targetSdkVersion >= 17]'),
    },
    'a_improper_provider': {
        'title': 'Improper Content Provider Permissions<br>[%s]',
        'level': 'high',
        'description': ('A content provider permission was set to allows'
                        ' access from any other app on the device. '
                        'Content providers may contain sensitive '
                        'information about an app and therefore '
                        'should not be shared.'),
        'name': 'Improper Content Provider Permissions',
    },
    'a_dailer_code': {
        'title': ('Dailer Code: %s Found'
                  ' <br>[android:scheme="android_secret_code"]'),
        'level': 'high',
        'description': ('A secret code was found in the manifest. These codes,'
                        ' when entered into the dialer grant access to hidden'
                        ' content that may contain sensitive information.'),
        'name': ('Dailer Code: Found '
                 '<br>[android:scheme="android_secret_code"]'),
    },
    'a_sms_receiver_port': {
        'title': 'Data SMS Receiver Set on Port: %s Found<br>[android:port]',
        'level': 'high',
        'description': ('A binary SMS recevier is configured to listen on a'
                        ' port. Binary SMS messages sent to a device are '
                        'processed by the application in whichever way the'
                        ' developer choses. The data in this SMS should be'
                        ' properly validated by the application. Furthermore,'
                        ' the application should assume that the SMS being'
                        ' received is from an untrusted source.'),
        'name': 'Data SMS Receiver Set on Port: Found<br>[android:port]',
    },
    'a_high_intent_priority': {
        'title': 'High Intent Priority (%s)<br>[android:priority]',
        'level': 'medium',
        'description': ('By setting an intent priority higher than another'
                        ' intent, the app effectively overrides '
                        'other requests.'),
        'name': 'High Intent Priority [android:priority]',
    },
    'a_high_action_priority': {
        'title': 'High Action Priority (%s)<br>[android:priority] ',
        'level': 'medium',
        'description': ('By setting an action priority higher than'
                        ' another action, the app effectively '
                        'overrides other requests.'),
        'name': 'High Action Priority [android:priority]',
    },
}
