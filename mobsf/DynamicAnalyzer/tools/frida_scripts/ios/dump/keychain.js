// From: https://github.com/sensepost/objection/blob/f8e78d8a29574c6dadd2b953a63207b45a19b1cf/objection/hooks/ios/keychain/dump.js
function dumpKeyChain(){
    var NSMutableDictionary = ObjC.classes.NSMutableDictionary;
    var NSString = ObjC.classes.NSString;
    
    // Ref: http://nshipster.com/bool/
    var kCFBooleanTrue = ObjC.classes.__NSCFBoolean.numberWithBool_(true);
    var SecItemCopyMatching = new NativeFunction(
        ptr(Module.findExportByName('Security', 'SecItemCopyMatching')), 'pointer', ['pointer', 'pointer']);
    var SecAccessControlGetConstraints = new NativeFunction(
        ptr(Module.findExportByName('Security', 'SecAccessControlGetConstraints')),
        'pointer', ['pointer']);
    
    // constants
    var kSecReturnAttributes = 'r_Attributes',
        kSecReturnData = 'r_Data',
        kSecReturnRef = 'r_Ref',
        kSecMatchLimit = 'm_Limit',
        kSecMatchLimitAll = 'm_LimitAll',
        kSecClass = 'class',
        kSecClassKey = 'keys',
        kSecClassIdentity = 'idnt',
        kSecClassCertificate = 'cert',
        kSecClassGenericPassword = 'genp',
        kSecClassInternetPassword = 'inet',
        kSecAttrService = 'svce',
        kSecAttrAccount = 'acct',
        kSecAttrAccessGroup = 'agrp',
        kSecAttrLabel = 'labl',
        kSecAttrCreationDate = 'cdat',
        kSecAttrAccessControl = 'accc',
        kSecAttrGeneric = 'gena',
        kSecAttrSynchronizable = 'sync',
        kSecAttrModificationDate = 'mdat',
        kSecAttrServer = 'srvr',
        kSecAttrDescription = 'desc',
        kSecAttrComment = 'icmt',
        kSecAttrCreator = 'crtr',
        kSecAttrType = 'type',
        kSecAttrScriptCode = 'scrp',
        kSecAttrAlias = 'alis',
        kSecAttrIsInvisible = 'invi',
        kSecAttrIsNegative = 'nega',
        kSecAttrHasCustomIcon = 'cusi',
        kSecProtectedDataItemAttr = 'prot',
        kSecAttrAccessible = 'pdmn',
        kSecAttrAccessibleWhenUnlocked = 'ak',
        kSecAttrAccessibleAfterFirstUnlock = 'ck',
        kSecAttrAccessibleAlways = 'dk',
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly = 'aku',
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly = 'akpu',
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly = 'cku',
        kSecAttrAccessibleAlwaysThisDeviceOnly = 'dku',
        kSecValueData = 'v_Data';
    
    // dict for reverse constants lookups
    var kSecConstantReverse = {
        'r_Attributes': 'kSecReturnAttributes',
        'r_Data': 'kSecReturnData',
        'r_Ref': 'kSecReturnRef',
        'm_Limit': 'kSecMatchLimit',
        'm_LimitAll': 'kSecMatchLimitAll',
        'class': 'kSecClass',
        'keys': 'kSecClassKey',
        'idnt': 'kSecClassIdentity',
        'cert': 'kSecClassCertificate',
        'genp': 'kSecClassGenericPassword',
        'inet': 'kSecClassInternetPassword',
        'svce': 'kSecAttrService',
        'acct': 'kSecAttrAccount',
        'agrp': 'kSecAttrAccessGroup',
        'labl': 'kSecAttrLabel',
        'srvr': 'kSecAttrServer',
        'cdat': 'kSecAttrCreationDate',
        'accc': 'kSecAttrAccessControl',
        'gena': 'kSecAttrGeneric',
        'sync': 'kSecAttrSynchronizable',
        'mdat': 'kSecAttrModificationDate',
        'desc': 'kSecAttrDescription',
        'icmt': 'kSecAttrComment',
        'crtr': 'kSecAttrCreator',
        'type': 'kSecAttrType',
        'scrp': 'kSecAttrScriptCode',
        'alis': 'kSecAttrAlias',
        'invi': 'kSecAttrIsInvisible',
        'nega': 'kSecAttrIsNegative',
        'cusi': 'kSecAttrHasCustomIcon',
        'prot': 'kSecProtectedDataItemAttr',
        'pdmn': 'kSecAttrAccessible',
        'ak': 'kSecAttrAccessibleWhenUnlocked',
        'ck': 'kSecAttrAccessibleAfterFirstUnlock',
        'dk': 'kSecAttrAccessibleAlways',
        'aku': 'kSecAttrAccessibleWhenUnlockedThisDeviceOnly',
        'akpu': 'kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly',
        'cku': 'kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly',
        'dku': 'kSecAttrAccessibleAlwaysThisDeviceOnly',
        'v_Data': 'kSecValueData',
    };
    
    // the base query dictionary to use for the keychain lookups
    var search_dictionary = NSMutableDictionary.alloc().init();
    search_dictionary.setObject_forKey_(kCFBooleanTrue, kSecReturnAttributes);
    search_dictionary.setObject_forKey_(kCFBooleanTrue, kSecReturnData);
    search_dictionary.setObject_forKey_(kCFBooleanTrue, kSecReturnRef);
    search_dictionary.setObject_forKey_(kSecMatchLimitAll, kSecMatchLimit);
    
    // keychain item times to query for
    var item_classes = [
        kSecClassKey,
        kSecClassIdentity,
        kSecClassCertificate,
        kSecClassGenericPassword,
        kSecClassInternetPassword
    ];
    
    // get the string representation of some data
    // ref: https://www.frida.re/docs/examples/ios/
    function odas(raw_data) {
    
        // "objective-c data as string"
    
        // // TODO: check if this is something we need NSKeyedUnarchiver for
        // if (raw_data.toString().toLowerCase()
        //     .indexOf('62706c69 73743030 d4010203 04050609 0a582476 65727369 6f6e5824 6f626a65 63747359 24617263 68697665 72542474')) {
    
        //         var new_value = NSKeyedUnarchiver.unarchiveObjectWithData_(raw_data);
        //         console.log(new_value);
        //         console.log(new_value.$ownMethods);
        //     }
    
        // try and get a string representation of the data
        try {
    
            var data_instance = new ObjC.Object(raw_data);
            return Memory.readUtf8String(data_instance.bytes(), data_instance.length());
    
        } catch (_) {
    
            try {
    
                return raw_data.toString();
    
            } catch (_) {
    
                return '';
            }
        }
    }
    
    // Decode the access control attributes on a keychain
    // entry into a human readable string. Getting an idea of what the
    // constriants actually are is done using an undocumented method,
    // SecAccessControlGetConstraints.
    function decode_acl(entry) {
    
        // No access control? Move along.
        if (!entry.containsKey_(kSecAttrAccessControl)) {
            return '';
        }
    
        var access_controls = ObjC.Object(
            SecAccessControlGetConstraints(entry.objectForKey_(kSecAttrAccessControl)));
    
        // Ensure we were able to get the SecAccessControlRef
        if (access_controls.handle == 0x00) {
            return '';
        }
    
        var flags = [];
        var access_control_enumerator = access_controls.keyEnumerator();
        var access_control_item_key;
    
        while ((access_control_item_key = access_control_enumerator.nextObject()) !== null) {
    
            var access_control_item = access_controls.objectForKey_(access_control_item_key);
    
            switch (odas(access_control_item_key)) {
    
                // Defaults?
                case 'dacl':
                    break;
    
                case 'osgn':
                    flags.push('PrivateKeyUsage');
    
                case 'od':
                    var constraints = access_control_item;
                    var constraint_enumerator = constraints.keyEnumerator();
                    var constraint_item_key;
    
                    while ((constraint_item_key = constraint_enumerator.nextObject()) !== null) {
    
                        switch (odas(constraint_item_key)) {
                            case 'cpo':
                                flags.push('kSecAccessControlUserPresence');
                                break;
    
                            case 'cup':
                                flags.push('kSecAccessControlDevicePasscode');
                                break;
    
                            case 'pkofn':
                                constraints.objectForKey_('pkofn') == 1 ?
                                    flags.push('Or') :
                                    flags.push('And');
                                break;
    
                            case 'cbio':
                                constraints.objectForKey_('cbio').count() == 1 ?
                                    flags.push('kSecAccessControlTouchIDAny') :
                                    flags.push('kSecAccessControlTouchIDCurrentSet');
                                break;
    
                            default:
                                break;
                        }
                    }
    
                    break;
    
                case 'prp':
                    flags.push('ApplicationPassword');
                    break;
    
                default:
                    break;
            }
        }
    
        return flags.join(' ');
    }
    
    // helper to lookup the constant name of a constant value
    function get_constant_for_value(v) {
    
        for (var k in kSecConstantReverse) {
            if (k == v) {
                return kSecConstantReverse[v];
            }
        }
    
        return v;
    }
    
    // a list of keychain items that will return 
    var keychain_items = [];
    
    for (var item_class_index in item_classes) {
    
        var item_class = item_classes[item_class_index];
    
        // set the class-type we are querying for now
        search_dictionary.setObject_forKey_(item_class, kSecClass);
    
        // get a pointer to write results to. no type? guess that goes as id* then
        var results_pointer = Memory.alloc(Process.pointerSize);
    
        // get the keychain items
        var copy_results = SecItemCopyMatching(search_dictionary, results_pointer);
    
        // if we have no results, move to the next
        if (copy_results != 0x00) {
            continue;
        }
    
        // read the resultant dict of the lookup from memory
        var search_results = new ObjC.Object(Memory.readPointer(results_pointer));
    
        // if there are search results, loop them each and populate the return
        // array with the data we got
        if (search_results.count() > 0) {
    
            for (var i = 0; i < search_results.count(); i++) {
    
                // the *actual* keychain item is here!
                var search_result = search_results.objectAtIndex_(i);
    
                var keychain_entry = {
                    'item_class': get_constant_for_value(item_class),
                    'create_date': odas(search_result.objectForKey_(kSecAttrCreationDate)),
                    'modification_date': odas(search_result.objectForKey_(kSecAttrModificationDate)),
                    'description': odas(search_result.objectForKey_(kSecAttrDescription)),
                    'comment': odas(search_result.objectForKey_(kSecAttrComment)),
                    'creator': odas(search_result.objectForKey_(kSecAttrCreator)),
                    'type': odas(search_result.objectForKey_(kSecAttrType)),
                    'script_code': odas(search_result.objectForKey_(kSecAttrScriptCode)),
                    'alias': odas(search_result.objectForKey_(kSecAttrAlias)),
                    'invisible': odas(search_result.objectForKey_(kSecAttrIsInvisible)),
                    'negative': odas(search_result.objectForKey_(kSecAttrIsNegative)),
                    'custom_icon': odas(search_result.objectForKey_(kSecAttrHasCustomIcon)),
                    'protected': odas(search_result.objectForKey_(kSecProtectedDataItemAttr)),
                    'access_control': decode_acl(search_result),
                    'accessible_attribute': get_constant_for_value(odas(search_result.objectForKey_(kSecAttrAccessible))),
                    'entitlement_group': odas(search_result.objectForKey_(kSecAttrAccessGroup)),
                    'generic': odas(search_result.objectForKey_(kSecAttrGeneric)),
                    'service': odas(search_result.objectForKey_(kSecAttrService)),
                    'account': odas(search_result.objectForKey_(kSecAttrAccount)),
                    'label': odas(search_result.objectForKey_(kSecAttrLabel)),
                    'data': odas(search_result.objectForKey_(kSecValueData)),
                };
    
                keychain_items.push(keychain_entry);
            }
        }
    }
    send('Dumping Application Keychain')
    send(JSON.stringify({'[MBSFDUMP] keychain': keychain_items}));
    }

try {
    dumpKeyChain();
} catch(err) {}