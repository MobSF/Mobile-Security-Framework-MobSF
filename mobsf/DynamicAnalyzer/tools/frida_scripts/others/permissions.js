Java.perform(function() {
    // Permission and Malware Score states
    var permissionList = [];
    var malwareScore = '';
    var test = '';
  
    // Declare permission malware scoring mapping
    var permissionMap = {
      "ACCESS_ASSISTED_GPS" :'uid',
      "ACCESS_CACHE_FILESYSTEM" :'uid',
      "ACCESS_CELL_ID" :'uid',
      "ACCESS_CHECKIN_PROPERTIES" :'uid',
      "ACCESS_COARSE_LOCATION" :'spyware(location)',
      "ACCESS_COARSE_UPDATES" :'uid',
      "ACCESS_DOWNLOAD_MANAGER" :'uid',
      "ACCESS_DOWNLOAD_MANAGER_ADVANCED" :'uid',
      "ACCESS_DRM" :'uid',
      "ACCESS_FINE_LOCATION" :'spyware(location)',
      "ACCESS_GPS" :'spyware(location)',
      "ACCESS_LOCATION" :'spyware(location)',
      "ACCESS_LOCATION_EXTRA_COMMANDS" :'spyware(location)',
      "ACCESS_LOCATTON_MOCK_LOCATION" :'uid',
      "ACCESS_MOCK_LOCATION" :'uid',
      "ACCESS_NETWORK_STATE" :'uid',
      "ACCESS_SURFACE_FLINGER" :'uid',
      "ACCESS_WIFI_STATE" :'uid',
      "ACCESS_WIMAX_STATE" :'uid',
      "ACCOUNT_MANAGER" :'uid',
      "ADD_SYSTEM_SERVICE" :'uid',
      "AUTHENTICATE_ACCOUNTS" :'uid',
      "BACKUP" :'uid',
      "BATTERY_STATS" :'uid',
      "BIND_APPWIDGET" :'uid',
      "BIND_INPUT_METHOD" :'uid',
      "BIND_WALLPAPER" :'uid',
      "BLUETOOTH" :'uid',
      "BLUETOOTH_ADMIN" :'uid',
      "BRICK" :'uid',
      "BROADCAST_PACKAGE_ADDED" :'uid',
      "BROADCAST_PACKAGE_REMOVED" :'uid',
      "BROADCAST_SMS" :'uid',
      "BROADCAST_STICKY" :'uid',
      "BROADCAST_WAP_PUSH" :'uid',
      "CALL_PHONE" :'uid',
      "CALL_PRIVILEGED" :'uid',
      "CAMERA" :'uid',
      "CHANGE_COMPONENT_ENABLED_STATE" :'uid',
      "CHANGE_CONFIGURATION" :'uid',
      "CHANGE_NETWORK_STATE" :'uid',
      "CHANGE_WIFI_MULTICAST_STATE" :'uid',
      "CHANGE_WIFI_STATE" :'uid',
      "CHANGE_WIMAX_STATE" :'uid',
      "CLEAR_APP_CACHE" :'uid',
      "CLEAR_APP_USER_DATA" :'uid',
      "CONTROL_LOCATION_UPDATES" :'uid',
      "DELETE_CACHE_FILES" :'uid',
      "DELETE_PACKAGES" :'uid',
      "DEVICE_POWER" :'uid',
      "DIAGNOSTIC" :'uid',
      "DISABLE_KEYGUARD" :'uid',
      "DUMP" :'uid',
      "EXPAND_STATUS_BAR" :'uid',
      "FACTORY_TEST" :'uid',
      "FLASHLIGHT" :'uid',
      "FORCE_BACK" :'uid',
      "FORCE_STOP_PACKAGES" :'uid',
      "FULLSCREEN" :'uid',
      "GET_ACCOUNTS" :'uid',
      "GET_PACKAGE_SIZE" :'uid',
      "GET_TASKS" :'uid',
      "GLOBAL_SEARCH" :'uid',
      "GLOBAL_SEARCH_CONTROL" :'uid',
      "HARDWARE_TEST" :'uid',
      "INJECT_EVENTS" :'uid',
      "INSTALL_DRM" :'uid',
      "INSTALL_LOCATION_PROVIDER" :'spyware(location)',
      "INSTALL_PACKAGES" :'uid',
      "INTERNAL_SYSTEM_WINDOW" :'uid',
      "INTERNET" :'uid',
      "KILL_BACKGROUND_PROCESSES" :'uid',
      "LISTEN_CALL_STATE" :'uid',
      "LOCATION" :'spyware(location)',
      "MANAGE_ACCOUNTS" :'uid',
      "MANAGE_APP_TOKENS" :'uid',
      "MASTER_CLEAR" :'uid',
      "MODIFY_AUDIO_SETTINGS" :'uid',
      "MODIFY_PHONE_STATE" :'uid',
      "MOUNT_FORMAT_FILESYSTEMS" :'uid',
      "MOUNT_UNMOUNT_FILESYSTEMS" :'uid',
      "NEW_OUTGOING_CALL" :'uid',
      "NFC" :'uid',
      "PERMISSION_NAME" :'uid',
      "PERSISTENT_ACTIVITY" :'uid',
      "PROCESS_CALL" :'uid',
      "PROCESS_INCOMING_CALLS" :'uid',
      "PROCESS_OUTGOING_CALLS" :'uid',
      "RAISED_THREAD_PRIORITY" :'uid',
      "READ_CALENDAR" :'uid',
      "READ_CONTACTS" :'uid',
      "READ_EXTERNAL_STORAGE" :'uid',
      "READ_FRAME_BUFFER" :'uid',
      "READ_INPUT_STATE" :'uid',
      "READ_LOGS" :'uid',
      "READ_OWNER_DATA" :'uid',
      "READ_PHONE_STATE" :'uid',
      "READ_SECURE_SETTINGS" :'uid',
      "READ_SETTINGS" :'uid',
      "READ_SMS" :'uid',
      "READ_SYNC_SETTINGS" :'uid',
      "READ_USER_DICTIONARY" :'uid',
      "REBOOT" :'uid',
      "RECEIVE_BOOT_COMPLETED" :'uid',
      "RECEIVE_SMS" :'uid',
      "RECEIVE_WAP_PUSH" :'uid',
      "RECORD_AUDIO" :'uid',
      "RECORD_VIDEO" :'uid',
      "REORDER_TASKS" :'uid',
      "RESTART_PACKAGES" :'uid',
      "SEND_DOWNLOAD_COMPLETED_INTENTS" :'uid',
      "SEND_SMS" :'uid',
      "SET_ACTIVITY_WATCHER" :'uid',
      "SET_ALWAYS_FINISH" :'uid',
      "SET_ANIMATION_SCALE" :'uid',
      "SET_DEBUG_APP" :'uid',
      "SET_ORIENTATION" :'uid',
      "SET_PREFERRED_APPLICATIONS" :'uid',
      "SET_PROCESS_LIMIT" :'uid',
      "SET_TIME_ZONE" :'uid',
      "SET_WALLPAPER" :'uid',
      "SET_WALLPAPER_COMPONENT" :'uid',
      "SET_WALLPAPER_HINTS" :'uid',
      "SIGNAL_PERSISTENT_PROCESSES" :'uid',
      "STATUS_BAR" :'uid',
      "SUBSCRIBED_FEEDS_READ" :'uid',
      "SUBSCRIBED_FEEDS_WRITE" :'uid',
      "SYSTEM_ALERT_WINDOW" :'uid',
      "UPDATE_DEVICE_STATS" :'uid',
      "USE_CREDENTIALS" :'uid',
      "VIBRATE" :'uid',
      "WAKE_LOCK" :'uid',
      "WIFI_LOCK" :'uid',
      "WRITE_APN_SETTINGS" :'uid',
      "WRITE_CALENDAR" :'uid',
      "WRITE_CONTACTS" :'uid',
      "WRITE_EXTERNAL_STORAGE" :'uid',
      "WRITE_GSERVICES" :'uid',
      "WRITE_MEDIA_STORAGE" :'uid',
      "WRITE_OWNER_DATA" :'uid',
      "WRITE_OWNER_FILE" :'uid',
      "WRITE_SECURE" :'uid',
      "WRITE_SECURE_SETTINGS" :'uid',
      "WRITE_SETTINGS" :'uid',
      "WRITE_SMS" :'uid',
      "WRITE_SYNC_SETTINGS" :'uid',
      "WRITE_USER_DICTIONARY" :'uid'
      
      
      
        // "MANAGE_DEVICE_POLICY_CAMERA" : 100, // under research
    };
  
  
  
    // Dynamically checks permissions``````
    var checkPermission = function(permission) {
        // Declare android objects
        var ManifestPermission = Java.use('android.Manifest$permission');
        var PackageManagerClass = Java.use('android.content.pm.PackageManager');
        var ProcessClass = Java.use('android.os.Process');
        var context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
        
        /*if (context == null) {
            send('[] Context is null. Unable to check permission.');
            return;
        }*/
  
        var permissionStatus = PackageManagerClass.PERMISSION_DENIED.value;
  
        try {
            permissionStatus = context.checkPermission(ManifestPermission[permission].value, ProcessClass.myPid(), ProcessClass.myUid());
        } catch (e) {
            send('[Permission] Error occurred while checking permission: ' + e);
            //test +='0';
        }
  
        if (permissionStatus === PackageManagerClass.PERMISSION_GRANTED.value) {
            send('[Permission] [+] ' + permission + ' is used in the application.');
            //test +='1,';
            test +='"'+permission+'": [1],';
            // Adds to permission list
            permissionList.push(permission);
        } else {
            send('[Permission] [-] ' + permission + ' is NOT used in the application.');
            //test +='0,';
            test +='"'+permission+'": [0],';
        }
    };
  
  
  
    // Adds to malware score based on permission type
    var malwareScoring = function(permissionList) {
        // Iterates list of permissions to add to malware score
        for (var permission in permissionList) {
            if (permissionList[permission] in permissionMap) {
                malwareScore += permissionMap[permissionList[permission]];
            }
       
        }
  
        //send('[*] Malware score is ' + malwareScore);
        test = test.slice(0,-1);
        send('[Permission.Score] [*] Malware score is ' + test);
        if (malwareScore.includes("spyware(location)")){
            send('[Permission] [*] Spyware(Location) capability');}
  
        if (malwareScore.includes("")){
            send('[Permission] [*] Dropper capability');
        }
        if (malwareScore.includes("ransomeware")){
            send('[Permission] [*] Ransomeware capability');
        }
    };
  
    checkPermission("ACCESS_ASSISTED_GPS");
    checkPermission("ACCESS_CACHE_FILESYSTEM");
    checkPermission("ACCESS_CELL_ID");
    checkPermission("ACCESS_CHECKIN_PROPERTIES");
    checkPermission("ACCESS_COARSE_LOCATION");
    checkPermission("ACCESS_COARSE_UPDATES");
    checkPermission("ACCESS_DOWNLOAD_MANAGER");
    checkPermission("ACCESS_DOWNLOAD_MANAGER_ADVANCED");
    checkPermission("ACCESS_DRM");
    checkPermission("ACCESS_FINE_LOCATION");
    checkPermission("ACCESS_GPS");
    checkPermission("ACCESS_LOCATION");
    checkPermission("ACCESS_LOCATION_EXTRA_COMMANDS");
    checkPermission("ACCESS_LOCATTON_MOCK_LOCATION");
    checkPermission("ACCESS_MOCK_LOCATION");
    checkPermission("ACCESS_NETWORK_STATE");
    checkPermission("ACCESS_SURFACE_FLINGER");
    checkPermission("ACCESS_WIFI_STATE");
    checkPermission("ACCESS_WIMAX_STATE");
    checkPermission("ACCOUNT_MANAGER");
    checkPermission("ADD_SYSTEM_SERVICE");
    checkPermission("AUTHENTICATE_ACCOUNTS");
    checkPermission("BACKUP");
    checkPermission("BATTERY_STATS");
    checkPermission("BIND_APPWIDGET");
    checkPermission("BIND_INPUT_METHOD");
    checkPermission("BIND_WALLPAPER");
    checkPermission("BLUETOOTH");
    checkPermission("BLUETOOTH_ADMIN");
    checkPermission("BRICK");
    checkPermission("BROADCAST_PACKAGE_ADDED");
    checkPermission("BROADCAST_PACKAGE_REMOVED");
    checkPermission("BROADCAST_SMS");
    checkPermission("BROADCAST_STICKY");
    checkPermission("BROADCAST_WAP_PUSH");
    checkPermission("CALL_PHONE");
    checkPermission("CALL_PRIVILEGED");
    checkPermission("CAMERA");
    checkPermission("CHANGE_COMPONENT_ENABLED_STATE");
    checkPermission("CHANGE_CONFIGURATION");
    checkPermission("CHANGE_NETWORK_STATE");
    checkPermission("CHANGE_WIFI_MULTICAST_STATE");
    checkPermission("CHANGE_WIFI_STATE");
    checkPermission("CHANGE_WIMAX_STATE");
    checkPermission("CLEAR_APP_CACHE");
    checkPermission("CLEAR_APP_USER_DATA");
    checkPermission("CONTROL_LOCATION_UPDATES");
    checkPermission("DELETE_CACHE_FILES");
    checkPermission("DELETE_PACKAGES");
    checkPermission("DEVICE_POWER");
    checkPermission("DIAGNOSTIC");
    checkPermission("DISABLE_KEYGUARD");
    checkPermission("DUMP");
    checkPermission("EXPAND_STATUS_BAR");
    checkPermission("FACTORY_TEST");
    checkPermission("FLASHLIGHT");
    checkPermission("FORCE_BACK");
    checkPermission("FORCE_STOP_PACKAGES");
    checkPermission("FULLSCREEN");
    checkPermission("GET_ACCOUNTS");
    checkPermission("GET_PACKAGE_SIZE");
    checkPermission("GET_TASKS");
    checkPermission("GLOBAL_SEARCH");
    checkPermission("GLOBAL_SEARCH_CONTROL");
    checkPermission("HARDWARE_TEST");
    checkPermission("INJECT_EVENTS");
    checkPermission("INSTALL_DRM");
    checkPermission("INSTALL_LOCATION_PROVIDER");
    checkPermission("INSTALL_PACKAGES");
    checkPermission("INTERNAL_SYSTEM_WINDOW");
    checkPermission("INTERNET");
    checkPermission("KILL_BACKGROUND_PROCESSES");
    checkPermission("LISTEN_CALL_STATE");
    checkPermission("LOCATION");
    checkPermission("MANAGE_ACCOUNTS");
    checkPermission("MANAGE_APP_TOKENS");
    checkPermission("MASTER_CLEAR");
    checkPermission("MODIFY_AUDIO_SETTINGS");
    checkPermission("MODIFY_PHONE_STATE");
    checkPermission("MOUNT_FORMAT_FILESYSTEMS");
    checkPermission("MOUNT_UNMOUNT_FILESYSTEMS");
    checkPermission("NEW_OUTGOING_CALL");
    checkPermission("NFC");
    checkPermission("PERMISSION_NAME");
    checkPermission("PERSISTENT_ACTIVITY");
    checkPermission("PROCESS_CALL");
    checkPermission("PROCESS_INCOMING_CALLS");
    checkPermission("PROCESS_OUTGOING_CALLS");
    checkPermission("RAISED_THREAD_PRIORITY");
    checkPermission("READ_CALENDAR");
    checkPermission("READ_CONTACTS");
    checkPermission("READ_EXTERNAL_STORAGE");
    checkPermission("READ_FRAME_BUFFER");
    checkPermission("READ_INPUT_STATE");
    checkPermission("READ_LOGS");
    checkPermission("READ_OWNER_DATA");
    checkPermission("READ_PHONE_STATE");
    checkPermission("READ_SECURE_SETTINGS");
    checkPermission("READ_SETTINGS");
    checkPermission("READ_SMS");
    checkPermission("READ_SYNC_SETTINGS");
    checkPermission("READ_USER_DICTIONARY");
    checkPermission("REBOOT");
    checkPermission("RECEIVE_BOOT_COMPLETED");
    checkPermission("RECEIVE_SMS");
    checkPermission("RECEIVE_WAP_PUSH");
    checkPermission("RECORD_AUDIO");
    checkPermission("RECORD_VIDEO");
    checkPermission("REORDER_TASKS");
    checkPermission("RESTART_PACKAGES");
    checkPermission("SEND_DOWNLOAD_COMPLETED_INTENTS");
    checkPermission("SEND_SMS");
    checkPermission("SET_ACTIVITY_WATCHER");
    checkPermission("SET_ALWAYS_FINISH");
    checkPermission("SET_ANIMATION_SCALE");
    checkPermission("SET_DEBUG_APP");
    checkPermission("SET_ORIENTATION");
    checkPermission("SET_PREFERRED_APPLICATIONS");
    checkPermission("SET_PROCESS_LIMIT");
    checkPermission("SET_TIME_ZONE");
    checkPermission("SET_WALLPAPER");
    checkPermission("SET_WALLPAPER_COMPONENT");
    checkPermission("SET_WALLPAPER_HINTS");
    checkPermission("SIGNAL_PERSISTENT_PROCESSES");
    checkPermission("STATUS_BAR");
    checkPermission("SUBSCRIBED_FEEDS_READ");
    checkPermission("SUBSCRIBED_FEEDS_WRITE");
    checkPermission("SYSTEM_ALERT_WINDOW");
    checkPermission("UPDATE_DEVICE_STATS");
    checkPermission("USE_CREDENTIALS");
    checkPermission("VIBRATE");
    checkPermission("WAKE_LOCK");
    checkPermission("WIFI_LOCK");
    checkPermission("WRITE_APN_SETTINGS");
    checkPermission("WRITE_CALENDAR");
    checkPermission("WRITE_CONTACTS");
    checkPermission("WRITE_EXTERNAL_STORAGE");
    checkPermission("WRITE_GSERVICES");
    checkPermission("WRITE_MEDIA_STORAGE");
    checkPermission("WRITE_OWNER_DATA");
    checkPermission("WRITE_OWNER_FILE");
    checkPermission("WRITE_SECURE");
    checkPermission("WRITE_SECURE_SETTINGS");
    checkPermission("WRITE_SETTINGS");
    checkPermission("WRITE_SMS");
    checkPermission("WRITE_SYNC_SETTINGS");
    
    
    
    // Get malware score
    malwareScoring(permissionList);
  });
  /*
    var test = function(permissionList) {
    // Iterates list of permissions to add to malware score
    for (var permission in permissionList) {
        if (permissionList[permission] in permissionMap) {
            malwareScore += permissionMap[permissionList[permission]];
        }
    }
  
    if (malwareScore.includes("uid13")){
        send('[*] Dropper or CMC____________');
    }
  };
  */