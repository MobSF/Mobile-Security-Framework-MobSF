PERMISSIONS = {
"BIND_DEVICE_ADMIN" : {
        "android.app.admin.DeviceAdminReceiver" : [
                ["C","ACTION_DEVICE_ADMIN_ENABLED","public static final String"],
        ],
},

"FACTORY_TEST" : {
        "android.content.pm.ApplicationInfo" : [
                ["C","FLAG_FACTORY_TEST","public static final int"],
                ["C","flags","public int"],
        ],
        "android.content.Intent" : [
                ["C","IntentResolution","public static final String"],
                ["C","ACTION_FACTORY_TEST","public static final String"],
        ],
},

"BIND_INPUT_METHOD" : {
        "android.view.inputmethod.InputMethod" : [
                ["C","SERVICE_INTERFACE","public static final String"],
        ],
},

"AUTHENTICATE_ACCOUNTS" : {
        "android.accounts.AccountManager" : [
                ["F","addAccountExplicitly(android.accounts.Account, java.lang.String, android.os.Bundle)","public boolean"],
                ["F","getPassword(android.accounts.Account)","public String"],
                ["F","getUserData(android.accounts.Account, java.lang.String)","public String"],
                ["F","peekAuthToken(android.accounts.Account, java.lang.String)","public String"],
                ["F","setAuthToken(android.accounts.Account, java.lang.String, java.lang.String)","public void"],
                ["F","setPassword(android.accounts.Account, java.lang.String)","public void"],
                ["F","setUserData(android.accounts.Account, java.lang.String, java.lang.String)","public void"],
        ],
},

"INTERNET" : {
        "android.drm.DrmErrorEvent" : [
                ["C","TYPE_NO_INTERNET_CONNECTION","public static final int"],
        ],
},

"RECORD_AUDIO" : {
        "android.net.sip.SipAudioCall" : [
                ["F","startAudio()","public void"],
        ],
},

"ACCESS_MOCK_LOCATION" : {
        "android.location.LocationManager" : [
                ["F","addTestProvider(java.lang.String, boolean, boolean, boolean, boolean, boolean, boolean, boolean, int, int)","public void"],
                ["F","clearTestProviderEnabled(java.lang.String)","public void"],
                ["F","clearTestProviderLocation(java.lang.String)","public void"],
                ["F","clearTestProviderStatus(java.lang.String)","public void"],
                ["F","removeTestProvider(java.lang.String)","public void"],
                ["F","setTestProviderEnabled(java.lang.String, boolean)","public void"],
                ["F","setTestProviderLocation(java.lang.String, android.location.Location)","public void"],
                ["F","setTestProviderStatus(java.lang.String, int, android.os.Bundle, long)","public void"],
        ],
},

"VIBRATE" : {
        "android.provider.Settings.System" : [
                ["C","VIBRATE_ON","public static final String"],
        ],
        "android.app.Notification" : [
                ["C","DEFAULT_VIBRATE","public static final int"],
                ["C","defaults","public int"],
        ],
        "android.app.Notification.Builder" : [
                ["F","setDefaults(int)","public Notification.Builder"],
        ],
        "android.media.AudioManager" : [
                ["C","EXTRA_RINGER_MODE","public static final String"],
                ["C","EXTRA_VIBRATE_SETTING","public static final String"],
                ["C","EXTRA_VIBRATE_TYPE","public static final String"],
                ["C","FLAG_REMOVE_SOUND_AND_VIBRATE","public static final int"],
                ["C","FLAG_VIBRATE","public static final int"],
                ["C","RINGER_MODE_VIBRATE","public static final int"],
                ["C","VIBRATE_SETTING_CHANGED_ACTION","public static final String"],
                ["C","VIBRATE_SETTING_OFF","public static final int"],
                ["C","VIBRATE_SETTING_ON","public static final int"],
                ["C","VIBRATE_SETTING_ONLY_SILENT","public static final int"],
                ["C","VIBRATE_TYPE_NOTIFICATION","public static final int"],
                ["C","VIBRATE_TYPE_RINGER","public static final int"],
                ["F","getRingerMode()","public int"],
                ["F","getVibrateSetting(int)","public int"],
                ["F","setRingerMode(int)","public void"],
                ["F","setVibrateSetting(int, int)","public void"],
                ["F","shouldVibrate(int)","public boolean"],
        ],
},

"GLOBAL_SEARCH" : {
        "android.app.SearchManager" : [
                ["C","EXTRA_SELECT_QUERY","public static final String"],
                ["C","INTENT_ACTION_GLOBAL_SEARCH","public static final String"],
        ],
},

"BROADCAST_STICKY" : {
        "android.content.Context" : [
                ["F","removeStickyBroadcast(android.content.Intent)","public abstract void"],
                ["F","sendStickyBroadcast(android.content.Intent)","public abstract void"],
        ],
        "android.content.ContextWrapper" : [
                ["F","removeStickyBroadcast(android.content.Intent)","public void"],
                ["F","sendStickyBroadcast(android.content.Intent)","public void"],
        ],
},

"KILL_BACKGROUND_PROCESSES" : {
        "android.app.ActivityManager" : [
                ["F","killBackgroundProcesses(java.lang.String)","public void"],
        ],
},

"SET_TIME_ZONE" : {
        "android.app.AlarmManager" : [
                ["F","setTimeZone(java.lang.String)","public void"],
        ],
},

"BLUETOOTH_ADMIN" : {
        "android.bluetooth.BluetoothAdapter" : [
                ["F","cancelDiscovery()","public boolean"],
                ["F","disable()","public boolean"],
                ["F","enable()","public boolean"],
                ["F","setName(java.lang.String)","public boolean"],
                ["F","startDiscovery()","public boolean"],
        ],
},

"CAMERA" : {
        "android.hardware.Camera.ErrorCallback" : [
                ["F","onError(int, android.hardware.Camera)","public abstract void"],
        ],
        "android.view.KeyEvent" : [
                ["C","KEYCODE_CAMERA","public static final int"],
        ],
        "android.bluetooth.BluetoothClass.Device" : [
                ["C","AUDIO_VIDEO_VIDEO_CAMERA","public static final int"],
        ],
        "android.provider.MediaStore" : [
                ["C","INTENT_ACTION_STILL_IMAGE_CAMERA","public static final String"],
                ["C","INTENT_ACTION_VIDEO_CAMERA","public static final String"],
        ],
        "android.hardware.Camera.CameraInfo" : [
                ["C","CAMERA_FACING_BACK","public static final int"],
                ["C","CAMERA_FACING_FRONT","public static final int"],
                ["C","facing","public int"],
        ],
        "android.provider.ContactsContract.StatusColumns" : [
                ["C","CAPABILITY_HAS_CAMERA","public static final int"],
        ],
        "android.hardware.Camera.Parameters" : [
                ["F","setRotation(int)","public void"],
        ],
        "android.media.MediaRecorder.VideoSource" : [
                ["C","CAMERA","public static final int"],
        ],
        "android.content.Intent" : [
                ["C","IntentResolution","public static final String"],
                ["C","ACTION_CAMERA_BUTTON","public static final String"],
        ],
        "android.content.pm.PackageManager" : [
                ["C","FEATURE_CAMERA","public static final String"],
                ["C","FEATURE_CAMERA_AUTOFOCUS","public static final String"],
                ["C","FEATURE_CAMERA_FLASH","public static final String"],
                ["C","FEATURE_CAMERA_FRONT","public static final String"],
        ],
        "android.hardware.Camera" : [
                ["C","CAMERA_ERROR_SERVER_DIED","public static final int"],
                ["C","CAMERA_ERROR_UNKNOWN","public static final int"],
                ["F","setDisplayOrientation(int)","public final void"],
        ],
},

"SET_WALLPAPER" : {
        "android.content.Intent" : [
                ["C","IntentResolution","public static final String"],
                ["C","ACTION_SET_WALLPAPER","public static final String"],
        ],
        "android.app.WallpaperManager" : [
                ["C","WALLPAPER_PREVIEW_META_DATA","public static final String"],
        ],
},

"WAKE_LOCK" : {
        "android.net.sip.SipAudioCall" : [
                ["F","startAudio()","public void"],
        ],
        "android.media.MediaPlayer" : [
                ["F","setWakeMode(android.content.Context, int)","public void"],
        ],
        "android.os.PowerManager" : [
                ["C","ACQUIRE_CAUSES_WAKEUP","public static final int"],
                ["C","FULL_WAKE_LOCK","public static final int"],
                ["C","ON_AFTER_RELEASE","public static final int"],
                ["C","PARTIAL_WAKE_LOCK","public static final int"],
                ["C","SCREEN_BRIGHT_WAKE_LOCK","public static final int"],
                ["C","SCREEN_DIM_WAKE_LOCK","public static final int"],
                ["F","newWakeLock(int, java.lang.String)","public PowerManager.WakeLock"],
        ],
},

"MANAGE_ACCOUNTS" : {
        "android.accounts.AccountManager" : [
                ["F","addAccount(java.lang.String, java.lang.String, java.lang.String[], android.os.Bundle, android.app.Activity, android.accounts.AccountManagerCallback<android.os.Bundle>, android.os.Handler)","public AccountManagerFuture"],
                ["F","clearPassword(android.accounts.Account)","public void"],
                ["F","confirmCredentials(android.accounts.Account, android.os.Bundle, android.app.Activity, android.accounts.AccountManagerCallback<android.os.Bundle>, android.os.Handler)","public AccountManagerFuture"],
                ["F","editProperties(java.lang.String, android.app.Activity, android.accounts.AccountManagerCallback<android.os.Bundle>, android.os.Handler)","public AccountManagerFuture"],
                ["F","getAuthTokenByFeatures(java.lang.String, java.lang.String, java.lang.String[], android.app.Activity, android.os.Bundle, android.os.Bundle, android.accounts.AccountManagerCallback<android.os.Bundle>, android.os.Handler)","public AccountManagerFuture"],
                ["F","invalidateAuthToken(java.lang.String, java.lang.String)","public void"],
                ["F","removeAccount(android.accounts.Account, android.accounts.AccountManagerCallback<java.lang.Boolean>, android.os.Handler)","public AccountManagerFuture"],
                ["F","updateCredentials(android.accounts.Account, java.lang.String, android.os.Bundle, android.app.Activity, android.accounts.AccountManagerCallback<android.os.Bundle>, android.os.Handler)","public AccountManagerFuture"],
        ],
},

"NFC" : {
        "android.inputmethodservice.InputMethodService" : [
                ["C","SoftInputView","public static final int"],
                ["C","CandidatesView","public static final int"],
                ["C","FullscreenMode","public static final int"],
                ["C","GeneratingText","public static final int"],
        ],
        "android.nfc.tech.NfcA" : [
                ["F","close()","public void"],
                ["F","connect()","public void"],
                ["F","get(android.nfc.Tag)","public static NfcA"],
                ["F","transceive(byte[])","public byte[]"],
        ],
        "android.nfc.tech.NfcB" : [
                ["F","close()","public void"],
                ["F","connect()","public void"],
                ["F","get(android.nfc.Tag)","public static NfcB"],
                ["F","transceive(byte[])","public byte[]"],
        ],
        "android.nfc.NfcAdapter" : [
                ["C","ACTION_TECH_DISCOVERED","public static final String"],
                ["F","disableForegroundDispatch(android.app.Activity)","public void"],
                ["F","disableForegroundNdefPush(android.app.Activity)","public void"],
                ["F","enableForegroundDispatch(android.app.Activity, android.app.PendingIntent, android.content.IntentFilter[], java.lang.String[][])","public void"],
                ["F","enableForegroundNdefPush(android.app.Activity, android.nfc.NdefMessage)","public void"],
                ["F","getDefaultAdapter()","public static NfcAdapter"],
                ["F","getDefaultAdapter(android.content.Context)","public static NfcAdapter"],
                ["F","isEnabled()","public boolean"],
        ],
        "android.nfc.tech.NfcF" : [
                ["F","close()","public void"],
                ["F","connect()","public void"],
                ["F","get(android.nfc.Tag)","public static NfcF"],
                ["F","transceive(byte[])","public byte[]"],
        ],
        "android.nfc.tech.NdefFormatable" : [
                ["F","close()","public void"],
                ["F","connect()","public void"],
                ["F","format(android.nfc.NdefMessage)","public void"],
                ["F","formatReadOnly(android.nfc.NdefMessage)","public void"],
        ],
        "android.app.Activity" : [
                ["C","Fragments","public static final int"],
                ["C","ActivityLifecycle","public static final int"],
                ["C","ConfigurationChanges","public static final int"],
                ["C","StartingActivities","public static final int"],
                ["C","SavingPersistentState","public static final int"],
                ["C","Permissions","public static final int"],
                ["C","ProcessLifecycle","public static final int"],
        ],
        "android.nfc.tech.MifareClassic" : [
                ["C","KEY_NFC_FORUM","public static final byte[]"],
                ["F","authenticateSectorWithKeyA(int, byte[])","public boolean"],
                ["F","authenticateSectorWithKeyB(int, byte[])","public boolean"],
                ["F","close()","public void"],
                ["F","connect()","public void"],
                ["F","decrement(int, int)","public void"],
                ["F","increment(int, int)","public void"],
                ["F","readBlock(int)","public byte[]"],
                ["F","restore(int)","public void"],
                ["F","transceive(byte[])","public byte[]"],
                ["F","transfer(int)","public void"],
                ["F","writeBlock(int, byte[])","public void"],
        ],
        "android.nfc.Tag" : [
                ["F","getTechList()","public String[]"],
        ],
        "android.app.Service" : [
                ["C","WhatIsAService","public static final int"],
                ["C","ServiceLifecycle","public static final int"],
                ["C","Permissions","public static final int"],
                ["C","ProcessLifecycle","public static final int"],
                ["C","LocalServiceSample","public static final int"],
                ["C","RemoteMessengerServiceSample","public static final int"],
        ],
        "android.nfc.NfcManager" : [
                ["F","getDefaultAdapter()","public NfcAdapter"],
        ],
        "android.nfc.tech.MifareUltralight" : [
                ["F","close()","public void"],
                ["F","connect()","public void"],
                ["F","readPages(int)","public byte[]"],
                ["F","transceive(byte[])","public byte[]"],
                ["F","writePage(int, byte[])","public void"],
        ],
        "android.nfc.tech.NfcV" : [
                ["F","close()","public void"],
                ["F","connect()","public void"],
                ["F","get(android.nfc.Tag)","public static NfcV"],
                ["F","transceive(byte[])","public byte[]"],
        ],
        "android.nfc.tech.TagTechnology" : [
                ["F","close()","public abstract void"],
                ["F","connect()","public abstract void"],
        ],
        "android.preference.PreferenceActivity" : [
                ["C","SampleCode","public static final String"],
        ],
        "android.content.pm.PackageManager" : [
                ["C","FEATURE_NFC","public static final String"],
        ],
        "android.content.Context" : [
                ["C","NFC_SERVICE","public static final String"],
        ],
        "android.nfc.tech.Ndef" : [
                ["C","NFC_FORUM_TYPE_1","public static final String"],
                ["C","NFC_FORUM_TYPE_2","public static final String"],
                ["C","NFC_FORUM_TYPE_3","public static final String"],
                ["C","NFC_FORUM_TYPE_4","public static final String"],
                ["F","close()","public void"],
                ["F","connect()","public void"],
                ["F","getType()","public String"],
                ["F","isWritable()","public boolean"],
                ["F","makeReadOnly()","public boolean"],
                ["F","writeNdefMessage(android.nfc.NdefMessage)","public void"],
        ],
        "android.nfc.tech.IsoDep" : [
                ["F","close()","public void"],
                ["F","connect()","public void"],
                ["F","setTimeout(int)","public void"],
                ["F","transceive(byte[])","public byte[]"],
        ],
},

"ACCESS_FINE_LOCATION" : {
        "android.telephony.TelephonyManager" : [
                ["F","getCellLocation()","public CellLocation"],
        ],
        "android.location.LocationManager" : [
                ["C","GPS_PROVIDER","public static final String"],
                ["C","NETWORK_PROVIDER","public static final String"],
                ["C","PASSIVE_PROVIDER","public static final String"],
                ["F","addGpsStatusListener(android.location.GpsStatus.Listener)","public boolean"],
                ["F","addNmeaListener(android.location.GpsStatus.NmeaListener)","public boolean"],
        ],
},

"REORDER_TASKS" : {
        "android.app.ActivityManager" : [
                ["F","moveTaskToFront(int, int)","public void"],
        ],
},

"MODIFY_AUDIO_SETTINGS" : {
        "android.net.sip.SipAudioCall" : [
                ["F","setSpeakerMode(boolean)","public void"],
        ],
        "android.media.AudioManager" : [
                ["F","startBluetoothSco()","public void"],
                ["F","stopBluetoothSco()","public void"],
        ],
},

"READ_PHONE_STATE" : {
        "android.telephony.TelephonyManager" : [
                ["C","ACTION_PHONE_STATE_CHANGED","public static final String"],
                ["F","getDeviceId()","public String"],
                ["F","getDeviceSoftwareVersion()","public String"],
                ["F","getLine1Number()","public String"],
                ["F","getSimSerialNumber()","public String"],
                ["F","getSubscriberId()","public String"],
                ["F","getVoiceMailAlphaTag()","public String"],
                ["F","getVoiceMailNumber()","public String"],
        ],
        "android.telephony.PhoneStateListener" : [
                ["C","LISTEN_CALL_FORWARDING_INDICATOR","public static final int"],
                ["C","LISTEN_CALL_STATE","public static final int"],
                ["C","LISTEN_DATA_ACTIVITY","public static final int"],
                ["C","LISTEN_MESSAGE_WAITING_INDICATOR","public static final int"],
                ["C","LISTEN_SIGNAL_STRENGTH","public static final int"],
        ],
        "android.os.Build.VERSION_CODES" : [
                ["C","DONUT","public static final int"],
        ],
},

"BIND_WALLPAPER" : {
        "android.service.wallpaper.WallpaperService" : [
                ["C","SERVICE_INTERFACE","public static final String"],
        ],
},

"DUMP" : {
        "android.os.Debug" : [
                ["F","dumpService(java.lang.String, java.io.FileDescriptor, java.lang.String[])","public static boolean"],
        ],
        "android.os.IBinder" : [
                ["C","DUMP_TRANSACTION","public static final int"],
        ],
},

"USE_CREDENTIALS" : {
        "android.accounts.AccountManager" : [
                ["F","blockingGetAuthToken(android.accounts.Account, java.lang.String, boolean)","public String"],
                ["F","getAuthToken(android.accounts.Account, java.lang.String, android.os.Bundle, android.app.Activity, android.accounts.AccountManagerCallback<android.os.Bundle>, android.os.Handler)","public AccountManagerFuture"],
                ["F","getAuthToken(android.accounts.Account, java.lang.String, boolean, android.accounts.AccountManagerCallback<android.os.Bundle>, android.os.Handler)","public AccountManagerFuture"],
                ["F","invalidateAuthToken(java.lang.String, java.lang.String)","public void"],
        ],
},

"ACCESS_COARSE_LOCATION" : {
        "android.telephony.TelephonyManager" : [
                ["F","getCellLocation()","public CellLocation"],
        ],
        "android.telephony.PhoneStateListener" : [
                ["C","LISTEN_CELL_LOCATION","public static final int"],
        ],
        "android.location.LocationManager" : [
                ["C","NETWORK_PROVIDER","public static final String"],
        ],
},

"RECEIVE_BOOT_COMPLETED" : {
        "android.content.Intent" : [
                ["C","ACTION_BOOT_COMPLETED","public static final String"],
        ],
},

"SET_ALARM" : {
        "android.provider.AlarmClock" : [
                ["C","ACTION_SET_ALARM","public static final String"],
                ["C","EXTRA_HOUR","public static final String"],
                ["C","EXTRA_MESSAGE","public static final String"],
                ["C","EXTRA_MINUTES","public static final String"],
                ["C","EXTRA_SKIP_UI","public static final String"],
        ],
},

"PROCESS_OUTGOING_CALLS" : {
        "android.content.Intent" : [
                ["C","ACTION_NEW_OUTGOING_CALL","public static final String"],
        ],
},

"GET_TASKS" : {
        "android.app.ActivityManager" : [
                ["F","getRecentTasks(int, int)","public List"],
                ["F","getRunningTasks(int)","public List"],
        ],
},

"SET_TIME" : {
        "android.app.AlarmManager" : [
                ["F","setTime(long)","public void"],
                ["F","setTimeZone(java.lang.String)","public void"],
        ],
},

"ACCESS_WIFI_STATE" : {
        "android.net.sip.SipAudioCall" : [
                ["F","startAudio()","public void"],
        ],
},

"READ_HISTORY_BOOKMARKS" : {
        "android.provider.Browser" : [
                ["C","BOOKMARKS_URI","public static final Uri"],
                ["C","SEARCHES_URI","public static final Uri"],
                ["F","addSearchUrl(android.content.ContentResolver, java.lang.String)","public static final void"],
                ["F","canClearHistory(android.content.ContentResolver)","public static final boolean"],
                ["F","getAllBookmarks(android.content.ContentResolver)","public static final Cursor"],
                ["F","getAllVisitedUrls(android.content.ContentResolver)","public static final Cursor"],
                ["F","requestAllIcons(android.content.ContentResolver, java.lang.String, android.webkit.WebIconDatabase.IconListener)","public static final void"],
                ["F","truncateHistory(android.content.ContentResolver)","public static final void"],
                ["F","updateVisitedHistory(android.content.ContentResolver, java.lang.String, boolean)","public static final void"],
        ],
},

"STATUS_BAR" : {
        "android.view.View.OnSystemUiVisibilityChangeListener" : [
                ["F","onSystemUiVisibilityChange(int)","public abstract void"],
        ],
        "android.view.View" : [
                ["C","STATUS_BAR_HIDDEN","public static final int"],
                ["C","STATUS_BAR_VISIBLE","public static final int"],
        ],
        "android.view.WindowManager.LayoutParams" : [
                ["C","TYPE_STATUS_BAR","public static final int"],
                ["C","TYPE_STATUS_BAR_PANEL","public static final int"],
                ["C","systemUiVisibility","public int"],
                ["C","type","public int"],
        ],
},

"READ_LOGS" : {
        "android.os.DropBoxManager" : [
                ["C","ACTION_DROPBOX_ENTRY_ADDED","public static final String"],
                ["F","getNextEntry(java.lang.String, long)","public DropBoxManager.Entry"],
        ],
},

"BLUETOOTH" : {
        "android.os.Process" : [
                ["C","BLUETOOTH_GID","public static final int"],
        ],
        "android.content.pm.PackageManager" : [
                ["C","FEATURE_BLUETOOTH","public static final String"],
        ],
        "android.media.AudioManager" : [
                ["C","ROUTE_BLUETOOTH","public static final int"],
                ["C","ROUTE_BLUETOOTH_A2DP","public static final int"],
                ["C","ROUTE_BLUETOOTH_SCO","public static final int"],
        ],
        "android.provider.Settings.System" : [
                ["C","AIRPLANE_MODE_RADIOS","public static final String"],
                ["C","BLUETOOTH_DISCOVERABILITY","public static final String"],
                ["C","BLUETOOTH_DISCOVERABILITY_TIMEOUT","public static final String"],
                ["C","BLUETOOTH_ON","public static final String"],
                ["C","RADIO_BLUETOOTH","public static final String"],
                ["C","VOLUME_BLUETOOTH_SCO","public static final String"],
        ],
        "android.provider.Settings" : [
                ["C","ACTION_BLUETOOTH_SETTINGS","public static final String"],
        ],
        "android.bluetooth.BluetoothAdapter" : [
                ["C","ACTION_CONNECTION_STATE_CHANGED","public static final String"],
                ["C","ACTION_DISCOVERY_FINISHED","public static final String"],
                ["C","ACTION_DISCOVERY_STARTED","public static final String"],
                ["C","ACTION_LOCAL_NAME_CHANGED","public static final String"],
                ["C","ACTION_REQUEST_DISCOVERABLE","public static final String"],
                ["C","ACTION_REQUEST_ENABLE","public static final String"],
                ["C","ACTION_SCAN_MODE_CHANGED","public static final String"],
                ["C","ACTION_STATE_CHANGED","public static final String"],
                ["F","cancelDiscovery()","public boolean"],
                ["F","disable()","public boolean"],
                ["F","enable()","public boolean"],
                ["F","getAddress()","public String"],
                ["F","getBondedDevices()","public Set"],
                ["F","getName()","public String"],
                ["F","getScanMode()","public int"],
                ["F","getState()","public int"],
                ["F","isDiscovering()","public boolean"],
                ["F","isEnabled()","public boolean"],
                ["F","listenUsingInsecureRfcommWithServiceRecord(java.lang.String, java.util.UUID)","public BluetoothServerSocket"],
                ["F","listenUsingRfcommWithServiceRecord(java.lang.String, java.util.UUID)","public BluetoothServerSocket"],
                ["F","setName(java.lang.String)","public boolean"],
                ["F","startDiscovery()","public boolean"],
        ],
        "android.bluetooth.BluetoothProfile" : [
                ["F","getConnectedDevices()","public abstract List"],
                ["F","getConnectionState(android.bluetooth.BluetoothDevice)","public abstract int"],
                ["F","getDevicesMatchingConnectionStates(int[])","public abstract List"],
        ],
        "android.bluetooth.BluetoothHeadset" : [
                ["C","ACTION_AUDIO_STATE_CHANGED","public static final String"],
                ["C","ACTION_CONNECTION_STATE_CHANGED","public static final String"],
                ["C","ACTION_VENDOR_SPECIFIC_HEADSET_EVENT","public static final String"],
                ["F","getConnectedDevices()","public List"],
                ["F","getConnectionState(android.bluetooth.BluetoothDevice)","public int"],
                ["F","getDevicesMatchingConnectionStates(int[])","public List"],
                ["F","isAudioConnected(android.bluetooth.BluetoothDevice)","public boolean"],
                ["F","startVoiceRecognition(android.bluetooth.BluetoothDevice)","public boolean"],
                ["F","stopVoiceRecognition(android.bluetooth.BluetoothDevice)","public boolean"],
        ],
        "android.bluetooth.BluetoothDevice" : [
                ["C","ACTION_ACL_CONNECTED","public static final String"],
                ["C","ACTION_ACL_DISCONNECTED","public static final String"],
                ["C","ACTION_ACL_DISCONNECT_REQUESTED","public static final String"],
                ["C","ACTION_BOND_STATE_CHANGED","public static final String"],
                ["C","ACTION_CLASS_CHANGED","public static final String"],
                ["C","ACTION_FOUND","public static final String"],
                ["C","ACTION_NAME_CHANGED","public static final String"],
                ["F","createInsecureRfcommSocketToServiceRecord(java.util.UUID)","public BluetoothSocket"],
                ["F","createRfcommSocketToServiceRecord(java.util.UUID)","public BluetoothSocket"],
                ["F","getBluetoothClass()","public BluetoothClass"],
                ["F","getBondState()","public int"],
                ["F","getName()","public String"],
        ],
        "android.provider.Settings.Secure" : [
                ["C","BLUETOOTH_ON","public static final String"],
        ],
        "android.bluetooth.BluetoothA2dp" : [
                ["C","ACTION_CONNECTION_STATE_CHANGED","public static final String"],
                ["C","ACTION_PLAYING_STATE_CHANGED","public static final String"],
                ["F","getConnectedDevices()","public List"],
                ["F","getConnectionState(android.bluetooth.BluetoothDevice)","public int"],
                ["F","getDevicesMatchingConnectionStates(int[])","public List"],
                ["F","isA2dpPlaying(android.bluetooth.BluetoothDevice)","public boolean"],
        ],
        "android.bluetooth.BluetoothAssignedNumbers" : [
                ["C","BLUETOOTH_SIG","public static final int"],
        ],
},

"WRITE_HISTORY_BOOKMARKS" : {
        "android.provider.Browser" : [
                ["C","BOOKMARKS_URI","public static final Uri"],
                ["C","SEARCHES_URI","public static final Uri"],
                ["F","addSearchUrl(android.content.ContentResolver, java.lang.String)","public static final void"],
                ["F","clearHistory(android.content.ContentResolver)","public static final void"],
                ["F","clearSearches(android.content.ContentResolver)","public static final void"],
                ["F","deleteFromHistory(android.content.ContentResolver, java.lang.String)","public static final void"],
                ["F","deleteHistoryTimeFrame(android.content.ContentResolver, long, long)","public static final void"],
                ["F","truncateHistory(android.content.ContentResolver)","public static final void"],
                ["F","updateVisitedHistory(android.content.ContentResolver, java.lang.String, boolean)","public static final void"],
        ],
},

"ACCOUNT_MANAGER" : {
        "android.accounts.AccountManager" : [
                ["C","KEY_ACCOUNT_MANAGER_RESPONSE","public static final String"],
        ],
},

"GET_ACCOUNTS" : {
        "android.accounts.AccountManager" : [
                ["F","getAccounts()","public Account[]"],
                ["F","getAccountsByType(java.lang.String)","public Account[]"],
                ["F","getAccountsByTypeAndFeatures(java.lang.String, java.lang.String[], android.accounts.AccountManagerCallback<android.accounts.Account[]>, android.os.Handler)","public AccountManagerFuture"],
                ["F","hasFeatures(android.accounts.Account, java.lang.String[], android.accounts.AccountManagerCallback<java.lang.Boolean>, android.os.Handler)","public AccountManagerFuture"],
        ],
},

"WRITE_EXTERNAL_STORAGE" : {
        "android.os.Build.VERSION_CODES" : [
                ["C","DONUT","public static final int"],
        ],
        "android.app.DownloadManager.Request" : [
                ["F","setDestinationUri(android.net.Uri)","public DownloadManager.Request"],
        ],
},

"REBOOT" : {
        "android.os.RecoverySystem" : [
                ["F","installPackage(android.content.Context, java.io.File)","public static void"],
                ["F","rebootWipeUserData(android.content.Context)","public static void"],
        ],
        "android.content.Intent" : [
                ["C","IntentResolution","public static final String"],
                ["C","ACTION_REBOOT","public static final String"],
        ],
        "android.os.PowerManager" : [
                ["F","reboot(java.lang.String)","public void"],
        ],
},

}
