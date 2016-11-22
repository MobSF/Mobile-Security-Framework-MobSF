# This file is part of Androguard.
#
# Copyright (C) 2012, Anthony Desnos <desnos at t0t0.fr>
# All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# frameworks/base/core/res/AndroidManifest.xml
########################################## PERMISSIONS ########################################################
DVM_PERMISSIONS = {
    "MANIFEST_PERMISSION": {

    # MESSAGES
    "SEND_SMS": ["dangerous", "send SMS messages", "Allows application to send SMS messages. Malicious applications may cost you money by sending messages without your confirmation."],
    "SEND_SMS_NO_CONFIRMATION": ["signatureOrSystem", "send SMS messages", "send SMS messages via the Messaging app with no user input or confirmation"],
    "RECEIVE_SMS": ["dangerous", "receive SMS", "Allows application to receive and process SMS messages. Malicious applications may monitor your messages or delete them without showing them to you."],
    "RECEIVE_MMS": ["dangerous", "receive MMS", "Allows application to receive and process MMS messages. Malicious applications may monitor your messages or delete them without showing them to you."],
    "RECEIVE_EMERGENCY_BROADCAST": [ "signatureOrSystem", "", "Allows an application to receive emergency cell broadcast messages, to record or display them to the user. Reserved for system apps." ],
    "READ_CELL_BROADCASTS"          : [ "dangerous", "received cell broadcast messages", "Allows an application to read previously received cell broadcast "\
																																								         "messages and to register a content observer to get notifications when "\
																																								         "a cell broadcast has been received and added to the database. For "\
																																								         "emergency alerts, the database is updated immediately after the "\
																																								         "alert dialog and notification sound/vibration/speech are presented."\
																																								         "The \"read\" column is then updated after the user dismisses the alert."\
																																								         "This enables supplementary emergency assistance apps to start loading "\
																																								         "additional emergency information (if Internet access is available) "\
																																								         "when the alert is first received, and to delay presenting the info "\
																																								         "to the user until after the initial alert dialog is dismissed." ],
		"READ_SMS" : [ "dangerous" , "read SMS or MMS" , "Allows application to read SMS messages stored on your phone or SIM card. Malicious applications may read your confidential messages." ],
		"WRITE_SMS" : [ "dangerous" , "edit SMS or MMS" , "Allows application to write to SMS messages stored on your phone or SIM card. Malicious applications may delete your messages." ],
		"RECEIVE_WAP_PUSH" : [ "dangerous" , "receive WAP" , "Allows application to receive and process WAP messages. Malicious applications may monitor your messages or delete them without showing them to you." ],
		"BROADCAST_SMS" : [ "signature" , "send SMS-received broadcast" , "Allows an application to broadcast a notification that an SMS message has been received. Malicious applications may use this to forge incoming SMS messages." ],
		"BROADCAST_WAP_PUSH" : [ "signature" , "send WAP-PUSH-received broadcast" , "Allows an application to broadcast a notification that a WAP-PUSH message has been received. Malicious applications may use this to forge MMS message receipt or to replace the content of any web page silently with malicious variants." ],

		# SOCIAL_INFO
		"READ_CONTACTS" : [ "dangerous" , "read contact data" , "Allows an application to read all of the contact (address) data stored on your phone. Malicious applications can use this to send your data to other people." ],
		"WRITE_CONTACTS" : [ "dangerous" , "write contact data" , "Allows an application to modify the contact (address) data stored on your phone. Malicious applications can use this to erase or modify your contact data." ],
    "BIND_DIRECTORY_SEARCH" : [ "signatureOrSystem", "execute contacts directory search", "Allows an application to execute contacts directory search. This should only be used by ContactsProvider." ],
    "READ_CALL_LOG": [ "dangerous", "read the user's call log.", "Allows an application to read the user's call log." ],
    "WRITE_CALL_LOG": [ "dangerous", "write (but not read) the user's contacts data.", "Allows an application to write (but not read) the user's contacts data." ],
    "READ_SOCIAL_STREAM" : [ "dangerous", "read from the user's social stream", "Allows an application to read from the user's social stream." ],
    "WRITE_SOCIAL_STREAM" : [ "dangerous", "write the user's social stream", "Allows an application to write (but not read) the user's social stream data." ],

    # PERSONAL_INFO
    "READ_PROFILE" : [ "dangerous", "read the user's personal profile data", "Allows an application to read the user's personal profile data."],
    "WRITE_PROFILE" : [ "dangerous", "write the user's personal profile data", "Allows an application to write (but not read) the user's personal profile data."],
    "RETRIEVE_WINDOW_CONTENT": [ "signatureOrSystem", "", "Allows an application to retrieve the content of the active window An active window is the window that has fired an accessibility event. " ],
		"BIND_APPWIDGET" : [ "signatureOrSystem" , "choose widgets" , "Allows the application to tell the system which widgets can be used by which application. With this permission, applications can give access to personal data to other applications. Not for use by normal applications." ],
    "BIND_KEYGUARD_APPWIDGET"       : [ "signatureOrSystem", "", "Private permission, to restrict who can bring up a dialog to add a new keyguard widget" ],

    # CALENDAR
    "READ_CALENDAR" : [ "dangerous" , "read calendar events" , "Allows an application to read all of the calendar events stored on your phone. Malicious applications can use this to send your calendar events to other people." ],
		"WRITE_CALENDAR": [ "dangerous" , "add or modify calendar events and send emails to guests" , "Allows an application to add or change the events on your calendar, which may send emails to guests. Malicious applications can use this to erase or modify your calendar events or to send emails to guests." ],


    # USER_DICTIONARY
  	"READ_USER_DICTIONARY" : [ "dangerous" , "read user-defined dictionary" , "Allows an application to read any private words, names and phrases that the user may have stored in the user dictionary." ],

  	# WRITE_USER_DICTIONARY
		"WRITE_USER_DICTIONARY" : [ "normal" , "write to user-defined dictionary" , "Allows an application to write new words into the user dictionary." ],

		# BOOKMARKS
		"READ_HISTORY_BOOKMARKS" : [ "dangerous" , "read Browser\'s history and bookmarks" , "Allows the application to read all the URLs that the browser has visited and all of the browser\'s bookmarks." ],
		"WRITE_HISTORY_BOOKMARKS" : [ "dangerous" , "write Browser\'s history and bookmarks" , "Allows an application to modify the browser\'s history or bookmarks stored on your phone. Malicious applications can use this to erase or modify your browser\'s data." ],

		# DEVICE_ALARMS
		"SET_ALARM" : [ "normal" , "set alarm in alarm clock" , "Allows the application to set an alarm in an installed alarm clock application. Some alarm clock applications may not implement this feature." ],

		# VOICEMAIL
    "ADD_VOICEMAIL" : [ "dangerous", "add voicemails into the system", "Allows an application to add voicemails into the system." ],

    # LOCATION
		"ACCESS_FINE_LOCATION" : [ "dangerous" , "fine (GPS) location" , "Access fine location sources, such as the Global Positioning System on the phone, where available. Malicious applications can use this to determine where you are and may consume additional battery power." ],
		"ACCESS_COARSE_LOCATION" : [ "dangerous" , "coarse (network-based) location" , "Access coarse location sources, such as the mobile network database, to determine an approximate phone location, where available. Malicious applications can use this to determine approximately where you are." ],
		"ACCESS_MOCK_LOCATION" : [ "dangerous" , "mock location sources for testing" , "Create mock location sources for testing. Malicious applications can use this to override the location and/or status returned by real-location sources such as GPS or Network providers." ],
		"ACCESS_LOCATION_EXTRA_COMMANDS" : [ "normal" , "access extra location provider commands" , "Access extra location provider commands. Malicious applications could use this to interfere with the operation of the GPS or other location sources." ],
  	"INSTALL_LOCATION_PROVIDER" : [ "signatureOrSystem" , "permission to install a location provider" , "Create mock location sources for testing. Malicious applications can use this to override the location and/or status returned by real-location sources such as GPS or Network providers, or monitor and report your location to an external source." ],


  	# NETWORK
		"INTERNET" : [ "dangerous" , "full Internet access" , "Allows an application to create network sockets." ],
		"ACCESS_NETWORK_STATE" : [ "normal" , "view network status" , "Allows an application to view the status of all networks." ],
		"ACCESS_WIFI_STATE" : [ "normal" , "view Wi-Fi status" , "Allows an application to view the information about the status of Wi-Fi." ],
		"CHANGE_WIFI_STATE" : [ "dangerous" , "change Wi-Fi status" , "Allows an application to connect to and disconnect from Wi-Fi access points and to make changes to configured Wi-Fi networks." ],
		"CHANGE_NETWORK_STATE" : [ "normal" , "change network connectivity" , "Allows an application to change the state of network connectivity." ],
    "ACCESS_WIMAX_STATE": [ "normal", "", "" ],
    "CHANGE_WIMAX_STATE": [ "dangerous", "", "" ],
		"NFC" : [ "dangerous" , "control Near-Field Communication" , "Allows an application to communicate with Near-Field Communication (NFC) tags, cards and readers." ],
    "CONNECTIVITY_INTERNAL": [ "signatureOrSystem", "use privileged ConnectivityManager API", "Allows an internal user to use privileged ConnectivityManager API" ],
    "RECEIVE_DATA_ACTIVITY_CHANGE": [ "signatureOrSystem", "", "" ],


		# BLUETOOTH_NETWORK
		"BLUETOOTH" : [ "dangerous" , "create Bluetooth connections" , "Allows an application to view configuration of the local Bluetooth phone and to make and accept connections with paired devices." ],
		"BLUETOOTH_ADMIN" : [ "dangerous" , "bluetooth administration" , "Allows an application to configure the local Bluetooth phone and to discover and pair with remote devices." ],


		# SYSTEM TOOLS
    "BLUETOOTH_STACK": [ "signature", "", "" ],
    "NET_ADMIN": [ "signature", "configure network interfaces, configure/use IPSec, etc", "Allows access to configure network interfaces, configure/use IPSec, etc." ],
    "REMOTE_AUDIO_PLAYBACK": [ "signature", "remote audio playback", "Allows registration for remote audio playback" ],
    "READ_EXTERNAL_STORAGE" : [ "normal", "read from external storage", "Allows an application to read from external storage" ],
    "INTERACT_ACROSS_USERS": [ "signatureOrSystemOrDevelopment", "", "Allows an application to call APIs that allow it to do interactions across the users on the device, using singleton services and user-targeted broadcasts.  This permission is not available to third party applications." ],
    "INTERACT_ACROSS_USERS_FULL": [ "signature", "", "Fuller form of INTERACT_ACROSS_USERS that removes restrictions on where broadcasts can be sent and allows other types of interactions." ],
    "MANAGE_USERS": [ "signatureOrSystem", "", "Allows an application to call APIs that allow it to query and manage users on the device. This permission is not available to third party applications." ],
    "GET_DETAILED_TASKS": [ "signature", "", "Allows an application to get full detailed information about recently running tasks, with full fidelity to the real state." ],
    "START_ANY_ACTIVITY": [ "signature", "", "Allows an application to start any activity, regardless of permission protection or exported state." ],
    "SET_SCREEN_COMPATIBILITY": [ "signature", "", "Change the screen compatibility mode of applications" ],
		"CHANGE_CONFIGURATION" : [ "signatureOrSystemOrDevelopment" , "change your UI settings" , "Allows an application to change the current configuration, such as the locale or overall font size." ],
		"FORCE_STOP_PACKAGES" : [ "signature" , "force-stop other applications" , "Allows an application to stop other applications forcibly." ],
		"SET_ANIMATION_SCALE" : [ "signatureOrSystemOrDevelopment" , "modify global animation speed" , "Allows an application to change the global animation speed (faster or slower animations) at any time." ],
		"GET_PACKAGE_SIZE" : [ "normal" , "measure application storage space" , "Allows an application to retrieve its code, data and cache sizes" ],
		"SET_PREFERRED_APPLICATIONS" : [ "signature" , "set preferred applications" , "Allows an application to modify your preferred applications. This can allow malicious applications to silently change the applications that are run, spoofing your existing applications to collect private data from you." ],
		"BROADCAST_STICKY" : [ "normal" , "send sticky broadcast" , "Allows an application to send sticky broadcasts, which remain after the broadcast ends. Malicious applications can make the phone slow or unstable by causing it to use too much memory." ],
	  "MOUNT_UNMOUNT_FILESYSTEMS" : [ "signatureOrSystem" , "mount and unmount file systems" , "Allows the application to mount and unmount file systems for removable storage." ],
		"MOUNT_FORMAT_FILESYSTEMS" : [ "signatureOrSystem" , "format external storage" , "Allows the application to format removable storage." ],
		"ASEC_ACCESS" : [ "signature" , "get information on internal storage" , "Allows the application to get information on internal storage." ],
	  "ASEC_CREATE" : [ "signature" , "create internal storage" , "Allows the application to create internal storage." ],
		"ASEC_DESTROY" : [ "signature" , "destroy internal storage" , "Allows the application to destroy internal storage." ],
		"ASEC_MOUNT_UNMOUNT" : [ "signature" , "mount/unmount internal storage" , "Allows the application to mount/unmount internal storage." ],
		"ASEC_RENAME" : [ "signature" , "rename internal storage" , "Allows the application to rename internal storage." ],
    "WRITE_APN_SETTINGS" : [ "signatureOrSystem" , "write Access Point Name settings" , "Allows an application to modify the APN settings, such as Proxy and Port of any APN." ],
		"SUBSCRIBED_FEEDS_READ" : [ "normal" , "read subscribed feeds" , "Allows an application to receive details about the currently synced feeds." ],
		"SUBSCRIBED_FEEDS_WRITE" : [ "dangerous" , "write subscribed feeds" , "Allows an application to modify your currently synced feeds. This could allow a malicious application to change your synced feeds." ],
		"CLEAR_APP_CACHE" : [ "dangerous" , "delete all application cache data" , "Allows an application to free phone storage by deleting files in application cache directory. Access is usually very restricted to system process." ],
		"DIAGNOSTIC" : [ "signature" , "read/write to resources owned by diag" , "Allows an application to read and write to any resource owned by the diag group; for example, files in /dev. This could potentially affect system stability and security. This should ONLY be used for hardware-specific diagnostics by the manufacturer or operator." ],
		"BROADCAST_PACKAGE_REMOVED" : [ "signature" , "send package removed broadcast" , "Allows an application to broadcast a notification that an application package has been removed. Malicious applications may use this to kill any other application running." ],
		"BATTERY_STATS" : [ "dangerous" , "modify battery statistics" , "Allows the modification of collected battery statistics. Not for use by normal applications." ],
    "MODIFY_APPWIDGET_BIND_PERMISSIONS" : [ "signatureOrSystem", "query/set which applications can bind AppWidgets.", "Internal permission allowing an application to query/set which applications can bind AppWidgets." ],
		"CHANGE_BACKGROUND_DATA_SETTING" : [ "signature" , "change background data usage setting" , "Allows an application to change the background data usage setting." ],
		"GLOBAL_SEARCH" : [ "signatureOrSystem" , "" , "This permission can be used on content providers to allow the global search " \
																									 "system to access their data.  Typically it used when the provider has some "  \
																									 "permissions protecting it (which global search would not be expected to hold)," \
																									 "and added as a read-only permission to the path in the provider where global "\
																									 "search queries are performed.  This permission can not be held by regular applications; "\
         																					 "it is used by applications to protect themselves from everyone else besides global search" ],
		"GLOBAL_SEARCH_CONTROL" : [ "signature" , "" , "Internal permission protecting access to the global search "			  \
																						       "system: ensures that only the system can access the provider " 		  \
																						       "to perform queries (since this otherwise provides unrestricted "	  \
																						       "access to a variety of content providers), and to write the "				\
																						       "search statistics (to keep applications from gaming the source "		\
																						       "ranking)." ],
		"SET_WALLPAPER_COMPONENT" : [ "signatureOrSystem" , "set a live wallpaper" , "Allows applications to set a live wallpaper." ],
    "READ_DREAM_STATE"              : [ "signature", "", "Allows applications to read dream settings and dream state." ],
    "WRITE_DREAM_STATE"             : [ "signature", "", "Allows applications to write dream settings, and start or stop dreaming." ],
		"WRITE_SETTINGS" : [ "normal" , "modify global system settings" , "Allows an application to modify the system\'s settings data. Malicious applications can corrupt your system\'s configuration." ],

   	# ACCOUNTS
		"GET_ACCOUNTS" : [ "normal" , "discover known accounts" , "Allows an application to access the list of accounts known by the phone." ],
		"AUTHENTICATE_ACCOUNTS" : [ "dangerous" , "act as an account authenticator" , "Allows an application to use the account authenticator capabilities of the Account Manager, including creating accounts as well as obtaining and setting their passwords." ],
		"USE_CREDENTIALS" : [ "dangerous" , "use the authentication credentials of an account" , "Allows an application to request authentication tokens." ],
		"MANAGE_ACCOUNTS" : [ "dangerous" , "manage the accounts list" , "Allows an application to perform operations like adding and removing accounts and deleting their password." ],
		"ACCOUNT_MANAGER" : [ "signature" , "act as the Account Manager Service" , "Allows an application to make calls to Account Authenticators" ],

		# AFFECTS_BATTERY
		"CHANGE_WIFI_MULTICAST_STATE" : [ "dangerous" , "allow Wi-Fi Multicast reception" , "Allows an application to receive packets not directly addressed to your device. This can be useful when discovering services offered nearby. It uses more power than the non-multicast mode." ],
		"VIBRATE" : [ "normal" , "control vibrator" , "Allows the application to control the vibrator." ],
		"FLASHLIGHT" : [ "normal" , "control flashlight" , "Allows the application to control the flashlight." ],
		"WAKE_LOCK" : [ "normal" , "prevent phone from sleeping" , "Allows an application to prevent the phone from going to sleep." ],

		# AUDIO_SETTINGS
		"MODIFY_AUDIO_SETTINGS" : [ "normal" , "change your audio settings" , "Allows application to modify global audio settings, such as volume and routing." ],

		# HARDWARE_CONTROLS
    "MANAGE_USB": [ "signatureOrSystem", "manage preferences and permissions for USB devices", "Allows an application to manage preferences and permissions for USB devices" ],
    "ACCESS_MTP": [ "signatureOrSystem", "access the MTP USB kernel driver", "Allows an application to access the MTP USB kernel driver. For use only by the device side MTP implementation." ],
		"HARDWARE_TEST" : [ "signature" , "test hardware" , "Allows the application to control various peripherals for the purpose of hardware testing." ],

		# MICROPHONE
		"RECORD_AUDIO" : [ "dangerous" , "record audio" , "Allows application to access the audio record path." ],

		# CAMERA
		"CAMERA" : [ "dangerous" , "take pictures and videos" , "Allows application to take pictures and videos with the camera. This allows the application to collect images that the camera is seeing at any time." ],

		# PHONE_CALLS
		"PROCESS_OUTGOING_CALLS" : [ "dangerous" , "intercept outgoing calls" , "Allows application to process outgoing calls and change the number to be dialled. Malicious applications may monitor, redirect or prevent outgoing calls." ],
		"MODIFY_PHONE_STATE" : [ "signatureOrSystem" , "modify phone status" , "Allows modification of the telephony state - power on, mmi, etc. Does not include placing calls." ],
		"READ_PHONE_STATE" : [ "dangerous" , "read phone state and identity" , "Allows the application to access the phone features of the device. An application with this permission can determine the phone number and serial number of this phone, whether a call is active, the number that call is connected to and so on." ],
    "READ_PRIVILEGED_PHONE_STATE": [ "signatureOrSystem", "read access to privileged phone state", "Allows read access to privileged phone state." ],
    "CALL_PHONE" : [ "dangerous" , "directly call phone numbers" , "Allows an application to initiate a phone call without going through the Dialer user interface for the user to confirm the call being placed. " ],
		"USE_SIP" : [ "dangerous" , "make/receive Internet calls" , "Allows an application to use the SIP service to make/receive Internet calls." ],

		# STORAGE
		"WRITE_EXTERNAL_STORAGE" : [ "dangerous" , "modify/delete SD card contents" , "Allows an application to write to the SD card." ],
    "WRITE_MEDIA_STORAGE": [ "signatureOrSystem", "write to internal media storage", "Allows an application to write to internal media storage" ],

    # SCREENLOCK
		"DISABLE_KEYGUARD" : [ "dangerous" , "disable key lock" , "Allows an application to disable the key lock and any associated password security. A legitimate example of this is the phone disabling the key lock when receiving an incoming phone call, then re-enabling the key lock when the call is finished." ],

		# APP_INFO
		"GET_TASKS" : [ "dangerous" , "retrieve running applications" , "Allows application to retrieve information about currently and recently running tasks. May allow malicious applications to discover private information about other applications." ],
		"REORDER_TASKS" : [ "normal" , "reorder applications running" , "Allows an application to move tasks to the foreground and background. Malicious applications can force themselves to the front without your control." ],
    "REMOVE_TASKS": [ "signature", "", "Allows an application to change to remove/kill tasks" ],
		"RESTART_PACKAGES" : [ "normal" , "kill background processes" , "Allows an application to kill background processes of other applications, even if memory is not low." ],
		"KILL_BACKGROUND_PROCESSES" : [ "normal" , "kill background processes" , "Allows an application to kill background processes of other applications, even if memory is not low." ],
		"PERSISTENT_ACTIVITY" : [ "normal" , "make application always run" , "Allows an application to make parts of itself persistent, so that the system can\'t use it for other applications." ],
		"RECEIVE_BOOT_COMPLETED" : [ "normal" , "automatically start at boot" , "Allows an application to start itself as soon as the system has finished booting. This can make it take longer to start the phone and allow the application to slow down the overall phone by always running." ],

		# DISPLAY
		"SYSTEM_ALERT_WINDOW" : [ "dangerous" , "display system-level alerts" , "Allows an application to show system-alert windows. Malicious applications can take over the entire screen of the phone." ],

		# WALLPAPER
	  "SET_WALLPAPER" : [ "normal" , "set wallpaper" , "Allows the application to set the system wallpaper." ],
		"SET_WALLPAPER_HINTS" : [ "normal" , "set wallpaper size hints" , "Allows the application to set the system wallpaper size hints." ],

		# SYSTEM_CLOCK
		"SET_TIME_ZONE" : [ "normal" , "set time zone" , "Allows an application to change the phone\'s time zone." ],

		# STATUS_BAR
		"EXPAND_STATUS_BAR" : [ "normal" , "expand/collapse status bar" , "Allows application to expand or collapse the status bar." ],

		# SYNC_SETTINGS
		"READ_SYNC_SETTINGS" : [ "normal" , "read sync settings" , "Allows an application to read the sync settings, such as whether sync is enabled for Contacts." ],
		"WRITE_SYNC_SETTINGS" : [ "normal" , "write sync settings" , "Allows an application to modify the sync settings, such as whether sync is enabled for Contacts." ],
		"READ_SYNC_STATS" : [ "normal" , "read sync statistics" , "Allows an application to read the sync stats; e.g. the history of syncs that have occurred." ],

    # DEVELOPMENT_TOOLS
		"WRITE_SECURE_SETTINGS" : [ "signatureOrSystemOrDevelopment" , "modify secure system settings" , "Allows an application to modify the system\'s secure settings data. Not for use by normal applications." ],
		"DUMP" : [ "signatureOrSystemOrDevelopment" , "retrieve system internal status" , "Allows application to retrieve internal status of the system. Malicious applications may retrieve a wide variety of private and secure information that they should never normally need." ],
		"READ_LOGS" : [ "signatureOrSystemOrDevelopment" , "read sensitive log data" , "Allows an application to read from the system\'s various log files. This allows it to discover general information about what you are doing with the phone, potentially including personal or private information." ],
		"SET_DEBUG_APP" : [ "signatureOrSystemOrDevelopment" , "enable application debugging" , "Allows an application to turn on debugging for another application. Malicious applications can use this to kill other applications." ],
		"SET_PROCESS_LIMIT" : [ "signatureOrSystemOrDevelopment" , "limit number of running processes" , "Allows an application to control the maximum number of processes that will run. Never needed for normal applications." ],
		"SET_ALWAYS_FINISH" : [ "signatureOrSystemOrDevelopment" , "make all background applications close" , "Allows an application to control whether activities are always finished as soon as they go to the background. Never needed for normal applications." ],
		"SIGNAL_PERSISTENT_PROCESSES" : [ "signatureOrSystemOrDevelopment" , "send Linux signals to applications" , "Allows application to request that the supplied signal be sent to all persistent processes." ],
    "ACCESS_ALL_EXTERNAL_STORAGE"   : [ "signature", "", "Allows an application to access all multi-user external storage" ],

		# No groups ...
		"SET_TIME": [ "signatureOrSystem" , "set time" , "Allows an application to change the phone\'s clock time." ],
    "ALLOW_ANY_CODEC_FOR_PLAYBACK": [ "signatureOrSystem", "", "Allows an application to use any media decoder when decoding for playback." ],
		"STATUS_BAR" : [ "signatureOrSystem" , "disable or modify status bar" , "Allows application to disable the status bar or add and remove system icons." ],
		"STATUS_BAR_SERVICE" : [ "signature" , "status bar" , "Allows the application to be the status bar." ],
		"FORCE_BACK" : [ "signature" , "force application to close" , "Allows an application to force any activity that is in the foreground to close and go back. Should never be needed for normal applications." ],
		"UPDATE_DEVICE_STATS" : [ "signatureOrSystem" , "modify battery statistics" , "Allows the modification of collected battery statistics. Not for use by normal applications." ],
		"INTERNAL_SYSTEM_WINDOW" : [ "signature" , "display unauthorised windows" , "Allows the creation of windows that are intended to be used by the internal system user interface. Not for use by normal applications." ],
		"MANAGE_APP_TOKENS" : [ "signature" , "manage application tokens" , "Allows applications to create and manage their own tokens, bypassing their normal Z-ordering. Should never be needed for normal applications." ],
    "FREEZE_SCREEN": [ "signature", "", "Allows the application to temporarily freeze the screen for a full-screen transition." ],
		"INJECT_EVENTS" : [ "signature" , "inject user events" , "Allows an application to inject user events (keys, touch, trackball) into the event stream and deliver them to ANY window.  Without this permission, you can only deliver events to windows in your own process. Very few applications should need to use this permission" ],
    "FILTER_EVENTS": [ "signature", "", "Allows an application to register an input filter which filters the stream of user events (keys, touch, trackball) before they are dispatched to any window" ],
    "RETRIEVE_WINDOW_INFO"          : [ "signature", "", "Allows an application to retrieve info for a window from the window manager." ],
    "TEMPORARY_ENABLE_ACCESSIBILITY": [ "signature", "", "Allows an application to temporary enable accessibility on the device." ],
    "MAGNIFY_DISPLAY": [ "signature", "", "Allows an application to magnify the content of a display." ],
		"SET_ACTIVITY_WATCHER" : [ "signature" , "monitor and control all application launching" , "Allows an application to monitor and control how the system launches activities. Malicious applications may compromise the system completely. This permission is needed only for development, never for normal phone usage." ],
		"SHUTDOWN" : [ "signatureOrSystem" , "partial shutdown" , "Puts the activity manager into a shut-down state. Does not perform a complete shut down." ],
		"STOP_APP_SWITCHES" : [ "signatureOrSystem" , "prevent app switches" , "Prevents the user from switching to another application." ],
		"READ_INPUT_STATE" : [ "signature" , "record what you type and actions that you take" , "Allows applications to watch the keys that you press even when interacting with another application (such as entering a password). Should never be needed for normal applications." ],
		"BIND_INPUT_METHOD" : [ "signature" , "bind to an input method" , "Allows the holder to bind to the top-level interface of an input method. Should never be needed for normal applications." ],
    "BIND_ACCESSIBILITY_SERVICE"    : [ "signature", "", "Must be required by an android.accessibilityservice.AccessibilityService to ensure that only the system can bind to it. " ],
    "BIND_TEXT_SERVICE"             : [ "signature", "", "Must be required by a TextService (e.g. SpellCheckerService) to ensure that only the system can bind to it." ],
    "BIND_VPN_SERVICE"              : [ "signature", "", "Must be required by an {@link android.net.VpnService}, to ensure that only the system can bind to it." ],
		"BIND_WALLPAPER" : [ "signatureOrSystem" , "bind to wallpaper" , "Allows the holder to bind to the top-level interface of wallpaper. Should never be needed for normal applications." ],
		"BIND_DEVICE_ADMIN" : [ "signature" , "interact with device admin" , "Allows the holder to send intents to a device administrator. Should never be needed for normal applications." ],
		"SET_ORIENTATION" : [ "signature" , "change screen orientation" , "Allows an application to change the rotation of the screen at any time. Should never be needed for normal applications." ],
    "SET_POINTER_SPEED"             : [ "signature", "", "Allows low-level access to setting the pointer speed. Not for use by normal applications. " ],
    "SET_KEYBOARD_LAYOUT"           : [ "signature", "", "Allows low-level access to setting the keyboard layout. Not for use by normal applications." ],
		"INSTALL_PACKAGES" : [ "signatureOrSystem" , "directly install applications" , "Allows an application to install new or updated Android packages. Malicious applications can use this to add new applications with arbitrarily powerful permissions." ],
		"CLEAR_APP_USER_DATA" : [ "signature" , "delete other applications\' data" , "Allows an application to clear user data." ],
		"DELETE_CACHE_FILES" : [ "signatureOrSystem" , "delete other applications\' caches" , "Allows an application to delete cache files." ],
		"DELETE_PACKAGES" : [ "signatureOrSystem" , "delete applications" , "Allows an application to delete Android packages. Malicious applications can use this to delete important applications." ],
		"MOVE_PACKAGE" : [ "signatureOrSystem" , "Move application resources" , "Allows an application to move application resources from internal to external media and vice versa." ],
		"CHANGE_COMPONENT_ENABLED_STATE" : [ "signatureOrSystem" , "enable or disable application components" , "Allows an application to change whether or not a component of another application is enabled. Malicious applications can use this to disable important phone capabilities. It is important to be careful with permission, as it is possible to bring application components into an unusable, inconsistent or unstable state." ],
    "GRANT_REVOKE_PERMISSIONS"      : [ "signature", "", "Allows an application to grant or revoke specific permissions." ],
		"ACCESS_SURFACE_FLINGER" : [ "signature" , "access SurfaceFlinger" , "Allows application to use SurfaceFlinger low-level features." ],
		"READ_FRAME_BUFFER" : [ "signatureOrSystem" , "read frame buffer" , "Allows application to read the content of the frame buffer." ],
    "CONFIGURE_WIFI_DISPLAY"        : [ "signature", "", "Allows an application to configure and connect to Wifi displays" ],  
    "CONTROL_WIFI_DISPLAY"          : [ "signature", "", "Allows an application to control low-level features of Wifi displays such as opening an RTSP socket.  This permission should only be used by the display manager." ],
		"BRICK" : [ "signature" , "permanently disable phone" , "Allows the application to disable the entire phone permanently. This is very dangerous." ],
		"REBOOT" : [ "signatureOrSystem" , "force phone reboot" , "Allows the application to force the phone to reboot." ],
		"DEVICE_POWER" : [ "signature" , "turn phone on or off" , "Allows the application to turn the phone on or off." ],
    "NET_TUNNELING"                 : [ "signature", "", "Allows low-level access to tun tap driver " ],
		"FACTORY_TEST" : [ "signature" , "run in factory test mode" , "Run as a low-level manufacturer test, allowing complete access to the phone hardware. Only available when a phone is running in manufacturer test mode." ],
		"MASTER_CLEAR" : [ "signatureOrSystem" , "reset system to factory defaults" , "Allows an application to completely reset the system to its factory settings, erasing all data, configuration and installed applications." ],
		"CALL_PRIVILEGED" : [ "signatureOrSystem" , "directly call any phone numbers" , "Allows the application to call any phone number, including emergency numbers, without your intervention. Malicious applications may place unnecessary and illegal calls to emergency services." ],
		"PERFORM_CDMA_PROVISIONING" : [ "signatureOrSystem" , "directly start CDMA phone setup" , "Allows the application to start CDMA provisioning. Malicious applications may start CDMA provisioning unnecessarily" ],
		"CONTROL_LOCATION_UPDATES" : [ "signatureOrSystem" , "control location update notifications" , "Allows enabling/disabling location update notifications from the radio. Not for use by normal applications." ],
		"ACCESS_CHECKIN_PROPERTIES" : [ "signatureOrSystem" , "access check-in properties" , "Allows read/write access to properties uploaded by the check-in service. Not for use by normal applications." ],
		"PACKAGE_USAGE_STATS" : [ "signatureOrSystem" , "update component usage statistics" , "Allows the modification of collected component usage statistics. Not for use by normal applications." ],
		"BACKUP" : [ "signatureOrSystem" , "control system back up and restore" , "Allows the application to control the system\'s back-up and restore mechanism. Not for use by normal applications." ],
    "CONFIRM_FULL_BACKUP"           : [ "signature", "", "Allows a package to launch the secure full-backup confirmation UI. ONLY the system process may hold this permission." ],
    "BIND_REMOTEVIEWS"              : [ "signatureOrSystem", "", "Must be required by a {@link android.widget.RemoteViewsService}, to ensure that only the system can bind to it." ],
		"ACCESS_CACHE_FILESYSTEM" : [ "signatureOrSystem" , "access the cache file system" , "Allows an application to read and write the cache file system." ],
		"COPY_PROTECTED_DATA" : [ "signature" , "Allows to invoke default container service to copy content. Not for use by normal applications." , "Allows to invoke default container service to copy content. Not for use by normal applications." ],
    "CRYPT_KEEPER" : [ "signatureOrSystem", "access to the encryption methods", "Internal permission protecting access to the encryption methods" ],
    "READ_NETWORK_USAGE_HISTORY" : [ "signatureOrSystem", "read historical network usage for specific networks and applications.", "Allows an application to read historical network usage for specific networks and applications."],
    "MANAGE_NETWORK_POLICY": [ "signature", "manage network policies and to define application-specific rules.", "Allows an application to manage network policies and to define application-specific rules."],
    "MODIFY_NETWORK_ACCOUNTING" : [ "signatureOrSystem", "account its network traffic against other UIDs.", "Allows an application to account its network traffic against other UIDs."],
		"C2D_MESSAGE" : [ "signature" , "C2DM permission." , "C2DM permission." ],
    "PACKAGE_VERIFICATION_AGENT" : [ "signatureOrSystem", "Package verifier needs to have this permission before the PackageManager will trust it to verify packages.", "Package verifier needs to have this permission before the PackageManager will trust it to verify packages."],
    "BIND_PACKAGE_VERIFIER" : [ "signature", "", "Must be required by package verifier receiver, to ensure that only the system can interact with it.."],
    "SERIAL_PORT"                   : [ "signature", "", "Allows applications to access serial ports via the SerialManager." ],    
    "ACCESS_CONTENT_PROVIDERS_EXTERNALLY": [ "signature", "", "Allows the holder to access content providers from outside an ApplicationThread. This permission is enforced by the ActivityManagerService on the corresponding APIs,in particular ActivityManagerService#getContentProviderExternal(String) and ActivityManagerService#removeContentProviderExternal(String)."],
		"UPDATE_LOCK"   : [ "signatureOrSystem", "", "Allows an application to hold an UpdateLock, recommending that a headless OTA reboot "\
																								 "*not* occur while the lock is held"],
		"WRITE_GSERVICES" : [ "signatureOrSystem" , "modify the Google services map" , "Allows an application to modify the Google services map. Not for use by normal applications." ],

		"ACCESS_USB" : [ "signatureOrSystem" , "access USB devices" , "Allows the application to access USB devices." ],
    },

    "MANIFEST_PERMISSION_GROUP":
        {
        "ACCOUNTS": "Permissions for direct access to the accounts managed by the Account Manager.",
        "AFFECTS_BATTERY": "Used for permissions that provide direct access to the hardware on the device that has an effect on battery life.  This includes vibrator, flashlight,  etc.",
        "APP_INFO": "Group of permissions that are related to the other applications installed on the system.",
        "AUDIO_SETTINGS": "Used for permissions that provide direct access to speaker settings the device.",
        "BLUETOOTH_NETWORK": "Used for permissions that provide access to other devices through Bluetooth.",
        "BOOKMARKS": "Used for permissions that provide access to the user bookmarks and browser history.",
        "CALENDAR": "Used for permissions that provide access to the device calendar to create / view events",
        "CAMERA": "Used for permissions that are associated with accessing camera or capturing images/video from the device.",
        "COST_MONEY": "Used for permissions that can be used to make the user spend money without their direct involvement.",
        "DEVICE_ALARMS": "Used for permissions that provide access to the user voicemail box.",
        "DEVELOPMENT_TOOLS": "Group of permissions that are related to development features.",
        "DISPLAY": "Group of permissions that allow manipulation of how another application displays UI to the user.",
        "HARDWARE_CONTROLS": "Used for permissions that provide direct access to the hardware on the device.",
        "LOCATION": "Used for permissions that allow access to the user's current location.",
        "MESSAGES": "Used for permissions that allow an application to send messages on behalf of the user or intercept messages being received by the user.",
        "MICROPHONE": "Used for permissions that are associated with accessing microphone audio from the device. Note that phone calls also capture audio but are in a separate (more visible) permission group.",
        "NETWORK": "Used for permissions that provide access to networking services.",
        "PERSONAL_INFO": "Used for permissions that provide access to the user's private data, such as contacts, calendar events, e-mail messages, etc.",
        "PHONE_CALLS": "Used for permissions that are associated with accessing and modifyign telephony state: intercepting outgoing calls, reading and modifying the phone state.",
        "STORAGE": "Group of permissions that are related to SD card access.",
        "SOCIAL_INFO": "Used for permissions that provide access to the user's social connections, such as contacts, call logs, social stream, etc.  This includes both reading and writing of this data (which should generally be expressed as two distinct permissions)",
        "SCREENLOCK": "Group of permissions that are related to the screenlock.",
        "STATUS_BAR": "Used for permissions that change the status bar.",
        "SYSTEM_CLOCK": "Group of permissions that are related to system clock.",
        "SYSTEM_TOOLS": "Group of permissions that are related to system APIs.",
        "SYNC_SETTINGS": "Used for permissions that access the sync settings or sync related information.",
        "USER_DICTIONARY": "Used for permissions that provide access to the user calendar to create / view events.",
        "VOICEMAIL": "Used for permissions that provide access to the user voicemail box.",
        "WALLPAPER": "Group of permissions that allow manipulation of how another application displays UI to the user.",
        "WRITE_USER_DICTIONARY": "Used for permissions that provide access to the user calendar to create / view events.",
    },
}
