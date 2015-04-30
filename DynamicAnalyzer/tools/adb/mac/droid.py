import subprocess,re
import json
import logging
import os
filename = "error.log"
package='com.yodlee.tandem'
proc=subprocess.Popen(["adb", "pull","/data/data/de.robv.android.xposed.installer/log/"+filename,filename], stdout=subprocess.PIPE)
proc.communicate()
apimonitor = ""
shell = ""
tag = "Droidmon-apimonitor-"+package
tag_error = "Droidmon-shell-"+package
with open(filename) as log_file:
    
    for line in log_file:
        if tag in line:
            out = re.sub(tag+":", "", line)
            apimonitor=apimonitor+out
        if tag_error in line:
            out = re.sub(tag_error+":", "", line)
            shell=shell+out
with open('droidmon.log','w') as f:
    f.write(apimonitor)

droidmon = {}
droidmon["crypto_keys"] = []
droidmon["reflection_calls"] = set()
droidmon["SystemProperties"] = set()
droidmon["started_activities"] = []
droidmon["file_accessed"]=set()
droidmon["fingerprint"]=set()
droidmon["registered_receivers"]=set()
droidmon["SharedPreferences"]=[]
droidmon["ContentResolver_queries"]=set()
droidmon["ContentValues"]=[]
droidmon["encoded_base64"]=[]
droidmon["decoded_base64"]=[]
droidmon["commands"]=set()
droidmon["ComponentEnabledSetting"]=[]
droidmon["data_leak"]=set()
droidmon["events"]=set()
droidmon["crypto_data"]=[]
droidmon["mac_data"]=[]
droidmon["handleReceiver"]=[]
droidmon["sms"]=[]
droidmon["killed_process"]=[]
droidmon["findResource"]=[]
droidmon["findLibrary"]=[]
droidmon["loadDex"]=set()
droidmon["TelephonyManager_listen"]=set()
droidmon["registerContentObserver"]=set()
droidmon["accounts"]=set()
droidmon["DexClassLoader"]=[]
droidmon["DexFile"]=[]
droidmon["PathClassLoader"]=[]
droidmon["loadClass"]=set()
droidmon["setMobileDataEnabled"]=set()
droidmon["httpConnections"]=[]
droidmon["error"]=[]
droidmon["raw"]=[]
def android_os_SystemProperties_get(api_call):
    droidmon["SystemProperties"].add(api_call["args"][0])
def javax_crypto_spec_SecretKeySpec_javax_crypto_spec_SecretKeySpec(api_call):
    key = api_call["args"][0]
    exists=False
    for current_key in droidmon["crypto_keys"]:
        if key in current_key["key"]:
            exists=True
            break
    if not exists :
        new_key={}
        new_key["key"]=api_call["args"][0]
        new_key["type"]=api_call["args"][1]
        droidmon["crypto_keys"].append(new_key)

def javax_crypto_Cipher_doFinal(api_call):
    if(api_call["this"]["mode"]== 1):
        droidmon["crypto_data"].append(api_call["args"][0])
    else:
        droidmon["crypto_data"].append(api_call["return"])
def java_lang_reflect_Method_invoke(api_call):
    reflection=""
    if("hooked_class" in api_call ):
        reflection=api_call["hooked_class"]+"->"+api_call["hooked_method"]
    else:
        reflection=api_call["hooked_method"]
    droidmon["reflection_calls"].add(reflection)
def dalvik_system_BaseDexClassLoader_findResource(api_call):
    lib_pairs(api_call,"findResource")
def android_app_Activity_startActivity(api_call):
    droidmon["started_activities"].append(api_call["args"][0])
def java_lang_Runtime_exec(api_call):
    command = api_call["args"][0]
    if type(command) is list:
        droidmon["commands"].add(' '.join(command))
    else:
        droidmon["commands"].add(command)
def java_lang_ProcessBuilder_start(api_call):
    command = api_call["this"]["command"]
    droidmon["commands"].add(' '.join(command))
def libcore_io_IoBridge_open(api_call):
    droidmon["file_accessed"].add(api_call["args"][0])
def android_app_ActivityThread_handleReceiver(api_call):
    droidmon["handleReceiver"].append(api_call["args"][0])
def android_app_ContextImpl_registerReceiver(api_call):
    for action in api_call["args"][1]["mActions"]:
        droidmon["registered_receivers"].add(action)
def android_telephony_TelephonyManager_getDeviceId(api_call):
    droidmon["fingerprint"].add("getDeviceId")
def android_telephony_TelephonyManager_getNetworkOperatorName(api_call):
    droidmon["fingerprint"].add("getNetworkOperatorName")
def android_telephony_TelephonyManager_getSubscriberId(api_call):
    droidmon["fingerprint"].add("getSubscriberId")
def android_telephony_TelephonyManager_getLine1Number(api_call):
    droidmon["fingerprint"].add("getLine1Number")
def android_telephony_TelephonyManager_getNetworkOperator(api_call):
    droidmon["fingerprint"].add("getNetworkOperator")
def android_telephony_TelephonyManager_getSimOperatorName(api_call):
    droidmon["fingerprint"].add("getSimOperatorName")
def android_telephony_TelephonyManager_getSimCountryIso(api_call):
    droidmon["fingerprint"].add("getSimCountryIso")
def android_telephony_TelephonyManager_getSimSerialNumber(api_call):
    droidmon["fingerprint"].add("getSimSerialNumber")
def android_telephony_TelephonyManager_getNetworkCountryIso(api_call):
    droidmon["fingerprint"].add("getNetworkCountryIso")
def android_telephony_TelephonyManager_getDeviceSoftwareVersion(api_call):
    droidmon["fingerprint"].add("getDeviceSoftwareVersion")
def android_net_wifi_WifiInfo_getMacAddress(api_call):
    droidmon["fingerprint"].add("getMacAddress")
def android_app_SharedPreferencesImpl_EditorImpl_putInt(api_call):
    droidmon["SharedPreferences"].append(get_pair(api_call))
def android_app_SharedPreferencesImpl_EditorImpl_putString(api_call):
    droidmon["SharedPreferences"].append(get_pair(api_call))
def android_app_SharedPreferencesImpl_EditorImpl_putFloat(api_call):
    droidmon["SharedPreferences"].append(get_pair(api_call))
def android_app_SharedPreferencesImpl_EditorImpl_putBoolean(api_call):
    droidmon["SharedPreferences"].append(get_pair(api_call))
def android_app_SharedPreferencesImpl_EditorImpl_putLong(api_call):
    droidmon["SharedPreferences"].append(get_pair(api_call))
def android_content_ContentResolver_query(api_call):
    droidmon["ContentResolver_queries"].add(api_call["args"][0]["uriString"])
def android_telephony_TelephonyManager_getSubscriberId(api_call):
    droidmon["fingerprint"].add("getSubscriberId")
def android_content_ContentValues_put(api_call):
    droidmon["ContentValues"].append(get_pair(api_call))
def android_telephony_TelephonyManager_getNetworkCountryIso(api_call):
    droidmon["fingerprint"].add("getNetworkCountryIso")
def javax_crypto_Mac_doFinal(api_call):
    droidmon["mac_data"].append(api_call["args"][0])
def android_util_Base64_encodeToString(api_call):
    droidmon["encoded_base64"].append(api_call["args"][0])
def android_util_Base64_encode(api_call):
    droidmon["encoded_base64"].append(api_call["return"][0])
def android_app_ApplicationPackageManager_setComponentEnabledSetting(api_call):
    new_pair={}
    component= api_call["args"][0]
    new_pair["component_name"]= component["mPackage"]+"/"+component["mClass"]
    new_state=api_call["args"][1]
    if (new_state in "2"):
        new_pair["component_new_state"] = "COMPONENT_ENABLED_STATE_DISABLED"
    elif (new_state in "1"):
        new_pair["component_new_state"] = "COMPONENT_ENABLED_STATE_ENABLED"
    elif (new_state in "0"):
        new_pair["component_new_state"] = "COMPONENT_ENABLED_STATE_DEFAULT"
    droidmon["ComponentEnabledSetting"].append(new_pair)
def android_location_Location_getLatitude(api_call):
    droidmon["data_leak"].add("location")
def android_location_Location_getLongitude(api_call):
    droidmon["data_leak"].add("location")
def android_app_ApplicationPackageManager_getInstalledPackages(api_call):
    droidmon["data_leak"].add("getInstalledPackages")
def dalvik_system_BaseDexClassLoader_findLibrary(api_call):
    lib_pairs(api_call,"findLibrary")
def android_telephony_SmsManager_sendTextMessage(api_call):
    new_pair={}
    new_pair["dest_number"]=api_call["args"][0]
    new_pair["content"]=' '.join(api_call["args"][1])
    droidmon["sms"].append(new_pair)
def android_util_Base64_decode(api_call):
    droidmon["decoded_base64"].append(api_call["return"])
def android_telephony_TelephonyManager_listen(api_call):
    event =  api_call["args"][1];
    listen_enent=""
    if event==16:
        listen_enent="LISTEN_CELL_LOCATION"
    elif event==256:
        listen_enent="LISTEN_SIGNAL_STRENGTHS"
    elif event==32:
        listen_enent="LISTEN_CALL_STATE"
    elif event==64:
        listen_enent="LISTEN_DATA_CONNECTION_STATE"
    elif event==1:
        listen_enent="LISTEN_SERVICE_STATE"
    if "" not in listen_enent:
        droidmon["TelephonyManager_listen"].add(listen_enent)
def android_content_ContentResolver_registerContentObserver(api_call):
    droidmon["registerContentObserver"].add(api_call["args"][0]["uriString"])
def android_content_ContentResolver_insert(api_call):
    droidmon["ContentResolver_queries"].add(api_call["args"][0]["uriString"])
def android_accounts_AccountManager_getAccountsByType(api_call):
    droidmon["accounts"].add(api_call["args"][0])
    droidmon["data_leak"].add("getAccounts")
def dalvik_system_BaseDexClassLoader_findResources(api_call):
    lib_pairs(api_call,"findResource")
def android_accounts_AccountManager_getAccounts(api_call):
   droidmon["data_leak"].add("getAccounts")
def android_telephony_SmsManager_sendMultipartTextMessage(api_call):
    new_pair={}
    new_pair["dest_number"]=api_call["args"][0]
    new_pair["content"]=api_call["args"][2]
    droidmon["sms"].append(new_pair)
def android_content_ContentResolver_delete(api_call):
    droidmon["ContentResolver_queries"].add(api_call["args"][0]["uriString"])
def android_media_AudioRecord_startRecording(api_call):
    droidmon["events"].add("mediaRecorder")
def android_media_MediaRecorder_start(api_call):
    droidmon["events"].add("mediaRecorder")
def android_content_BroadcastReceiver_abortBroadcast(api_call):
    droidmon["events"].add("abortBroadcast")
def dalvik_system_DexFile_loadDex(api_call):
    droidmon["loadDex"].add(api_call["args"][0])
def dalvik_system_DexClass_dalvik_system_DexClassLoader(api_call):
   droidmon["DexClassLoader"].append(api_call["args"])
def dalvik_system_DexFile_dalvik_system_DexFile(api_call):
   droidmon["DexFile"].append(api_call["args"])
def dalvik_system_PathClassLoader_dalvik_system_PathClassLoader(api_call):
    droidmon["PathClassLoader"].append(api_call["args"])
def android_app_ActivityManager_killBackgroundProcesses(api_call):
    droidmon["killed_process"].append(api_call["args"][0])
def android_os_Process_killProcess(api_call):
    droidmon["killed_process"].append(api_call["args"][0])

def android_net_ConnectivityManager_setMobileDataEnabled(api_call):
    droidmon["setMobileDataEnabled"].append(api_call["args"][0])
def org_apache_http_impl_client_AbstractHttpClient_execute(api_call):
    json = {}
    if type(api_call["args"][0]) is dict:
        json["request"]=api_call["args"][1]
    else:
        json["request"]=api_call["args"][0]
    json["response"]=api_call["return"]
    droidmon["httpConnections"].append(json)
def java_net_URL_openConnection(api_call):
    json = {}
    json["request"]=api_call["this"]
    json["response"]=api_call["return"]
    if("file:" in api_call["this"] or "jar:" in api_call["this"]):
        return
    droidmon["httpConnections"].append(json)
def dalvik_system_DexFile_loadClass(api_call):
    droidmon["loadClass"].add(api_call["args"][0])
def get_pair(api_call):
    new_pair={}
    new_pair["key"]=api_call["args"][0]
    if(api_call["args"].__len__()>1):
        new_pair["value"]=api_call["args"][1]
    return new_pair
def lib_pairs(api_call,key):
    libname=api_call["args"][0]
    exists=False
    for current_key in droidmon[key]:
        if libname in current_key["libname"]:
            exists=True
            break
    if not exists :
        new_pair={}
        new_pair["libname"]=api_call["args"][0]
        if "return" in api_call:
            new_pair["result"]=api_call["return"]
        else:
            new_pair["result"]=""
        droidmon[key].append(new_pair)
def keyCleaner(d):
    if type(d) is dict:
        for key, value in d.iteritems():
            d[key] = keyCleaner(value)
            if '.' in key:
                d[key.replace('.', '_')] = value
                del(d[key])
        return d
    if type(d) is list:
        return map(keyCleaner, d)
    if type(d) is tuple:
        return tuple(map(keyCleaner, d))
    return d
results={}
key = "droidmon"
log_path="droidmon.log"
try :
    with open(log_path) as log_file:
        for line in log_file:
            try:
                api_call =json.loads(line)
                droidmon["raw"].append(keyCleaner(api_call))
                call = api_call["class"]+"_"+api_call["method"]
                call = call.replace(".","_")
                call = call.replace("$","_")
                try:
                    func = getattr( call)
                    func(api_call)
                except Exception as e:
                    droidmon["error"].append(e.message+" "+line)
            except Exception as e:
                print e.message
except Exception as e:
    print e.message
for key in droidmon.keys():
    if len(droidmon[key]) > 0:
        if type(droidmon[key]) is list:
            results[key]=droidmon[key]
        else:
            results[key]=list(droidmon[key])
#return results

for x in results:
    if str(x)=='error':
        pass
    else:
        print str(x) + "\n\n        "#+ str(results[x])