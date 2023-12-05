/* 
    Description: Android ADB Detection Bypass frida script
    Credit: meerkati

    Useful when bypassing USB debugging detection on Android!
    If it doesn't work, remove the conditional statement 

    Src: https://github.com/rsenet/FriList/blob/main/02_SecurityBypass/DebugMode_Emulator/android-adb-detection-bypass.js
    Link:
        https://developer.android.com/reference/android/os/Build.VERSION
*/

setTimeout(function() 
{
    Java.perform(function() 
    {
        var androidSettings = ['adb_enabled'];
        var sdkVersion = Java.use('android.os.Build$VERSION');
        console.log("SDK Version : " + sdkVersion.SDK_INT.value);

        /* API 16 or lower Settings.Global Hook */
        if (sdkVersion.SDK_INT.value <= 16)
        {
            var settingSecure = Java.use('android.provider.Settings$Secure');

            settingSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) 
            {
                //console.log("[*]settingSecure.getInt(cr,name) : " + name);
                if (name == androidSettings[0]) 
                {
                    console.log('[+]Secure.getInt(cr, name) Bypassed');
                    return 0;
                }
                var ret = this.getInt(cr, name);
                return ret;
            }

            settingSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, def) 
            {
                //console.log("[*]settingSecure.getInt(cr,name,def) : " + name);
                if (name == (androidSettings[0])) 
                {
                    console.log('[+]Secure.getInt(cr, name, def) Bypassed');
                    return 0;
                }
                var ret = this.getInt(cr, name, def);
                return ret;
            }

            settingSecure.getFloat.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) 
            {
                //console.log("[*]settingSecure.getFloat(cr,name) : " + name);
                if (name == androidSettings[0]) 
                {
                    console.log('[+]Secure.getFloat(cr, name) Bypassed');
                    return 0;
                }
                var ret = this.getFloat(cr, name)
                return ret;
            }

            settingSecure.getFloat.overload('android.content.ContentResolver', 'java.lang.String', 'float').implementation = function(cr, name, def)
            {
                //console.log("[*]settingSecure.getFloat(cr,name,def) : " + name);
                if (name == androidSettings[0]) 
                {
                    console.log('[+]Secure.getFloat(cr, name, def) Bypassed');
                    return 0;
                }
                var ret = this.getFloat(cr, name, def);
                return ret;
            }

            settingSecure.getLong.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) 
            {
                //console.log("[*]settingSecure.getLong(cr,name) : " + name);
                if (name == androidSettings[0]) 
                {
                    console.log('[+]Secure.getLong(cr, name) Bypassed');
                    return 0;
                }
                var ret = this.getLong(cr, name)
                return ret;
            }

            settingSecure.getLong.overload('android.content.ContentResolver', 'java.lang.String', 'long').implementation = function(cr, name, def) 
            {
                //console.log("[*]settingSecure.getLong(cr,name,def) : " + name);
                if (name == androidSettings[0]) 
                {
                    console.log('[+]Secure.getLong(cr, name, def) Bypassed');
                    return 0;
                }
                var ret = this.getLong(cr, name, def);
                return ret;
            }

            settingSecure.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) 
            {
                //console.log("[*]settingSecure.getString(cr,name) : " + name);
                if (name == androidSettings[0]) 
                {
                    var stringClass = Java.use("java.lang.String");
                    var stringInstance = stringClass.$new("0");

                    console.log('[+]Secure.getString(cr, name) Bypassed');
                    return stringInstance;
                }
                var ret = this.getString(cr, name);
                return ret;
            }
        }

        /* API 17 or higher Settings.Global Hook */
        if (sdkVersion.SDK_INT.value >= 17) 
        {
            var settingGlobal = Java.use('android.provider.Settings$Global');

            settingGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) 
            {
                //console.log("[*]settingGlobal.getInt(cr,name) : " + name);
                if (name == androidSettings[0]) 
                {
                    console.log('[+]Global.getInt(cr, name) Bypassed');
                    return 0;
                }
                var ret = this.getInt(cr, name);
                return ret;
            }

            settingGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, def) 
            {
                //console.log("[*]settingGlobal.getInt(cr,name,def) : " + name);
                if (name == (androidSettings[0])) 
                {
                    console.log('[+]Global.getInt(cr, name, def) Bypassed');
                    return 0;
                }
                var ret = this.getInt(cr, name, def);
                return ret;
            }

            settingGlobal.getFloat.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) 
            {
                //console.log("[*]settingGlobal.getFloat(cr,name) : " + name);
                if (name == androidSettings[0]) 
                {
                    console.log('[+]Global.getFloat(cr, name) Bypassed');
                    return 0;
                }
                var ret = this.getFloat(cr, name);
                return ret;
            }

            settingGlobal.getFloat.overload('android.content.ContentResolver', 'java.lang.String', 'float').implementation = function(cr, name, def) 
            {
                //console.log("[*]settingGlobal.getFloat(cr,name,def) : " + name);
                if (name == androidSettings[0])
                {
                    console.log('[+]Global.getFloat(cr, name, def) Bypassed');
                    return 0;
                }
                var ret = this.getFloat(cr, name, def);
                return ret;
            }

            settingGlobal.getLong.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) 
            {
                //console.log("[*]settingGlobal.getLong(cr,name) : " + name);
                if (name == androidSettings[0]) 
                {
                    console.log('[+]Global.getLong(cr, name) Bypassed');
                    return 0;
                }
                var ret = this.getLong(cr, name);
                return ret;
            }

            settingGlobal.getLong.overload('android.content.ContentResolver', 'java.lang.String', 'long').implementation = function(cr, name, def) 
            {
                //console.log("[*]settingGlobal.getLong(cr,name,def) : " + name);
                if (name == androidSettings[0]) 
                {
                    console.log('[+]Global.getLong(cr, name, def) Bypassed');
                    return 0;
                }
                var ret = this.getLong(cr, name, def);
                return ret;
            }

            settingGlobal.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) 
            {
                //console.log("[*]settingGlobal.getString(cr,name) : " + name);
                if (name == androidSettings[0]) 
                {
                    var stringClass = Java.use("java.lang.String");
                    var stringInstance = stringClass.$new("0");

                    console.log('[+]Global.getString(cr, name) Bypassed');
                    return stringInstance;
                }
                var ret = this.getString(cr, name);
                return ret;
            }
        }
    });
}, 0);