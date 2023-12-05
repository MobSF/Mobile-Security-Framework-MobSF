/* 
    Description: Android Emulator Detection Bypass frida script
    Credit: @Areizen_

    Useful when bypassing USB debugging detection on Android!
    If it doesn't work, remove the conditional statement 

    Src: https://github.com/rsenet/FriList/blob/main/02_SecurityBypass/DebugMode_Emulator/android-emulator-detection-bypass.js
    Link:
        https://developer.android.com/reference/android/os/Build.VERSION
*/

Java.perform(function() 
{
    console.log("--> Anti Emulator Detection Bypass (aka BluePill) - Script Loaded")
    /***********************************************************
      *** IMPORTANT ***
      uncomment instructions below to skip one or more bypasses 
    /***********************************************************/
    bypass_build_properties()
    bypass_phonenumber()
    bypass_deviceid()
    bypass_imsi()
    bypass_operator_name()
    bypass_sim_operator_name()
    bypass_has_file()
    bypass_processbuilder()
    bypass_system_properties()
});


function replaceFinaleField(object, fieldName, value)
{
    var field =  object.class.getDeclaredField(fieldName)
    field.setAccessible(true)
    field.set(null, value)
}

function bypass_build_properties()
{        
        console.log("Build Properties - Bypass Loaded")
        // Class containing const that we want to modify
        const Build = Java.use("android.os.Build")

        // reflection class for changing const
        const Field = Java.use('java.lang.reflect.Field')
        const Class = Java.use('java.lang.Class')

        // Replacing Build static fields
        replaceFinaleField(Build, "FINGERPRINT", "abcd/C1505:4.1.1/11.3.A.2.13:user/release-keys")
        replaceFinaleField(Build, "MODEL", "C1505")
        replaceFinaleField(Build, "MANUFACTURER", "Sony")
        replaceFinaleField(Build, "BRAND", "Xperia")
        replaceFinaleField(Build, "BOARD", "7x27")
        replaceFinaleField(Build, "ID", "11.3.A.2.13")
        replaceFinaleField(Build, "SERIAL", "abcdef123")
        replaceFinaleField(Build, "TAGS", "release-keys")
        replaceFinaleField(Build, "USER", "administrator")
}

function bypass_phonenumber()
{   
    console.log("Phone Number - Bypass Loaded")
    const TelephonyManager = Java.use('android.telephony.TelephonyManager')

    TelephonyManager.getLine1Number.overload().implementation = function()
    {
        console.log("Phone number - bypass done!")
        return "060102030405"
    }
}

function bypass_deviceid()
{
    console.log("Device ID - Bypass Loaded")
    const TelephonyManager = Java.use('android.telephony.TelephonyManager')

    TelephonyManager.getDeviceId.overload().implementation = function()
    {
        console.log("Device ID - bypass done!")
        return "012343545456445"
    }
}

function bypass_imsi()
{
    console.log("IMSI - Bypass Loaded")
    const TelephonyManager = Java.use('android.telephony.TelephonyManager')

    TelephonyManager.getSubscriberId.overload().implementation = function()
    {
        console.log("Device ID (getSubscriberId) - bypass done!")
        return "310260000000111"
    }
}

function bypass_operator_name()
{
    console.log("Operator Name - Bypass Loaded")
    const TelephonyManager = Java.use('android.telephony.TelephonyManager')

    TelephonyManager.getNetworkOperatorName.overload().implementation = function()
    {
        console.log("Operator Name - bypass done!")
        return "not"
    }
}

function bypass_sim_operator_name()
{
    console.log("SIM Operator Name - Bypass Loaded")
    const TelephonyManager = Java.use('android.telephony.TelephonyManager')

    TelephonyManager.getSimOperatorName.overload().implementation = function()
    {
        console.log("SIM Operator Name - bypass done!")
        return "not"
    }
}

function bypass_has_file()
{
    console.log("Emulator related files check - Bypass Loaded")
    const File = Java.use("java.io.File")
    const KnownFiles= [
        "ueventd.android_x86.rc",
        "x86.prop",
        "ueventd.ttVM_x86.rc",
         "init.ttVM_x86.rc",
        "fstab.ttVM_x86",
        "fstab.vbox86",
        "init.vbox86.rc",
        "ueventd.vbox86.rc",
        "/dev/socket/qemud",
        "/dev/qemu_pipe",
        "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace",
        "/system/bin/qemu-props",
        "/dev/socket/genyd",
        "/dev/socket/baseband_genyd",
        "/proc/tty/drivers",
        "/proc/cpuinfo"
    ]
   
    File.exists.implementation = function () 
    {
        var x = this.getAbsolutePath();
        for(var i=0; i<KnownFiles.length; i++)
        {
            if(KnownFiles[i] == x)
            {
                console.log("App was looking for "+x+" emulator file - bypass done!")
                return false;
            }
        }
  
        return this.exists();
    };
}

function bypass_processbuilder()
{
    console.log("ProcessBuilder - Bypass Loaded")
    var ProcessBuilder = Java.use('java.lang.ProcessBuilder');

    ProcessBuilder.$init.overload('[Ljava.lang.String;').implementation = function(x)
    {
        console.log("ProcessBuilder - bypass done!")
        return null
    }
}


function bypass_system_properties() 
{
    /*
    * Function used to bypass common checks to
    * Android OS properties
    * Bypass the props checking from this git : https://github.com/strazzere/anti-emulator
    *
    */
    console.log("System Properties - Bypass Loaded")
    const SystemProperties = Java.use('android.os.SystemProperties')
    const Properties = 
    {
        "init.svc.qemud": null,
        "init.svc.qemu-props": null,
        "qemu.hw.mainkeys": null,
        "qemu.sf.fake_camera": null,
        "qemu.sf.lcd_density": null,
        "ro.bootloader": "xxxxx",
        "ro.bootmode": "xxxxxx",
        "ro.hardware": "xxxxxx",
        "ro.kernel.android.qemud": null,
        "ro.kernel.qemu.gles": null,
        "ro.kernel.qemu": "xxxxxx",
        "ro.product.device": "xxxxx",
        "ro.product.model": "xxxxxx",
        "ro.product.name": "xxxxxx",
        "ro.serialno": null
    }

    SystemProperties.get.overload('java.lang.String').implementation = function(x)
    {
        if (x in Properties)
        {
            console.log("App is looking for "+x+". Output replaced with "+Properties[x]+" - bypass done!")
            return Properties[x]
        }

        return this.get(x)
    }
}