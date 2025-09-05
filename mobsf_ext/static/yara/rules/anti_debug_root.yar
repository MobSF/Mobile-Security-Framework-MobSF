rule ANDROID_AntiDebug_Root_Strings {
  meta:
    description = "Root/Anti-debug/frida indicators"
  strings:
    $su1 = "/system/xbin/su"
    $su2 = "/system/bin/su"
    $superuser = "Superuser.apk"
    $testkeys = "test-keys"
    $frida1 = "frida"
    $frida2 = "gum-js-loop"
    $ptrace = "android.os.Debug"
    $dbg1 = "isDebuggerConnected"
  condition:
    any of ($su*) or $superuser or $testkeys or any of ($frida*) or $ptrace or $dbg1
}