var paths = [
    "/Applications/blackra1n.app",
    "/Applications/Cydia.app",
    "/Applications/FakeCarrier.app",
    "/Applications/Icy.app",
    "/Applications/IntelliScreen.app",
    "/Applications/MxTube.app",
    "/Applications/RockApp.app",
    "/Applications/SBSetttings.app",
    "/Applications/WinterBoard.app",
    "/bin/bash",
    "/bin/sh",
    "/bin/su",
    "/etc/apt",
    "/etc/ssh/sshd_config",
    "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
    "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/pguntether",
    "/private/var/lib/cydia",
    "/private/var/mobile/Library/SBSettings/Themes",
    "/private/var/stash",
    "/private/var/tmp/cydia.log",
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/usr/bin/cycript",
    "/usr/bin/ssh",
    "/usr/bin/sshd",
    "/usr/libexec/sftp-server",
    "/usr/libexec/ssh-keysign",
    "/usr/sbin/frida-server",
    "/usr/sbin/sshd",
    "/var/cache/apt",
    "/var/lib/cydia",
    "/var/log/syslog",
    "/var/mobile/Media/.evasi0n7_installed",
    "/var/tmp/cydia.log",
    "/etc/apt",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/Applications/Cydia.app",
    "/Applications/blackra1n.app",
    "/Applications/FakeCarrier.app",
    "/Applications/Icy.app",
    "/Applications/IntelliScreen.app",
    "/Applications/MxTube.app",
    "/Applications/RockApp.app",
    "/Applications/SBSetttings.app",
    "/private/var/lib/apt/",
    "/Applications/WinterBoard.app",
    "/usr/sbin/sshd",
    "/private/var/tmp/cydia.log",
    "/usr/binsshd",
    "/usr/libexec/sftp-server",
    "/Systetem/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/System/Library/LaunchDaemons/com.saurik.Cy@dia.Startup.plist",
    "/var/log/syslog",
    "/bin/bash",
    "/bin/sh",
    "/etc/ssh/sshd_config",
    "/usr/libexec/ssh-keysign",
    "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/private/var/stash",
    "/usr/bin/cycript",
    "/usr/bin/ssh",
    "/usr/bin/sshd",
    "/var/cache/apt",
    "/var/lib/cydia",
    "/var/tmp/cydia.log",
    "/Applications/SBSettings.app",
    "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/mobile/Library/SBSettings/Themes",
    "/var/lib/apt",
    "/private/jailbreak.txt",
    "/bin/su",
    "/pguntether",
    "/usr/sbin/frida-server",
    "/private/Jailbreaktest.txt",
    "/var/mobile/Media/.evasi0n7_installed",
    "cydia://package/com.example.package"
];

function bypassJailbreakDetection2() {
try {
    
        var resolver = new ApiResolver('objc');

        resolver.enumerateMatches('*[* *jail**]', {
            onMatch: function(match) {
                var ptr = match["address"];
                Interceptor.attach(ptr, {
                    onEnter: function() {},
                    onLeave: function(retval) {
                        retval.replace(0x0);
                    }
                });
            },
            onComplete: function() {}
        });

        resolver.enumerateMatches('*[* fileExistsAtPath*]', {
            onMatch: function(match) {
                var ptr = match["address"];
                Interceptor.attach(ptr, {
                    onEnter: function(args) {
                        var path = ObjC.Object(args[2]).toString();
                        this.jailbreakCall = false;
                        for (var i = 0; i < paths.length; i++) {
                            if (paths[i] == path) {
                                this.jailbreakCall = true;
                            }
                        }
                    },
                    onLeave: function(retval) {
                        if (this.jailbreakCall) {
                            retval.replace(0x0);
                        }
                    }
                });
            },
            onComplete: function() {}
        });

        resolver.enumerateMatches('*[* canOpenURL*]', {
            onMatch: function(match) {
                var ptr = match["address"];
                Interceptor.attach(ptr, {
                    onEnter: function(args) {
                        var url = ObjC.Object(args[2]).toString();
                        this.jailbreakCall = false;
                        if (url.indexOf("cydia") >= 0) {
                            this.jailbreakCall = true;
                        }
                    },
                    onLeave: function(retval) {
                        if (this.jailbreakCall) {
                            retval.replace(0x0);
                        }
                    }
                });
            },
            onComplete: function() {}
        });
        send("[Jailbreak Detection Bypass 2] success");
    }
    catch(e) {
        send('[Jailbreak Detection Bypass 2] script error:' + e.toString());
    }
}


try {
    if (ObjC.available) {
        bypassJailbreakDetection2();
    } else {
        send('[Jailbreak Detection Bypass 2] error: Objective-C Runtime is not available!');
    }
} catch(err) {}
