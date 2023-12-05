// Source: https://github.com/apkunpacker/FridaScripts
console.warn(Process.arch, "environment Detected")
let do_dlopen = null;
let call_ctor = null;
let LibraryName = "libflutter.so";
let moduleName = Process.arch == "arm" ? "linker" : "linker64";
let reg = Process.arch == "arm" ? "r0" : "x0";
let Arch = Process.arch;
Process.findModuleByName(moduleName)
    .enumerateSymbols()
    .forEach(function(sym) {
    if (sym.name.indexOf('do_dlopen') !== -1) {
        do_dlopen = sym.address;
    } else if (sym.name.indexOf('call_constructor') !== -1) {
        call_ctor = sym.address;
    }
})
Interceptor.attach(do_dlopen, function() {
    let Lib = this.context[reg].readCString();
    if (Lib && Lib.indexOf(LibraryName) !== -1) {
        Interceptor.attach(call_ctor, function() {
            Hook(LibraryName);
        })
    }
})

function Hook(Name) {
    let Hooked = 0;
    let Mod = Process.findModuleByName(Name);
    let Arm64Pattern = [
        "F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9",
        "F? 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 13 00 40 F9 F4 03 00 AA 68 1A 40 F9",
        "FF 43 01 D1 FE 67 01 A9 ?? ?? 06 94 ?? 7? 06 94 68 1A 40 F9 15 15 41 F9 B5 00 00 B4 B6 4A 40 F9"];
        //"FF C3 01 D1 F? 7B 01 A9 FC 6F 02 A9 FA 67 03 A9 F8 5F 04 A9 F6 57 05 ?9"]          
    let ArmPattern = ["2D E9 F? 4? D0 F8 00 80 81 46 D8 F8 18 00 D0 F8 ??"];
    let ranges = Mod.enumerateRanges('r-x');
    ranges.forEach(range => {
        if (Arch == "arm64") {
            Arm64Pattern.forEach(pattern => {
                Memory.scan(range.base, range.size, pattern, {
                    onMatch: function(address, size) {                      
                        if (Hooked == 0) {
                            Hooked = 1;
                            hook_ssl_verify_peer_cert(address, address.sub(Mod.base), Name);
                        }
                    }
                });
            });
        } else if (Arch == "arm") {
            ArmPattern.forEach(pattern => {
                Memory.scan(range.base, range.size, pattern, {
                    onMatch: function(address, size) {
                        if (Hooked == 0) {
                            Hooked = 1;
                            hook_ssl_verify_peer_cert(address, address.sub(Mod.base), Name);
                        }
                    }
                });
            });
        } 
    });
}

function hook_ssl_verify_peer_cert(address, offset, Name) {
    console.log("ssl_verify_peer_cert Patched at : ", Name, address, offset)
    try {
        Interceptor.replace(address, new NativeCallback((pathPtr, flags) => {
            return 0;
        }, 'int', ['pointer', 'int']));
    } catch (e) {}
}
