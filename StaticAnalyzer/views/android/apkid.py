import ast
import subprocess
# Esteve 14.08.2016 - begin - Pirated and Malicious App Detection with APKiD 
def APKiD(APP_FILE,APP_DIR,TOOLS_DIR,APP_NAME):
    try:
        print "[INFO] Detecting Packers, Obfuscators, Compilers, and other stuff with APKiD"
        RET=''
        apkid=TOOLS_DIR+'apkid'
        args=[apkid,'-j',APP_DIR+APP_FILE]
        dat=ast.literal_eval(subprocess.check_output(args))
        for key1, value1 in dat.items():
            if key1.find('!') == -1:
                file=APP_NAME
            else:
                file=key1.split('!')[1]
            for key2, value2 in value1.items():
                concept=key2
                for item3 in value2:
                    item=item3
                    detection = False
                    if concept == 'compiler' and item == 'Android SDK (dx)':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been compiled using the <strong>'+item3+'</strong> compiler.</td><td><span class="label label-info">info</span></td><td> The file has been compiled using the standard Android SDK compiler.</td></tr>'
                        detection = True
                    if concept == 'compiler' and item == 'Android SDK (dexmerge)':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been compiled using the <strong>'+item3+'</strong> compiler.</td><td><span class="label label-info">info</span></td><td> The file has been compiled using dexmerge, which is used for incremental builds by some IDEs (after using dx).</td></tr>'                 
                        detection = True
                    if concept == 'compiler' and (item == 'dexlib 1.x' or item == 'dexlib 2.x' or item == 'dexlib 2.x beta'):
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been compiled using the <strong>'+item3+'</strong> compiler.</td><td><span class="label label-danger">high</span></td><td> The file has been compiled using one of the dexlib families. This is an indicator of potential crack or malware injection.</td></tr>'
                        detection = True
                    if concept == 'obfuscator' and item == 'DexGuard':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been obfuscated using the <strong>'+item3+'</strong> obfuscator.</td><td><span class="label label-warning">medium</span></td><td> The file has been obfuscated. Developers sometimes use obfuscation. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'obfuscator' and item == 'DexProtect':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been obfuscated using the <strong>'+item3+'</strong> obfuscator.</td><td><span class="label label-warning">medium</span></td><td> The file has been obfuscated. Developers sometimes use obfuscation. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'obfuscator' and item == 'Bitwise AntiSkid':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been obfuscated using the <strong>'+item3+'</strong> obfuscator.</td><td><span class="label label-warning">medium</span></td><td> The file has been obfuscated. Developers sometimes use obfuscation. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'APKProtect':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been protected using the <strong>'+item3+'</strong> protector.</td><td><span class="label label-warning">medium</span></td><td> The file has been protected. Developers sometimes use protection. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'Bangcle':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed using the <strong>'+item3+'</strong> packer.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'Kiro':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed using the <strong>'+item3+'</strong> packer.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'Qihoo 360':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed using the <strong>'+item3+'</strong> packer.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'Jiagu':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed using the <strong>'+item3+'</strong> packer.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == '\'qdbh\'(?)':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed using the <strong>'+item3+'</strong> packer.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == '\'jpj\'packer(?)':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed using the <strong>'+item3+'</strong> packer.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'Unicom SDK Loader':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed using the <strong>'+item3+'</strong> packer.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'LIAPP':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed using the <strong>'+item3+'</strong> packer.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'APP Fortify':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed using the <strong>'+item3+'</strong> packer.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'NQ Shield':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed using the <strong>'+item3+'</strong> packer.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'Tencent':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed using the <strong>'+item3+'</strong> packer.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'Ijiami':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed using the <strong>'+item3+'</strong> packer.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'Naga':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed using the <strong>'+item3+'</strong> packer.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'Alibaba':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed using the <strong>'+item3+'</strong> packer.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'Medusa':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed using the <strong>'+item3+'</strong> packer.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'Baidu':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed using the <strong>'+item3+'</strong> packer.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'apk':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> looks like a common APK. <strong>'+item3+'</strong>.</td><td><span class="label label-info">info</span></td><td> The file looks like a common APK that is likely not corrupt.</td></tr>'
                        detection = True
                    if concept == 'signed_apk':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> looks like a common APK. <strong>'+item3+'</strong>.</td><td><span class="label label-info">info</span></td><td> The file looks like a common APK that is signed and likely not corrupt.</td></tr>'
                        detection = True
                    if concept == 'unsigned_apk':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> looks like a common APK. <strong>'+item3+'</strong>.</td><td><span class="label label-info">info</span></td><td> The file looks like a common APK that is not signed and likely not corrupt.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'Contains a UPX ARM stub':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed. <strong>'+item3+'</strong>.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'Contains a UPX stub':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed. <strong>'+item3+'</strong>.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'Contains an unmodified UPX stub':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed. <strong>'+item3+'</strong>.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'sharelib UPX':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed: <strong>'+item3+'</strong>.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'UPX 3.92 (unmodified)':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed. <strong>'+item3+'</strong>.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'UPX 3.09 (unmodified)':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed. <strong>'+item3+'</strong>.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'UPX 3.08 (unmodified)':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed. <strong>'+item3+'</strong>.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'UPX 3.07 (unmodified)':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed. <strong>'+item3+'</strong>.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'UPX 3.04 (unmodified)':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed. <strong>'+item3+'</strong>.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'UPX 3.03 (unmodified)':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed. <strong>'+item3+'</strong>.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'UPX 3.02 (unmodified)':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed. <strong>'+item3+'</strong>.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'UPX 3.01 (unmodified)':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed. <strong>'+item3+'</strong>.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'Bangcle/SecNeo (UPX)':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed. <strong>'+item3+'</strong>.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'newer-style Bangcle/SecNeo (UPX)':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed. <strong>'+item3+'</strong>.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'Ijiami (UPX)':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed. <strong>'+item3+'</strong>.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'UPX (unknown)':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed. <strong>'+item3+'</strong>.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer dropper' and item == 'UPX packed ELF embedded in ELF':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed. <strong>'+item3+'</strong>.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'UPX (unknown, modified)':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed. <strong>'+item3+'</strong>.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer embedded' and item == 'UPX packed ELF embedded in APK':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed. <strong>'+item3+'</strong>.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'packer' and item == 'UPX (unknown, unmodified)':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has been packed. <strong>'+item3+'</strong>.</td><td><span class="label label-warning">medium</span></td><td> The file has been packed. Developers sometimes use packing. However, this is also a technique used by malware to hide its internals.</td></tr>'
                        detection = True
                    if concept == 'abnormal' and item == 'non-standard header size':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has a <strong>'+item3+'</strong>.</td><td><span class="label label-danger">high</span></td><td> The file has an abnormal header size. Data might have been hidden after the normal header data. This is a weird characteristic which points to potential malware activity. </td></tr>'
                        detection = True
                    if concept == 'abnormal anti_disassembly' and item == 'non-zero link size':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has a <strong>'+item3+'</strong>.</td><td><span class="label label-warning">medium</span></td><td> The file has an abnormmal link section. This is a weird characteristic. It might have been used as an anti-decompiler technique. </td></tr>'
                        detection = True
                    if concept == 'abnormal anti_disassembly' and item == 'non-zero link offset':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has a <strong>'+item3+'</strong>.</td><td><span class="label label-warning">medium</span></td><td> The file has an abnormmal link section. This is a weird characteristic. It might have been used as an anti-decompiler technique. </td></tr>'
                        detection = True
                    if concept == 'abnormal' and item == 'non little-endian format':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has a <strong>'+item3+'</strong>.</td><td><span class="label label-warning">medium</span></td><td> The file has an abnormmal endian magic. This is a weird characteristic. It should not run on any Android device. </td></tr>'
                        detection = True
                    if concept == 'abnormal' and item == 'injected data after map section':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has <strong>'+item3+'</strong>.</td><td><span class="label label-danger">high</span></td><td> The file has data injected after the map section. This is a weird characteristic which points to potential malware activity. </td></tr>'
                        detection = True
                    if concept == 'anti_disassembly' and item == 'illegal class name':
                        RET=RET +'<tr><td>File <strong>'+file+'</strong> has <strong>'+item3+'s.</strong></td><td><span class="label label-warning">medium</span></td><td> The file has illegal class names. This is a weird characteristic. It might have been used as an anti-decompiler technique. </td></tr>'
                        detection = True
                    if detection == False:
                        print "[INFO] A Yara rule has not been detected. Please, report this fact so that it can be included. The concerned file is \"%s\", the rule category is \"%s\", and the meta description is \"%s\"." %(file,concept,item3)
        return RET
    except:
        PrintException("[ERROR] Detecting Packers, Obfuscators, Compilers, and other stuff with APKiD")
# Esteve 14.08.2016 - end - Pirated and Malicious App Detection with APKiD 
