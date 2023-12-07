/* Description: Show contents of NSUserDefaults
 * Mode: S+A
 * Version: 1.0
 * Credit: Objection (https://github.com/sensepost/objection/blob/master/objection/commands/ios/nsuserdefaults.py) & https://github.com/interference-security/frida-scripts/blob/master/iOS
 * Author: @interference-security
 */
//Credit: Objection (https://github.com/sensepost/objection/blob/master/objection/commands/ios/nsuserdefaults.py)
//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security

function convertNsDictionaryToJson(nsDict) {
    let jsDict = {};
    let keys = nsDict.allKeys();
    let keyCount = keys.count();
    for (var i = 0; i < keyCount; i++) {
        let key = keys.objectAtIndex_(i);
        let value = new ObjC.Object(nsDict.objectForKey_(key));
        jsDict[key] = String(value); // convert everything to a JavaScript String representation
    }
    return jsDict;
}

function ns_userdefaults() {
    send("Dumping NSUserDefaults Data");
    var NSUserDefaults = ObjC.classes.NSUserDefaults;
    var NSDictionary = NSUserDefaults.alloc().init().dictionaryRepresentation();
    send(JSON.stringify({'[MBSFDUMP] nsuserdefaults': convertNsDictionaryToJson(NSDictionary)}));
}

try{
    setTimeout(() => {
        ns_userdefaults();
    }, 2000);
   
} catch(err) {}