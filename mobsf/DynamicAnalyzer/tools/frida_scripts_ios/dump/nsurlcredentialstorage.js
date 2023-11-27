// Dumps contents of NSURLCredentialStorage for all protection spaces
// Based on https://github.com/sensepost/objection/blob/f8e78d8a29574c6dadd2b953a63207b45a19b1cf/objection/hooks/ios/keychain/dump.js#L3
function dumpNSURLCredentialStorage () {
    send('Dumping Credentials from NSURLCredentialStorage')
    var data = [];
    var credentialstorage = [];
    var credentialsDict = ObjC.classes.NSURLCredentialStorage.sharedCredentialStorage().allCredentials();

    if (credentialsDict.count() <= 0) {
        return data;
    }

    const protectionSpaceEnumerator = credentialsDict.keyEnumerator();
    let urlProtectionSpace;

    while ((urlProtectionSpace = protectionSpaceEnumerator.nextObject()) !== null) {

        const userNameEnumerator = credentialsDict.objectForKey_(urlProtectionSpace).keyEnumerator();
        let userName;
        while ((userName = userNameEnumerator.nextObject()) !== null) {

            var creds = credentialsDict.objectForKey_(urlProtectionSpace).objectForKey_(userName);
            credentialstorage.push({
                host: urlProtectionSpace.host().toString(),
                authenticationMethod: urlProtectionSpace.authenticationMethod().toString(),
                protocol: urlProtectionSpace.protocol().toString(),
                port: urlProtectionSpace.port(),
                user: creds.user().toString(),
                password: creds.password().toString()
            
            })
        }
    }
    send(JSON.stringify({'[MBSFDUMP] credentialstorage': credentialstorage}));
}

try {
    dumpNSURLCredentialStorage();
} catch(err) {}