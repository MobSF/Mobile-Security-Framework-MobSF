var SSLPinningBypass = [{
    // https://codeshare.frida.re/@akabe1/frida-universal-pinning-bypasser/
    class: 'com.android.org.conscrypt.OpenSSLSocketImpl',
    method: 'verifyCertificateChain',
    func: function (g, i) { send('[SSL Pinning Bypass] OpenSSLSocketImpl.verifyCertificateChain() bypassed'); }
}, {
    class: 'nl.xservices.plugins.SSLCertificateChecker',
    method: 'execute',
    arg_list: ["java.lang.String", "org.json.JSONArray", "org.apache.cordova.CallbackContext"],
    func: function (action, args, callbackContext) { send('[SSL Pinning Bypass] Apache Cordova - SSLCertificateChecker.execute() bypassed'); callbackContext.success("CONNECTION_SECURE"); return; }
}, {
    class: 'appcelerator.https.PinningTrustManager',
    method: 'checkServerTrusted',
    func: function () { send("[SSL Pinning Bypass]  Appcelerator Titanium - appcelerator.https.PinningTrustManager.checkServerTrusted() bypassed"); }
}, {
    class: 'okhttp3.CertificatePinner',
    method: 'check',
    arg_list: ['java.lang.String', 'java.util.List'],
    func: function () { send("[SSL Pinning Bypass] OkHTTP 3.x okhttp3.CertificatePinner.check() bypassed"); }
}, {
    // https://android.googlesource.com/platform/external/okhttp/+/a2cab72/okhttp/src/main/java/com/squareup/okhttp/CertificatePinner.java#122
    class: 'com.squareup.okhttp.CertificatePinner',
    method: 'check',
    arg_list: ['java.lang.String', 'java.util.List'],
    func: function () { send("[SSL Pinning Bypass] OkHTTP com.squareup.okhttp.CertificatePinner.check() bypassed"); }
}, {
    class: 'com.android.org.conscrypt.TrustManagerImpl',
    method: 'checkTrustedRecursive',
    func: function (certs, ocspData, tlsSctData, host, clientAuth, untrustedChain, trustAnchorChain, used) { send("[SSL Pinning Bypass] Android 7+ TrustManagerImpl.checkTrustedRecursive() 1 bypassed"); return Java.use("java.util.ArrayList").$new(); }
}, {
    // https://github.com/google/conscrypt/blob/c88f9f55a523f128f0e4dace76a34724bfa1e88c/platform/src/main/java/org/conscrypt/TrustManagerImpl.java#L522
    class: 'com.android.org.conscrypt.TrustManagerImpl',
    method: 'checkTrustedRecursive',
    func: function (ccerts, host, clientAuth, untrustedChain, trustedChain, used) { send("[SSL Pinning Bypass] Android 7+ TrustManagerImpl.checkTrustedRecursive() 2 bypassed"); return Java.use("java.util.ArrayList").$new(); }
}, {
    // https://android.googlesource.com/platform/external/conscrypt/+/1186465/src/platform/java/org/conscrypt/TrustManagerImpl.java#391
    class: 'com.android.org.conscrypt.TrustManagerImpl',
    method: 'checkTrustedRecursive',
    func: function (ccerts, host, clientAuth, untrustedChain, trustedChain, used) { send("[SSL Pinning Bypass] Android 7+ TrustManagerImpl.checkTrustedRecursive() 2 bypassed"); return Java.use("java.util.ArrayList").$new(); }
}, {
    // https://android.googlesource.com/platform/external/conscrypt/+/1186465/src/platform/java/org/conscrypt/TrustManagerImpl.java#514
    class: 'com.android.org.conscrypt.TrustManagerImpl',
    method: 'verifyChain',
    func: function (untrustedChain, trustAnchorChain, host, clientAuth) { send("[SSL Pinning Bypass] Android  TrustManagerImpl.verifyChain() bypassed."); return untrustedChain; }
}, {
    // https://github.com/google/conscrypt/blob/c88f9f55a523f128f0e4dace76a34724bfa1e88c/platform/src/main/java/org/conscrypt/TrustManagerImpl.java#L650
    class: 'com.android.org.conscrypt.TrustManagerImpl',
    method: 'verifyChain',
    func: function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) { send("[SSL Pinning Bypass] Android  TrustManagerImpl.verifyChain() bypassed."); return untrustedChain; }
}, {
    // https://github.com/google/conscrypt/blob/c88f9f55a523f128f0e4dace76a34724bfa1e88c/platform/src/main/java/org/conscrypt/TrustManagerImpl.java#L650
    class: 'com.android.org.conscrypt.TrustManagerImpl',
    method: 'verifyChain',
    func: function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) { send("[SSL Pinning Bypass] Android  TrustManagerImpl.verifyChain() bypassed."); return untrustedChain; }
}, {
    // https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/
    class: 'javax.net.ssl.SSLContext',
    method: 'init',
    arg_list: ["[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom"],
    func: function (a, b, c) {
        var CertificateFactory = Java.use("java.security.cert.CertificateFactory");
        var FileInputStream = Java.use("java.io.FileInputStream");
        var BufferedInputStream = Java.use("java.io.BufferedInputStream");
        var X509Certificate = Java.use("java.security.cert.X509Certificate");
        var KeyStore = Java.use("java.security.KeyStore");
        var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        // Load CAs from an InputStream
        var cf = CertificateFactory.getInstance("X.509");
        try {
            var fileInputStream = FileInputStream.$new("/system/etc/security/cacerts/0025aabb.0");
        }
        catch (err) {
            send("[SSL Pinning Bypass] ERROR - " + err);
        }
        var bufferedInputStream = BufferedInputStream.$new(fileInputStream);
        var ca = cf.generateCertificate(bufferedInputStream);
        bufferedInputStream.close();
        var certInfo = Java.cast(ca, X509Certificate);
        // console.log("[o] Our CA Info: " + certInfo.getSubjectDN());
        // console.log("[+] Creating a KeyStore for our CA...");
        var keyStoreType = KeyStore.getDefaultType();
        var keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);
        keyStore.setCertificateEntry("ca", ca);
        //  console.log("[+] Creating a TrustManager that trusts the CA in our KeyStore...");
        var tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        var tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
        tmf.init(keyStore);
        SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").call(this, a, tmf.getTrustManagers(), c);
        send("[SSL Pinning Bypass]: javax.net.ssl.SSLContext.init initialized with our custom TrustManager");
    }
}
]

setTimeout(function () {
    Java.perform(function () {
        SSLPinningBypass.forEach(function (bypass, _) {
            try {
                if (bypass.target && parseInt(Java.androidVersion) < bypass.target) {
                    send('[SSL Pinning Bypass] Not Hooking unavailable class/method - ' + bypass.class + '.' + bypass.method)
                    return
                }
                if (!Java.use(bypass.class)[bypass.method]) {
                    // send('[SSL Pinning Bypass] Cannot find ' + bypass.class + '.' + bypass.method);
                    return
                }
            } catch (err) {
                // send('[SSL Pinning Bypass] Cannot find ' + bypass.class + '.' + bypass.method);
                return
            }
            if (bypass.arg_list) {
                Java.use(bypass.class)[bypass.method].overload.apply(null, bypass.arg_list).implementation = bypass.func;
            } else {
                Java.use(bypass.class)[bypass.method].overload.implementation = bypass.func;
            }
        })
    })
}, 0);
