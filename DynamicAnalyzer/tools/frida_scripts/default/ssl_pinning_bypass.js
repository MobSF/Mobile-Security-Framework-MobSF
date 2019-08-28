var SSLPinningBypass = [{
    // https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/
    class: 'javax.net.ssl.SSLContext',
    method: 'init',
    arguments: ["[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom"],
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
}, {
    // https://github.com/google/conscrypt/blob/c88f9f55a523f128f0e4dace76a34724bfa1e88c/platform/src/main/java/org/conscrypt/TrustManagerImpl.java#L522
    class: 'com.android.org.conscrypt.TrustManagerImpl',
    method: 'checkTrustedRecursive',
    func: function (certs, ocspData, tlsSctData, host, clientAuth, untrustedChain, trustAnchorChain, used) {
        send("[SSL Pinning Bypass] Android 7+ TrustManagerImpl.checkTrustedRecursive() 1 bypassed");
        var arrayList = Java.use("java.util.ArrayList");
        return arrayList.$new();
    }
}, {
    // https://android.googlesource.com/platform/external/conscrypt/+/1186465/src/platform/java/org/conscrypt/TrustManagerImpl.java#391
    class: 'com.android.org.conscrypt.TrustManagerImpl',
    method: 'checkTrustedRecursive',
    func: function (ccerts, host, clientAuth, untrustedChain, trustedChain, used) {
        send("[SSL Pinning Bypass] Android 7+ TrustManagerImpl.checkTrustedRecursive() 2 bypassed");
        var arrayList = Java.use("java.util.ArrayList");
        return arrayList.$new();
    }
}, {
    // https://github.com/google/conscrypt/blob/c88f9f55a523f128f0e4dace76a34724bfa1e88c/platform/src/main/java/org/conscrypt/TrustManagerImpl.java#L650
    class: 'com.android.org.conscrypt.TrustManagerImpl',
    method: 'verifyChain',
    func: function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
        send("[SSL Pinning Bypass] Android  TrustManagerImpl.verifyChain() 1 bypassed.");
        return untrustedChain;
    }
}, {
    // https://android.googlesource.com/platform/external/conscrypt/+/1186465/src/platform/java/org/conscrypt/TrustManagerImpl.java#514
    class: 'com.android.org.conscrypt.TrustManagerImpl',
    method: 'verifyChain',
    func: function (untrustedChain, trustAnchorChain, host, clientAuth) {
        send("[SSL Pinning Bypass] Android  TrustManagerImpl.verifyChain() 2 bypassed.");
        return untrustedChain;
    }
}, {
    // https://android.googlesource.com/platform/external/conscrypt/+/1186465/src/platform/java/org/conscrypt/TrustManagerImpl.java#514
    class: 'com.android.org.conscrypt.TrustManagerImpl',
    method: 'verifyChain',
    func: function (untrustedChain, trustAnchorChain, host, clientAuth) {
        send("[SSL Pinning Bypass] Android  TrustManagerImpl.verifyChain() 2 bypassed.");
        return untrustedChain;
    }
}, /*{
    // https://codeshare.frida.re/@akabe1/frida-universal-pinning-bypasser/
    class: 'com.android.org.conscrypt.OpenSSLSocketImpl',
    method: 'verifyCertificateChain',
    func: function (g, i) { send('[SSL Pinning Bypass] OpenSSLSocketImpl.verifyCertificateChain() bypassed'); }
},*/ {
    class: 'nl.xservices.plugins.SSLCertificateChecker',
    method: 'execute',
    arguments: ["java.lang.String", "org.json.JSONArray", "org.apache.cordova.CallbackContext"],
    func: function (action, args, callbackContext) { send('[SSL Pinning Bypass] Apache Cordova - SSLCertificateChecker.execute() bypassed');
        callbackContext.success("CONNECTION_SECURE");
        return;}
}, {
    class: 'appcelerator.https.PinningTrustManager',
    method: 'checkServerTrusted',
    func: function () { send("[SSL Pinning Bypass]  Appcelerator Titanium - appcelerator.https.PinningTrustManager.checkServerTrusted() bypassed"); }
}, {
    // https://gist.github.com/cubehouse/56797147b5cb22768b500f25d3888a22
    class: 'com.datatheorem.android.trustkit.pinning.OkHostnameVerifier',
    method: 'verify',
    arguments: ['java.lang.String', 'javax.net.ssl.SSLSession'],
    func: function () { send("[SSL Pinning Bypass] trustkit com.datatheorem.android.trustkit.pinning.OkHostnameVerifier.verify() 1 bypassed");
        return true;}
}, {
    class: 'com.datatheorem.android.trustkit.pinning.OkHostnameVerifier',
    method: 'verify',
    arguments: ['java.lang.String', 'java.security.cert.X509Certificate'],
    func: function (str) { send("[SSL Pinning Bypass] trustkit com.datatheorem.android.trustkit.pinning.OkHostnameVerifier.verify() 2 bypassed");
        return true; }
}, {
    class: 'com.wultra.android.sslpinning.CertStore',
    method: 'validateFingerprint',
    arguments: ['java.lang.String', '[B'],
    func: function (commonName, fingerprint) { send("[SSL Pinning Bypass] Wultra com.wultra.android.sslpinning.CertStore.validateFingerprint() bypassed");
        var ValidationResult = Java.use('com.wultra.android.sslpinning.ValidationResult');
        return ValidationResult.TRUSTED; }
},{
    class: 'okhttp3.CertificatePinner',
    method: 'check',
    arguments: ['java.lang.String', 'java.util.List'],
    func: function () { send("[SSL Pinning Bypass] OkHTTP 3.x okhttp3.CertificatePinner.check() bypassed"); }
},{
    // https://android.googlesource.com/platform/external/okhttp/+/a2cab72/okhttp/src/main/java/com/squareup/okhttp/CertificatePinner.java#122
    class: 'com.squareup.okhttp.CertificatePinner',
    method: 'check',
    arguments: ['java.lang.String', 'java.util.List'],
    func: function () { send("[SSL Pinning Bypass] OkHTTP com.squareup.okhttp.CertificatePinner.check() bypassed"); }
}
]

setTimeout(function () {
    Java.perform(function () {
        SSLPinningBypass.forEach(function (bypass, _) {
            var toHook;
            try {
                if (bypass.target && parseInt(Java.androidVersion, 10) < bypass.target) {
                    send('[SSL Pinning Bypass] Not Hooking unavailable class/method - ' + bypass.class + '.' + bypass.method)
                    return
                }
                toHook = Java.use(bypass.class)[bypass.method];
                if (!toHook) {
                   //  send('[SSL Pinning Bypass] Cannot find ' + bypass.class + '.' + bypass.method);
                    return
                }
            } catch (err) {
                // send('[SSL Pinning Bypass] Cannot find ' + bypass.class + '.' + bypass.method);
                return
            }
            if (bypass.arguments) {
                send('[SSL Pinning Bypass] Bypassing ' + bypass.class + '.' + bypass.method);
                toHook.overload.apply(null, bypass.arguments).implementation = bypass.func;
            } else {
                send('[SSL Pinning Bypass] Bypassing ' + bypass.class + '.' + bypass.method);
                toHook.overload.implementation = bypass.func;
            }
        })
    })
}, 0);