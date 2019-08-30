Java.perform(function() {
    var androidVersion = parseInt(Java.androidVersion, 10) 
    if (androidVersion > 6){
        try{
            // Generic SSL Pinning Bypass tested on Android 7, 7.1, 8, and 9
            // https://android.googlesource.com/platform/external/conscrypt/+/1186465/src/platform/java/org/conscrypt/TrustManagerImpl.java#391
            var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TrustManagerImpl.checkTrustedRecursive.implementation = function(certs, host, clientAuth, untrustedChain, trustedChain, used) {
                send('[SSL Pinning Bypass] checkTrustedRecursive() bypassed');
                return Java.use("java.util.ArrayList").$new();
            }
        }catch (err) {
            send('[SSL Pinning Bypass] TrustManagerImpl.checkTrustedRecursive() not found');
        }
        try {
            var TrustManagerImpl2 = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TrustManagerImpl2.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                send('[SSL Pinning Bypass] verifyChain() bypassed for: ' + host);
                return untrustedChain;
            }
        } catch (err) {
            send('[SSL Pinning Bypass] TrustManagerImpl.verifyChain() not found');
        }
        try {
            var ConscryptFileDescriptorSocket = Java.use('com.android.org.conscrypt.ConscryptFileDescriptorSocket');
            ConscryptFileDescriptorSocket.verifyCertificateChain.implementation = function (certChain, authMethod) {
                send('[SSL Pinning Bypass] verifyCertificateChain() bypassed');
                return;
            }
        } catch (err) {
            send('[SSL Pinning Bypass] ConscryptFileDescriptorSocket.verifyCertificateChain() not found');
        }
    } else if (androidVersion > 4 && androidVersion < 7) {
        // Generic SSL Pinning Bypass tested on Android 5, 5,1, 6
        // https://codeshare.frida.re/@akabe1/frida-universal-pinning-bypasser/
        try {
            var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
            OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certRefs, authMethod) {
                send('[SSL Pinning Bypass] OpenSSLSocketImpl.verifyCertificateChain() bypassed');
                return;
            }
        } catch (err) {
            send('[SSL Pinning Bypass] OpenSSLSocketImpl.verifyCertificateChain() not found');
        }
    }
    // 3rd Party Pinning
    try{
        var OkHttpClient = Java.use("com.squareup.okhttp.OkHttpClient");
        OkHttpClient.setCertificatePinner.implementation = function(certificatePinner){
            send('[SSL Pinning Bypass] OkHttpClient.setCertificatePinner() bypassed');
            return this;
        };
        // Invalidate the certificate pinnet checks (if "setCertificatePinner" was called before the previous invalidation)
        var CertificatePinner = Java.use("com.squareup.okhttp.CertificatePinner");
        CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(p0, p1){
            send('[SSL Pinning Bypass] CertificatePinner.check() 1 bypassed');
            return;
        };
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(p0, p1){
            send('[SSL Pinning Bypass] CertificatePinner.check() 2 bypassed');
            return;
        };
    } catch(err) {
        send('[SSL Pinning Bypass] okhttp CertificatePinner not found');
    }
    try {
        var CertificatePinner2 = Java.use('okhttp3.CertificatePinner');
        CertificatePinner2.check.overload('java.lang.String', 'java.util.List').implementation = function (str) {
            send('[SSL Pinning Bypass] okhttp3.CertificatePinner.check() bypassed for ' + str);
            return;
        };
    } catch(err) {
        send('[SSL Pinning Bypass] okhttp3 CertificatePinner not found');
    }
    try {
        // https://gist.github.com/cubehouse/56797147b5cb22768b500f25d3888a22
        var dataTheorem = Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier");
        dataTheorem.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (str) {
            send('[SSL Pinning Bypass] DataTheorem trustkit.pinning.OkHostnameVerifier.verify() 1 bypassed for ' + str);
            return true;
        };

        dataTheorem.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (str) {
            send('[SSL Pinning Bypass] DataTheorem trustkit.pinning.OkHostnameVerifier.verify() 2 bypassed for ' + str);
            return true;
        };
    } catch(err) {
        send('[SSL Pinning Bypass] DataTheorem trustkit not found');
    }
    try {
        var PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
        PinningTrustManager.checkServerTrusted.implementation = function () {
            send('[SSL Pinning Bypass] Appcelerator appcelerator.https.PinningTrustManager.checkServerTrusted() bypassed');
        }
    } catch (err) {
       send('[SSL Pinning Bypass] Appcelerator PinningTrustManager not found');
    }
    try {
        var SSLCertificateChecker = Java.use('nl.xservices.plugins.SSLCertificateChecker');
        SSLCertificateChecker.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function (action, args, callbackContext) {
            send('[SSL Pinning Bypass] Apache Cordova - SSLCertificateChecker.execute() bypassed');
            callbackContext.success("CONNECTION_SECURE");
            return;
        };
    } catch(err) {
        send('[SSL Pinning Bypass] Apache Cordova SSLCertificateChecker not found');
    }
    try {
        var wultra = Java.use('com.wultra.android.sslpinning.CertStore');
        wultra.validateFingerprint.overload('java.lang.String', '[B').implementation = function (commonName, fingerprint) {
            send('[SSL Pinning Bypass] Wultra com.wultra.android.sslpinning.CertStore.validateFingerprint() bypassed');
            var ValidationResult = Java.use('com.wultra.android.sslpinning.ValidationResult');
            return ValidationResult.TRUSTED;
        };
    } catch(err) {
        send('[SSL Pinning Bypass] Wultra CertStore.validateFingerprint not found');
    }
}, 0);
