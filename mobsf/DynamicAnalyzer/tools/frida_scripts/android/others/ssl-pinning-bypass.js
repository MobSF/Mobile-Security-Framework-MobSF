// Source: https://github.com/apkunpacker/FridaScripts
function disableFlutterPinningv2() {
    var config = {
        "ios": {
            "modulename": "Flutter",
            "patterns": {
                "arm64": ["FF 83 01 D1 FA 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 FD 7B 05 A9 FD 43 01 91 F? 03 00 AA ?? 0? 40 F9 ?8 1? 40 F9 15 ?? 4? F9 B5 00 00 B4", ],
            },
        },
        "android": {
            "modulename": "libflutter.so",
            "patterns": {
                "arm64": ["F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9", "F? 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 13 00 40 F9 F4 03 00 AA 68 1A 40 F9", "FF 43 01 D1 FE 67 01 A9 ?? ?? 06 94 ?? 7? 06 94 68 1A 40 F9 15 15 41 F9 B5 00 00 B4 B6 4A 40 F9", ],
                "arm": ["2D E9 F? 4? D0 F8 00 80 81 46 D8 F8 18 00 D0 F8 ??", ],
                "x64": ["55 41 57 41 56 41 55 41 54 53 50 49 89 f? 4c 8b 37 49 8b 46 30 4c 8b a? ?? 0? 00 00 4d 85 e? 74 1? 4d 8b", "55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FF 48 8B 1F 48 8B 43 30 4C 8B A0 28 02 00 00 4D 85 E4 74"]
            }
        }
    };
    var TLSValidationDisabled = false;
    if (Java.available) {
        console.log("[+] Java Environment Detected");
        Java.perform(hookSystemLoadLibrary);
    } else if (ObjC.available) {
        console.log("[+] iOS environment detected. Not Supported");
    }
    disableTLSValidation();
    setTimeout(disableTLSValidation, 2000, true);

    function hookSystemLoadLibrary() {
        const System = Java.use('java.lang.System');
        const Runtime = Java.use('java.lang.Runtime');
        const SystemLoad_2 = System.loadLibrary.overload('java.lang.String');
        const VMStack = Java.use('dalvik.system.VMStack');
        SystemLoad_2.implementation = function(library) {
            try {
                const loaded = Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), library);
                if (library === 'flutter') {
                    console.log("[+] libflutter.so loaded");
                    disableTLSValidation();
                }
                return loaded;
            } catch (ex) {
                console.log(ex);
            }
        };
    }

    function disableTLSValidation(fallback = false) {
        if (TLSValidationDisabled) return;
        var platformConfig = config[Java.available ? "android" : "ios"];
        var m = Process.findModuleByName(platformConfig["modulename"]);
        // If there is no loaded Flutter module, the setTimeout may trigger a second time, but after that we give up
        if (m === null) {
            if (fallback) {
            }
            return;
        }
        if (Process.arch in platformConfig["patterns"]) {
            findAndPatch(m, platformConfig["patterns"][Process.arch], Java.available && Process.arch == "arm" ? 1 : 0, fallback);
        } else {
            console.log("[!] Processor architecture not supported: ", Process.arch);
        }
        if (!TLSValidationDisabled) {
            if (fallback) {
                if (m.enumerateRanges('r-x').length == 0) {
                    console.log('[!] No memory ranges found in Flutter library. This is either a Frida bug, or the application is using some kind of RASP.');
                } else {
                    console.log('[!] ssl_verify_peer_cert not found. Please open an issue at https://github.com/NVISOsecurity/disable-flutter-tls-verification/issues');
                }
            } else {
                console.log('[!] ssl_verify_peer_cert not found. Trying again...');
            }
        }
    }

    function findAndPatch(m, patterns, thumb, fallback) {
        console.log("[+] Flutter library found");
        var ranges = m.enumerateRanges('r-x');
        ranges.forEach(range => {
            patterns.forEach(pattern => {
                Memory.scan(range.base, range.size, pattern, {
                    onMatch: function(address, size) {
                        console.log('[+] ssl_verify_peer_cert found at offset: 0x' + (address - m.base).toString(16));
                        // TLSValidationDisabled = true;
                        hook_ssl_verify_peer_cert(address.add(thumb));
                    }
                });
            });
        });
    }

    function hook_ssl_verify_peer_cert(address) {
        Interceptor.replace(address, new NativeCallback((pathPtr, flags) => {
            return 0;
        }, 'int', ['pointer', 'int']));
    }
}

function hook_ssl_verify_result(address) {
    Interceptor.attach(address, {
        onEnter: function(args) {
            console.log("Disabling SSL validation")
        },
        onLeave: function(retval) {
            console.log("Retval: " + retval)
            retval.replace(0x1);
        }
    });
}

function disablePinning() {
    try {
        var m = Process.findModuleByName("libflutter.so");
        var pattern = "2d e9 f0 4f a3 b0 82 46 50 20 10 70"
        var res = Memory.scan(m.base, m.size, pattern, {
            onMatch: function(address, size) {
                console.log('[+] ssl_verify_result found at: ' + address.toString());
                hook_ssl_verify_result(address.add(0x01));
            },
            onError: function(reason) {
                console.log('[!] There was an error scanning memory');
            },
            onComplete: function() {
                console.log("All done")
            }
        });
    } catch (e) {
        console.warn("[*] This is Not A Flutter Based APP");
    }
}

function CommonMethods() {
    try {
        const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
            console.log('[*] Bypassing HttpsURLConnection (setDefaultHostnameVerifier)');
        };
        console.log('[+] HttpsURLConnection (setDefaultHostnameVerifier)');
    } catch (err) {}
    try {
        const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setSSLSocketFactory.implementation = function(SSLSocketFactory) {
            console.log('[*] Bypassing HttpsURLConnection (setSSLSocketFactory)');
        };
        console.log('[+] HttpsURLConnection (setSSLSocketFactory)');
    } catch (err) {}
    try {
        const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setHostnameVerifier.implementation = function(hostnameVerifier) {
            console.log('[*] Bypassing HttpsURLConnection (setHostnameVerifier)');
        };
        console.log('[+] HttpsURLConnection (setHostnameVerifier)');
    } catch (err) {}
    try {
        const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        const SSLContext = Java.use('javax.net.ssl.SSLContext');
        const TrustManager = Java.registerClass({
            name: 'incogbyte.bypass.test.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() {
                    return [];
                }
            }
        });
        const TrustManagers = [TrustManager.$new()];
        const SSLContext_init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
        SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
            console.log('[*] Bypassing Trustmanager (Android < 7) request');
            SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
        };
        console.log('[+] SSLContext');
    } catch (err) {}
    try {
        const array_list = Java.use("java.util.ArrayList");
        const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) {
            console.log('[*] Bypassing TrustManagerImpl checkTrusted ');
            return array_list.$new();
        }
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[*] Bypassing TrustManagerImpl verifyChain: ' + host);
            return untrustedChain;
        };
        console.log('[+] TrustManagerImpl');
    } catch (err) {}
    try {
        const okhttp3_Activity_1 = Java.use('okhttp3.CertificatePinner');
        okhttp3_Activity_1.check.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
            console.log('[*] Bypassing OkHTTPv3 (list): ' + a);
        };
        console.log('[+] OkHTTPv3 (list)');
    } catch (err) {}
    try {
        const okhttp3_Activity_2 = Java.use('okhttp3.CertificatePinner');
        okhttp3_Activity_2.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function(a, b) {
            console.log('[*] Bypassing OkHTTPv3 (cert): ' + a);
        };
        console.log('[+] OkHTTPv3 (cert)');
    } catch (err) {}
    try {
        const okhttp3_Activity_3 = Java.use('okhttp3.CertificatePinner');
        okhttp3_Activity_3.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(a, b) {
            console.log('[*] Bypassing OkHTTPv3 (cert array): ' + a);
        };
        console.log('[+] OkHTTPv3 (cert array)');
    } catch (err) {}
    try {
        const okhttp3_Activity_4 = Java.use('okhttp3.CertificatePinner');
        okhttp3_Activity_4['check$okhttp'].implementation = function(a, b) {
            console.log('[*] Bypassing OkHTTPv3 ($okhttp): ' + a);
        };
        console.log('[+] OkHTTPv3 ($okhttp)');
    } catch (err) {}
    try {
        const trustkit_Activity_1 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        trustkit_Activity_1.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(a, b) {
            console.log('[*] Bypassing Trustkit OkHostnameVerifier(SSLSession): ' + a);
            return true;
        };
        console.log('[+] Trustkit OkHostnameVerifier(SSLSession)');
    } catch (err) {}
    try {
        const trustkit_Activity_2 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        trustkit_Activity_2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(a, b) {
            console.log('[*] Bypassing Trustkit OkHostnameVerifier(cert): ' + a);
            return true;
        };
        console.log('[+] Trustkit OkHostnameVerifier(cert)');
    } catch (err) {}
    try {
        const trustkit_PinningTrustManager = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
        trustkit_PinningTrustManager.checkServerTrusted.implementation = function() {
            console.log('[*] Bypassing Trustkit PinningTrustManager');
        };
        console.log('[+] Trustkit PinningTrustManager');
    } catch (err) {}
    try {
        const appcelerator_PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
        appcelerator_PinningTrustManager.checkServerTrusted.implementation = function() {
            console.log('[*] Bypassing Appcelerator PinningTrustManager');
        };
        console.log('[+] Appcelerator PinningTrustManager');
    } catch (err) {}
    try {
        const OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
        OpenSSLSocketImpl.verifyCertificateChain.implementation = function(certRefs, JavaObject, authMethod) {
            console.log('[*] Bypassing OpenSSLSocketImpl Conscrypt');
        };
        console.log('[+] OpenSSLSocketImpl Conscrypt');
    } catch (err) {}
    try {
        const OpenSSLEngineSocketImpl_Activity = Java.use('com.android.org.conscrypt.OpenSSLEngineSocketImpl');
        OpenSSLEngineSocketImpl_Activity.verifyCertificateChain.overload('[Ljava.lang.Long;', 'java.lang.String').implementation = function(a, b) {
            console.log('[*] Bypassing OpenSSLEngineSocketImpl Conscrypt: ' + b);
        };
        console.log('[+] OpenSSLEngineSocketImpl Conscrypt');
    } catch (err) {}
    try {
        const OpenSSLSocketImpl_Harmony = Java.use('org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl');
        OpenSSLSocketImpl_Harmony.verifyCertificateChain.implementation = function(asn1DerEncodedCertificateChain, authMethod) {
            console.log('[*] Bypassing OpenSSLSocketImpl Apache Harmony');
        };
        console.log('[+] OpenSSLSocketImpl Apache Harmony');
    } catch (err) {}
    try {
        const phonegap_Activity = Java.use('nl.xservices.plugins.sslCertificateChecker');
        phonegap_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function(a, b, c) {
            console.log('[*] Bypassing PhoneGap sslCertificateChecker: ' + a);
            return true;
        };
        console.log('[+] PhoneGap sslCertificateChecker');
    } catch (err) {}
    try {
        const WLClient_Activity_1 = Java.use('com.worklight.wlclient.api.WLClient');
        WLClient_Activity_1.getInstance().pinTrustedCertificatePublicKey.overload('java.lang.String').implementation = function(cert) {
            console.log('[*] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey (string): ' + cert);
            return;
        };
        console.log('[+] IBM MobileFirst pinTrustedCertificatePublicKey (string)');
    } catch (err) {}
    try {
        const WLClient_Activity_2 = Java.use('com.worklight.wlclient.api.WLClient');
        WLClient_Activity_2.getInstance().pinTrustedCertificatePublicKey.overload('[Ljava.lang.String;').implementation = function(cert) {
            console.log('[*] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey (string array): ' + cert);
            return;
        };
        console.log('[+] IBM MobileFirst pinTrustedCertificatePublicKey (string array)');
    } catch (err) {}
    try {
        const worklight_Activity_1 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
        worklight_Activity_1.verify.overload('java.lang.String', 'javax.net.ssl.SSLSocket').implementation = function(a, b) {
            console.log('[*] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSocket): ' + a);
            return;
        };
        console.log('[+] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSocket)');
    } catch (err) {}
    try {
        const worklight_Activity_2 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
        worklight_Activity_2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(a, b) {
            console.log('[*] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (cert): ' + a);
            return;
        };
        console.log('[+] IBM WorkLight HostNameVerifierWithCertificatePinning (cert)');
    } catch (err) {}
    try {
        const worklight_Activity_3 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
        worklight_Activity_3.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;').implementation = function(a, b) {
            console.log('[*] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (string string): ' + a);
            return;
        };
        console.log('[+] IBM WorkLight HostNameVerifierWithCertificatePinning (string string)');
    } catch (err) {}
    try {
        const worklight_Activity_4 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
        worklight_Activity_4.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(a, b) {
            console.log('[*] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSession): ' + a);
            return true;
        };
        console.log('[+] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSession)');
    } catch (err) {}
    try {
        const conscrypt_CertPinManager_Activity = Java.use('com.android.org.conscrypt.CertPinManager');
        conscrypt_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
            console.log('[*] Bypassing Conscrypt CertPinManager: ' + a);
            return true;
        };
        console.log('[+] Conscrypt CertPinManager');
    } catch (err) {}
    try {
        const cwac_CertPinManager_Activity = Java.use('com.commonsware.cwac.netsecurity.conscrypt.CertPinManager');
        cwac_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
            console.log('[*] Bypassing CWAC-Netsecurity CertPinManager: ' + a);
            return true;
        };
        console.log('[+] CWAC-Netsecurity CertPinManager');
    } catch (err) {}
    try {
        const androidgap_WLCertificatePinningPlugin_Activity = Java.use('com.worklight.androidgap.plugin.WLCertificatePinningPlugin');
        androidgap_WLCertificatePinningPlugin_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function(a, b, c) {
            console.log('[*] Bypassing Worklight Androidgap WLCertificatePinningPlugin: ' + a);
            return true;
        };
        console.log('[+] Worklight Androidgap WLCertificatePinningPlugin');
    } catch (err) {}
    try {
        const netty_FingerprintTrustManagerFactory = Java.use('io.netty.handler.ssl.util.FingerprintTrustManagerFactory');
        netty_FingerprintTrustManagerFactory.checkTrusted.implementation = function(type, chain) {
            console.log('[*] Bypassing Netty FingerprintTrustManagerFactory');
        };
        console.log('[+] Netty FingerprintTrustManagerFactory');
    } catch (err) {}
    try {
        const Squareup_CertificatePinner_Activity_1 = Java.use('com.squareup.okhttp.CertificatePinner');
        Squareup_CertificatePinner_Activity_1.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function(a, b) {
            console.log('[*] Bypassing Squareup CertificatePinner (cert): ' + a);
            return;
        };
        console.log('[+] Squareup CertificatePinner (cert)');
    } catch (err) {}
    try {
        const Squareup_CertificatePinner_Activity_2 = Java.use('com.squareup.okhttp.CertificatePinner');
        Squareup_CertificatePinner_Activity_2.check.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
            console.log('[*] Bypassing Squareup CertificatePinner (list): ' + a);
            return null;
        };
        console.log('[+] Squareup CertificatePinner (list)');
    } catch (err) {}
    try {
        const Squareup_OkHostnameVerifier_Activity_1 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
        Squareup_OkHostnameVerifier_Activity_1.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(a, b) {
            console.log('[*] Bypassing Squareup OkHostnameVerifier (cert): ' + a);
            return true;
        };
        console.log('[+] Squareup OkHostnameVerifier (cert)');
    } catch (err) {}
    try {
        const Squareup_OkHostnameVerifier_Activity_2 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
        Squareup_OkHostnameVerifier_Activity_2.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(a, b) {
            console.log('[*] Bypassing Squareup OkHostnameVerifier (SSLSession): ' + a);
            return true;
        };
        console.log('[+] Squareup OkHostnameVerifier (SSLSession)');
    } catch (err) {}
    try {
        const AndroidWebViewClient_Activity_1 = Java.use('android.webkit.WebViewClient');
        AndroidWebViewClient_Activity_1.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function(obj1, obj2, obj3) {
            console.log('[*] Bypassing Android WebViewClient (SslErrorHandler)');
        };
        console.log('[+] Android WebViewClient (SslErrorHandler)');
    } catch (err) {}
    try {
        const AndroidWebViewClient_Activity_2 = Java.use('android.webkit.WebViewClient');
        AndroidWebViewClient_Activity_2.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function(obj1, obj2, obj3) {
            console.log('[*] Bypassing Android WebViewClient (WebResourceError)');
        };
        console.log('[+] Android WebViewClient (WebResourceError)');
    } catch (err) {}
    try {
        const CordovaWebViewClient_Activity = Java.use('org.apache.cordova.CordovaWebViewClient');
        CordovaWebViewClient_Activity.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function(obj1, obj2, obj3) {
            console.log('[*] Bypassing Apache Cordova WebViewClient');
            obj3.proceed();
        };
        console.log('[+] Apache Cordova WebViewClient');
    } catch (err) {}
    try {
        const boye_AbstractVerifier = Java.use('ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier');
        boye_AbstractVerifier.verify.implementation = function(host, ssl) {
            console.log('[*] Bypassing Boye AbstractVerifier: ' + host);
        };
        console.log('[+] Boye AbstractVerifier');
    } catch (err) {}
}

function dynamicPatching() {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustManager = Java.registerClass({
        name: 'incogbyte.bypass.test.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() {
                return [];
            }
        }
    });
    try {
        var okhttp3_Activity_1 = Java.use('okhttp3.CertificatePinner');
        okhttp3_Activity_1.check.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
            console.log('[+] Bypassing OkHTTPv3 {1}: ' + a);
        };
    } catch (err) {}
    try {
        var okhttp3_Activity_2 = Java.use('okhttp3.CertificatePinner');
        okhttp3_Activity_2.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function(a, b) {
            console.log('[+] Bypassing OkHTTPv3 {2}: ' + a);
        };
    } catch (err) {}
    try {
        var okhttp3_Activity_3 = Java.use('okhttp3.CertificatePinner');
        okhttp3_Activity_3.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(a, b) {
            console.log('[+] Bypassing OkHTTPv3 {3}: ' + a);
        };
    } catch (err) {}
    try {
        var okhttp3_Activity_4 = Java.use('okhttp3.CertificatePinner');
        okhttp3_Activity_4.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function(a, b) {
            console.log('[+] Bypassing OkHTTPv3 {4}: ' + a);
            return;
        };
    } catch (err) {}
    try {
        var trustkit_Activity_1 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        trustkit_Activity_1.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(a, b) {
            console.log('[+] Bypassing Trustkit {1}: ' + a);
            return true;
        };
    } catch (err) {}
    try {
        var trustkit_Activity_2 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        trustkit_Activity_2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(a, b) {
            console.log('[+] Bypassing Trustkit {2}: ' + a);
            return true;
        };
    } catch (err) {}
    try {
        var trustkit_PinningTrustManager = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
        trustkit_PinningTrustManager.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function(chain, authType) {
            console.log('[+] Bypassing Trustkit {3}');
        };
    } catch (err) {}
    try {
        var array_list = Java.use("java.util.ArrayList");
        var TrustManagerImpl_Activity_1 = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl_Activity_1.checkTrustedRecursive.implementation = function(certs, ocspData, tlsSctData, host, clientAuth, untrustedChain, trustAnchorChain, used) {
            console.log('[+] Bypassing TrustManagerImpl (Android > 7) checkTrustedRecursive check: ' + host);
            return array_list.$new();
        };
    } catch (err) {}
    try {
        var TrustManagerImpl_Activity_2 = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl_Activity_2.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[+] Bypassing TrustManagerImpl (Android > 7) verifyChain check: ' + host);
            return untrustedChain;
        };
    } catch (err) {}
    try {
        var appcelerator_PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
        appcelerator_PinningTrustManager.checkServerTrusted.implementation = function(chain, authType) {
            console.log('[+] Bypassing Appcelerator PinningTrustManager');
            return;
        };
    } catch (err) {}
    try {
        var fabric_PinningTrustManager = Java.use('io.fabric.sdk.android.services.network.PinningTrustManager');
        fabric_PinningTrustManager.checkServerTrusted.implementation = function(chain, authType) {
            console.log('[+] Bypassing Fabric PinningTrustManager');
            return;
        };
    } catch (err) {}
    try {
        var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
        OpenSSLSocketImpl.verifyCertificateChain.implementation = function(certRefs, JavaObject, authMethod) {
            console.log('[+] Bypassing OpenSSLSocketImpl Conscrypt {1}');
        };
    } catch (err) {}
    try {
        var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
        OpenSSLSocketImpl.verifyCertificateChain.implementation = function(certChain, authMethod) {
            console.log('[+] Bypassing OpenSSLSocketImpl Conscrypt {2}');
        };
    } catch (err) {}
    try {
        var OpenSSLEngineSocketImpl_Activity = Java.use('com.android.org.conscrypt.OpenSSLEngineSocketImpl');
        OpenSSLEngineSocketImpl_Activity.verifyCertificateChain.overload('[Ljava.lang.Long;', 'java.lang.String').implementation = function(a, b) {
            console.log('[+] Bypassing OpenSSLEngineSocketImpl Conscrypt: ' + b);
        };
    } catch (err) {}
    try {
        var OpenSSLSocketImpl_Harmony = Java.use('org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl');
        OpenSSLSocketImpl_Harmony.verifyCertificateChain.implementation = function(asn1DerEncodedCertificateChain, authMethod) {
            console.log('[+] Bypassing OpenSSLSocketImpl Apache Harmony');
        };
    } catch (err) {}
    try {
        var phonegap_Activity = Java.use('nl.xservices.plugins.sslCertificateChecker');
        phonegap_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function(a, b, c) {
            console.log('[+] Bypassing PhoneGap sslCertificateChecker: ' + a);
            return true;
        };
    } catch (err) {}
    try {
        var WLClient_Activity_1 = Java.use('com.worklight.wlclient.api.WLClient');
        WLClient_Activity_1.getInstance().pinTrustedCertificatePublicKey.overload('java.lang.String').implementation = function(cert) {
            console.log('[+] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {1}: ' + cert);
            return;
        };
    } catch (err) {}
    try {
        var WLClient_Activity_2 = Java.use('com.worklight.wlclient.api.WLClient');
        WLClient_Activity_2.getInstance().pinTrustedCertificatePublicKey.overload('[Ljava.lang.String;').implementation = function(cert) {
            console.log('[+] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {2}: ' + cert);
            return;
        };
    } catch (err) {}
    try {
        var worklight_Activity_1 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
        worklight_Activity_1.verify.overload('java.lang.String', 'javax.net.ssl.SSLSocket').implementation = function(a, b) {
            console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {1}: ' + a);
            return;
        };
    } catch (err) {}
    try {
        var worklight_Activity_2 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
        worklight_Activity_2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(a, b) {
            console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {2}: ' + a);
            return;
        };
    } catch (err) {}
    try {
        var worklight_Activity_3 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
        worklight_Activity_3.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;').implementation = function(a, b) {
            console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {3}: ' + a);
            return;
        };
    } catch (err) {}
    try {
        var worklight_Activity_4 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
        worklight_Activity_4.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(a, b) {
            console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {4}: ' + a);
            return true;
        };
    } catch (err) {}
    try {
        var conscrypt_CertPinManager_Activity = Java.use('com.android.org.conscrypt.CertPinManager');
        conscrypt_CertPinManager_Activity.checkChainPinning.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
            console.log('[+] Bypassing Conscrypt CertPinManager: ' + a);
            return true;
        };
    } catch (err) {}
    try {
        var legacy_conscrypt_CertPinManager_Activity = Java.use('com.android.org.conscrypt.CertPinManager');
        legacy_conscrypt_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
            console.log('[+] Bypassing Conscrypt CertPinManager (Legacy): ' + a);
            return true;
        };
    } catch (err) {}
    try {
        var cwac_CertPinManager_Activity = Java.use('com.commonsware.cwac.netsecurity.conscrypt.CertPinManager');
        cwac_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
            console.log('[+] Bypassing CWAC-Netsecurity CertPinManager: ' + a);
            return true;
        };
    } catch (err) {}
    try {
        var androidgap_WLCertificatePinningPlugin_Activity = Java.use('com.worklight.androidgap.plugin.WLCertificatePinningPlugin');
        androidgap_WLCertificatePinningPlugin_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function(a, b, c) {
            console.log('[+] Bypassing Worklight Androidgap WLCertificatePinningPlugin: ' + a);
            return true;
        };
    } catch (err) {}
    try {
        var netty_FingerprintTrustManagerFactory = Java.use('io.netty.handler.ssl.util.FingerprintTrustManagerFactory');
        //var netty_FingerprintTrustManagerFactory = Java.use('org.jboss.netty.handler.ssl.util.FingerprintTrustManagerFactory');
        netty_FingerprintTrustManagerFactory.checkTrusted.implementation = function(type, chain) {
            console.log('[+] Bypassing Netty FingerprintTrustManagerFactory');
        };
    } catch (err) {}
    try {
        var Squareup_CertificatePinner_Activity_1 = Java.use('com.squareup.okhttp.CertificatePinner');
        Squareup_CertificatePinner_Activity_1.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function(a, b) {
            console.log('[+] Bypassing Squareup CertificatePinner {1}: ' + a);
            return;
        };
    } catch (err) {}
    try {
        var Squareup_CertificatePinner_Activity_2 = Java.use('com.squareup.okhttp.CertificatePinner');
        Squareup_CertificatePinner_Activity_2.check.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
            console.log('[+] Bypassing Squareup CertificatePinner {2}: ' + a);
            return;
        };
    } catch (err) {}
    try {
        var Squareup_OkHostnameVerifier_Activity_1 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
        Squareup_OkHostnameVerifier_Activity_1.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(a, b) {
            console.log('[+] Bypassing Squareup OkHostnameVerifier {1}: ' + a);
            return true;
        };
    } catch (err) {}
    try {
        var Squareup_OkHostnameVerifier_Activity_2 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
        Squareup_OkHostnameVerifier_Activity_2.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(a, b) {
            console.log('[+] Bypassing Squareup OkHostnameVerifier {2}: ' + a);
            return true;
        };
    } catch (err) {}
    try {
        var AndroidWebViewClient_Activity_1 = Java.use('android.webkit.WebViewClient');
        AndroidWebViewClient_Activity_1.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function(obj1, obj2, obj3) {
            console.log('[+] Bypassing Android WebViewClient check {1}');
        };
    } catch (err) {}
    try {
        var AndroidWebViewClient_Activity_2 = Java.use('android.webkit.WebViewClient');
        AndroidWebViewClient_Activity_2.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function(obj1, obj2, obj3) {
            console.log('[+] Bypassing Android WebViewClient check {2}');
        };
    } catch (err) {}
    try {
        var AndroidWebViewClient_Activity_3 = Java.use('android.webkit.WebViewClient');
        AndroidWebViewClient_Activity_3.onReceivedError.overload('android.webkit.WebView', 'int', 'java.lang.String', 'java.lang.String').implementation = function(obj1, obj2, obj3, obj4) {
            console.log('[+] Bypassing Android WebViewClient check {3}');
        };
    } catch (err) {}
    try {
        var AndroidWebViewClient_Activity_4 = Java.use('android.webkit.WebViewClient');
        AndroidWebViewClient_Activity_4.onReceivedError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function(obj1, obj2, obj3) {
            console.log('[+] Bypassing Android WebViewClient check {4}');
        };
    } catch (err) {}
    try {
        var CordovaWebViewClient_Activity = Java.use('org.apache.cordova.CordovaWebViewClient');
        CordovaWebViewClient_Activity.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function(obj1, obj2, obj3) {
            console.log('[+] Bypassing Apache Cordova WebViewClient check');
            obj3.proceed();
        };
    } catch (err) {}
    try {
        var boye_AbstractVerifier = Java.use('ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier');
        boye_AbstractVerifier.verify.implementation = function(host, ssl) {
            console.log('[+] Bypassing Boye AbstractVerifier check: ' + host);
        };
    } catch (err) {}
    try {
        var apache_AbstractVerifier = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
        apache_AbstractVerifier.verify.implementation = function(a, b, c, d) {
            console.log('[+] Bypassing Apache AbstractVerifier check: ' + a);
            return;
        };
    } catch (err) {}
    try {
        var CronetEngineBuilderImpl_Activity = Java.use("org.chromium.net.impl.CronetEngineBuilderImpl");
        CronetEngine_Activity.enablePublicKeyPinningBypassForLocalTrustAnchors.overload('boolean').implementation = function(a) {
            console.log("[+] Disabling Public Key pinning for local trust anchors in Chromium Cronet");
            var cronet_obj_1 = CronetEngine_Activity.enablePublicKeyPinningBypassForLocalTrustAnchors.call(this, true);
            return cronet_obj_1;
        };
        CronetEngine_Activity.addPublicKeyPins.overload('java.lang.String', 'java.util.Set', 'boolean', 'java.util.Date').implementation = function(hostName, pinsSha256, includeSubdomains, expirationDate) {
            console.log("[+] Bypassing Chromium Cronet pinner: " + hostName);
            var cronet_obj_2 = CronetEngine_Activity.addPublicKeyPins.call(this, hostName, pinsSha256, includeSubdomains, expirationDate);
            return cronet_obj_2;
        };
    } catch (err) {}
    try {
        var HttpCertificatePinning_Activity = Java.use('diefferson.http_certificate_pinning.HttpCertificatePinning');
        HttpCertificatePinning_Activity.checkConnexion.overload("java.lang.String", "java.util.List", "java.util.Map", "int", "java.lang.String").implementation = function(a, b, c, d, e) {
            console.log('[+] Bypassing Flutter HttpCertificatePinning : ' + a);
            return true;
        };
    } catch (err) {}
    try {
        var SslPinningPlugin_Activity = Java.use('com.macif.plugin.sslpinningplugin.SslPinningPlugin');
        SslPinningPlugin_Activity.checkConnexion.overload("java.lang.String", "java.util.List", "java.util.Map", "int", "java.lang.String").implementation = function(a, b, c, d, e) {
            console.log('[+] Bypassing Flutter SslPinningPlugin: ' + a);
            return true;
        };
    } catch (err) {}

    function rudimentaryFix(typeName) {
        if (typeName === undefined) {
            return;
        } else if (typeName === 'boolean') {
            return true;
        } else {
            return null;
        }
    }
    try {
        var UnverifiedCertError = Java.use('javax.net.ssl.SSLPeerUnverifiedException');
        UnverifiedCertError.$init.implementation = function(str) {
            console.log('[!] Unexpected SSLPeerUnverifiedException occurred, trying to patch it dynamically...!');
            try {
                var stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
                var exceptionStackIndex = stackTrace.findIndex(stack => stack.getClassName() === "javax.net.ssl.SSLPeerUnverifiedException");
                var callingFunctionStack = stackTrace[exceptionStackIndex + 1];
                var className = callingFunctionStack.getClassName();
                var methodName = callingFunctionStack.getMethodName();
                var callingClass = Java.use(className);
                var callingMethod = callingClass[methodName];
                console.log('[!] Attempting to bypass uncommon SSL Pinning method on: ' + className + '.' + methodName + '!');
                if (callingMethod.implementation) {
                    return;
                }
                var returnTypeName = callingMethod.returnType.type;
                callingMethod.implementation = function() {
                    rudimentaryFix(returnTypeName);
                };
            } catch (e) {
                if (String(e).includes(".overload")) {
                    var splittedList = String(e).split(".overload");
                    for (let i = 2; i < splittedList.length; i++) {
                        var extractedOverload = splittedList[i].trim().split("(")[1].slice(0, -1).replaceAll("'", "");
                        if (extractedOverload.includes(",")) {
                            var argList = extractedOverload.split(", ");
                            console.log('[!] Attempting overload of ' + className + '.' + methodName + ' with arguments: ' + extractedOverload + '!');
                            if (argList.length == 2) {
                                callingMethod.overload(argList[0], argList[1]).implementation = function(a, b) {
                                    rudimentaryFix(returnTypeName);
                                }
                            } else if (argNum == 3) {
                                callingMethod.overload(argList[0], argList[1], argList[2]).implementation = function(a, b, c) {
                                    rudimentaryFix(returnTypeName);
                                }
                            } else if (argNum == 4) {
                                callingMethod.overload(argList[0], argList[1], argList[2], argList[3]).implementation = function(a, b, c, d) {
                                    rudimentaryFix(returnTypeName);
                                }
                            } else if (argNum == 5) {
                                callingMethod.overload(argList[0], argList[1], argList[2], argList[3], argList[4]).implementation = function(a, b, c, d, e) {
                                    rudimentaryFix(returnTypeName);
                                }
                            } else if (argNum == 6) {
                                callingMethod.overload(argList[0], argList[1], argList[2], argList[3], argList[4], argList[5]).implementation = function(a, b, c, d, e, f) {
                                    rudimentaryFix(returnTypeName);
                                }
                            }
                        } else {
                            callingMethod.overload(extractedOverload).implementation = function(a) {
                                rudimentaryFix(returnTypeName);
                            }
                        }
                    }
                } else {
                    console.log('[-] Failed to dynamically patch SSLPeerUnverifiedException ' + e + '!');
                }
            }
            return this.$init(str);
        };
    } catch (err) {}
}
setTimeout(function() {
    Java.perform(function() {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManager = Java.registerClass({
            name: 'incogbyte.bypass.test.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() {
                    return [];
                }
            }
        });
        setTimeout(disablePinning, 1000);
        disableFlutterPinningv2();
        dynamicPatching();
        CommonMethods();
        try {
            var okhttp3_Activity = Java.use('okhttp3.CertificatePinner');
            okhttp3_Activity.check.overload('java.lang.String', 'java.util.List').implementation = function(str) {
                console.log('[+] Bypassing OkHTTPv3 {1}: ' + str);
            };
            okhttp3_Activity.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function(str) {
                console.log('[+] Bypassing OkHTTPv3 {2}: ' + str);
            };
        } catch (err) {}
        try {
            var trustkit_Activity = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
            trustkit_Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(str) {
                console.log('[+] Bypassing Trustkit {1}: ' + str);
                return true;
            };
            trustkit_Activity.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(str) {
                console.log('[+] Bypassing Trustkit {2}: ' + str);
                return true;
            };
            var trustkit_PinningTrustManager = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
            trustkit_PinningTrustManager.checkServerTrusted.implementation = function() {
                console.log('[+] Bypassing Trustkit {3}');
            };
        } catch (err) {}
        try {
            var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                console.log('[+] Bypassing TrustManagerImpl (Android > 7): ' + host);
                return untrustedChain;
            };
        } catch (err) {}
        try {
            var appcelerator_PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
            appcelerator_PinningTrustManager.checkServerTrusted.implementation = function() {
                console.log('[+] Bypassing Appcelerator PinningTrustManager');
            };
        } catch (err) {}
        try {
            var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
            OpenSSLSocketImpl.verifyCertificateChain.implementation = function(certRefs, JavaObject, authMethod) {
                console.log('[+] Bypassing OpenSSLSocketImpl Conscrypt');
            };
        } catch (err) {}
        try {
            var OpenSSLEngineSocketImpl_Activity = Java.use('com.android.org.conscrypt.OpenSSLEngineSocketImpl');
            OpenSSLSocketImpl_Activity.verifyCertificateChain.overload('[Ljava.lang.Long;', 'java.lang.String').implementation = function(str1, str2) {
                console.log('[+] Bypassing OpenSSLEngineSocketImpl Conscrypt: ' + str2);
            };
        } catch (err) {}
        try {
            var OpenSSLSocketImpl_Harmony = Java.use('org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl');
            OpenSSLSocketImpl_Harmony.verifyCertificateChain.implementation = function(asn1DerEncodedCertificateChain, authMethod) {
                console.log('[+] Bypassing OpenSSLSocketImpl Apache Harmony');
            };
        } catch (err) {}
        try {
            var phonegap_Activity = Java.use('nl.xservices.plugins.sslCertificateChecker');
            phonegap_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function(str) {
                console.log('[+] Bypassing PhoneGap sslCertificateChecker: ' + str);
                return true;
            };
        } catch (err) {}
        try {
            var WLClient_Activity = Java.use('com.worklight.wlclient.api.WLClient');
            WLClient_Activity.getInstance().pinTrustedCertificatePublicKey.overload('java.lang.String').implementation = function(cert) {
                console.log('[+] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {1}: ' + cert);
                return;
            };
            WLClient_Activity.getInstance().pinTrustedCertificatePublicKey.overload('[Ljava.lang.String;').implementation = function(cert) {
                console.log('[+] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {2}: ' + cert);
                return;
            };
        } catch (err) {}
        try {
            var worklight_Activity = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
            worklight_Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSocket').implementation = function(str) {
                console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {1}: ' + str);
                return;
            };
            worklight_Activity.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(str) {
                console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {2}: ' + str);
                return;
            };
            worklight_Activity.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;').implementation = function(str) {
                console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {3}: ' + str);
                return;
            };
            worklight_Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(str) {
                console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {4}: ' + str);
                return true;
            };
        } catch (err) {}
        try {
            var conscrypt_CertPinManager_Activity = Java.use('com.android.org.conscrypt.CertPinManager');
            conscrypt_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function(str) {
                console.log('[+] Bypassing Conscrypt CertPinManager: ' + str);
                return true;
            };
        } catch (err) {}
        try {
            var cwac_CertPinManager_Activity = Java.use('com.commonsware.cwac.netsecurity.conscrypt.CertPinManager');
            cwac_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function(str) {
                console.log('[+] Bypassing CWAC-Netsecurity CertPinManager: ' + str);
                return true;
            };
        } catch (err) {}
        try {
            var androidgap_WLCertificatePinningPlugin_Activity = Java.use('com.worklight.androidgap.plugin.WLCertificatePinningPlugin');
            androidgap_WLCertificatePinningPlugin_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function(str) {
                console.log('[+] Bypassing Worklight Androidgap WLCertificatePinningPlugin: ' + str);
                return true;
            };
        } catch (err) {}
        try {
            var Squareup_CertificatePinner_Activity = Java.use('com.squareup.okhttp.CertificatePinner');
            Squareup_CertificatePinner_Activity.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function(str1, str2) {
                console.log('[+] Bypassing Squareup CertificatePinner {1}: ' + str1);
                return;
            };
            Squareup_CertificatePinner_Activity.check.overload('java.lang.String', 'java.util.List').implementation = function(str1, str2) {
                console.log('[+] Bypassing Squareup CertificatePinner {2}: ' + str1);
                return;
            };
        } catch (err) {}
        try {
            var Squareup_OkHostnameVerifier_Activity = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
            Squareup_OkHostnameVerifier_Activity.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(str1, str2) {
                console.log('[+] Bypassing Squareup OkHostnameVerifier {1}: ' + str1);
                return true;
            };
            Squareup_OkHostnameVerifier_Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(str1, str2) {
                console.log('[+] Bypassing Squareup OkHostnameVerifier {2}: ' + str1);
                return true;
            };
        } catch (err) {}
        try {
            var AndroidWebViewClient_Activity = Java.use('android.webkit.WebViewClient');
            AndroidWebViewClient_Activity.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function(obj1, obj2, obj3) {
                console.log('[+] Bypassing Android WebViewClient');
            };
        } catch (err) {}
        try {
            var CordovaWebViewClient_Activity = Java.use('org.apache.cordova.CordovaWebViewClient');
            CordovaWebViewClient_Activity.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function(obj1, obj2, obj3) {
                console.log('[+] Bypassing Apache Cordova WebViewClient');
                obj3.proceed();
            };
        } catch (err) {}
        try {
            var boye_AbstractVerifier = Java.use('ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier');
            boye_AbstractVerifier.verify.implementation = function(host, ssl) {
                console.log('[+] Bypassing Boye AbstractVerifier: ' + host);
            };
        } catch (err) {}
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        try {
            TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                console.log("[+] TrustManagerImpl verifyChain called");
                return untrustedChain;
            }
        } catch (e) {}
        try {
            var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
            OpenSSLSocketImpl.verifyCertificateChain.implementation = function(certRefs, authMethod) {
                console.log('    OpenSSLSocketImpl.verifyCertificateChain');
            }
            console.log('[+] OpenSSLSocketImpl pinning')
        } catch (err) {}
        try {
            var Activity = Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier");
            Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(str) {
                console.log('    Trustkit.verify1: ' + str);
                return true;
            };
            Activity.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(str) {
                console.log('    Trustkit.verify2: ' + str);
                return true;
            };
            console.log('[+] Trustkit pinning')
        } catch (err) {}
        try {
            var netBuilder = Java.use("org.chromium.net.CronetEngine$Builder");
            netBuilder.enablePublicKeyPinningBypassForLocalTrustAnchors.implementation = function(arg) {
                console.log("    Enables or disables public key pinning bypass for local trust anchors = " + arg);
                var ret = netBuilder.enablePublicKeyPinningBypassForLocalTrustAnchors.call(this, true);
                return ret;
            };
            netBuilder.addPublicKeyPins.implementation = function(hostName, pinsSha256, includeSubdomains, expirationDate) {
                console.log("[+] Сronet addPublicKeyPins hostName = " + hostName);
                return this;
            };
        } catch (err) {}
    });
}, 0);
