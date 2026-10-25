bypassIosSslPinning: function() {
    
    // Constants
    const SSL_VERIFY_NONE = 0;
    const ERR_SEC_SUCCESS = 0;
    
    function get_ios_version() {
        try {
            // Get iOS version using UIDevice
            const UIDevice = ObjC.classes.UIDevice;
            const device = UIDevice.currentDevice();
            const systemVersion = device.systemVersion().toString();
            send("[+] Detected iOS version: " + systemVersion);
            
            // Parse version string to get major version
            const majorVersion = parseInt(systemVersion.split('.')[0]);
            return majorVersion;
        } catch (e) {
            send("[-] Error detecting iOS version: " + e);
            // Fallback: try to detect from system info
            try {
                const sysinfo = Process.getSystemInfo();
                if (sysinfo && sysinfo.os) {
                    const versionMatch = sysinfo.os.match(/iOS (\d+)/);
                    if (versionMatch) {
                        const majorVersion = parseInt(versionMatch[1]);
                        send("[+] Detected iOS version from system info: " + majorVersion);
                        return majorVersion;
                    }
                }
            } catch (fallbackError) {
                send("[-] Fallback iOS version detection failed: " + fallbackError);
            }
            
            // Default to latest version if detection fails
            send("[!] Could not detect iOS version, defaulting to iOS 15+ bypass");
            return 15;
        }
    }

    // Helper function to create custom verify callback
    function createCustomVerifyCallback() {
        return new NativeCallback(function(ssl, out_alert) {
            return SSL_VERIFY_NONE;
        }, 'int', ['pointer', 'pointer']);
    }

    // Helper function to create PSK identity callback
    function createPSKIdentityCallback() {
        return new NativeCallback(function(ssl) {
            return "notarealPSKidentity";
        }, 'pointer', ['pointer']);
    }

    function bypass_ssl_pinning_ios10() {
        try {
            const tls_helper_create_peer_trust = new NativeFunction(
                Module.getGlobalExportByName("tls_helper_create_peer_trust"),
                'int', ['pointer', 'bool', 'pointer']
            );

            Interceptor.replace(tls_helper_create_peer_trust, new NativeCallback(function(hdsk, server, trustRef) {
                return ERR_SEC_SUCCESS;
            }, 'int', ['pointer', 'bool', 'pointer']));
            send("[+] iOS 10 SSL certificate validation bypass active");
        } catch (e) {
            send("[-] Error loading iOS 10 SSL bypass: " + e);
        }
    }

    function bypass_ssl_pinning_ios11() {
        try {
            const tls_helper_create_peer_trust = new NativeFunction(
                Module.getGlobalExportByName("nw_tls_create_peer_trust"),
                'int', ['pointer', 'bool', 'pointer']
            );

            Interceptor.replace(tls_helper_create_peer_trust, new NativeCallback(function(hdsk, server, trustRef) {
                return ERR_SEC_SUCCESS;
            }, 'int', ['pointer', 'bool', 'pointer']));
            send("[+] iOS 11 SSL certificate validation bypass active");
        } catch (e) {
            send("[-] Error loading iOS 11 SSL bypass: " + e);
        }
    }

    function bypass_ssl_pinning_ios12() {
        try {
            const libboringssl = Process.getModuleByName("libboringssl.dylib");
            if (!libboringssl) {
                send("[-] libboringssl.dylib not found for iOS 12 bypass");
                return;
            }

            const ssl_ctx_set_custom_verify = new NativeFunction(
                libboringssl.getExportByName("SSL_CTX_set_custom_verify"),
                'void', ['pointer', 'int', 'pointer']
            );

            const ssl_get_psk_identity = new NativeFunction(
                libboringssl.getExportByName("SSL_get_psk_identity"),
                'pointer', ['pointer']
            );

            const ssl_verify_result_t = createCustomVerifyCallback();
            const psk_callback = createPSKIdentityCallback();

            Interceptor.replace(ssl_ctx_set_custom_verify, new NativeCallback(function(ssl, mode, callback) {
                ssl_ctx_set_custom_verify(ssl, mode, ssl_verify_result_t);
            }, 'void', ['pointer', 'int', 'pointer']));

            Interceptor.replace(ssl_get_psk_identity, psk_callback);

            send("[+] iOS 12 SSL Pinning Bypass - successfully loaded");
        } catch (e) {
            send("[-] Error loading iOS 12 SSL bypass: " + e);
        }
    }

    function bypass_ssl_pinning_ios13() {
        try {
            let libboringssl = Process.getModuleByName("libboringssl.dylib");
            if (!libboringssl) {
                send("[!] libboringssl.dylib module not loaded. Trying to manually load it.");
                Module.load("libboringssl.dylib");
                libboringssl = Process.getModuleByName("libboringssl.dylib");
                if (!libboringssl) {
                    send("[-] Failed to load libboringssl.dylib");
                    return;
                }
            }

            const ssl_set_custom_verify = new NativeFunction(
                libboringssl.getExportByName("SSL_set_custom_verify"),
                'void', ['pointer', 'int', 'pointer']
            );

            const ssl_get_psk_identity = new NativeFunction(
                libboringssl.getExportByName("SSL_get_psk_identity"),
                'pointer', ['pointer']
            );

            const ssl_verify_result_t = createCustomVerifyCallback();
            const psk_callback = createPSKIdentityCallback();

            Interceptor.replace(ssl_set_custom_verify, new NativeCallback(function(ssl, mode, callback) {
                ssl_set_custom_verify(ssl, mode, ssl_verify_result_t);
            }, 'void', ['pointer', 'int', 'pointer']));

            Interceptor.replace(ssl_get_psk_identity, psk_callback);

            send("[+] iOS 13 SSL bypass successfully loaded");
        } catch (e) {
            send("[-] Error loading iOS 13 SSL bypass: " + e);
        }
    }

    function bypass_ssl_pinning_ios14_plus() {
        try {
            const boringssl = Process.getModuleByName('libboringssl.dylib');
            if (!boringssl) {
                send("[-] BoringSSL not found for iOS 14+ bypass");
                return;
            }

            const SSL_set_custom_verify = new NativeFunction(
                boringssl.getExportByName('SSL_set_custom_verify'),
                'void', ['pointer', 'int', 'pointer']
            );

            const custom_verify_cb = createCustomVerifyCallback();

            Interceptor.replace(SSL_set_custom_verify, new NativeCallback(function(ssl, mode, callback) {
                SSL_set_custom_verify(ssl, mode, custom_verify_cb);
            }, 'void', ['pointer', 'int', 'pointer']));

            send('[+] BoringSSL SSL_set_custom_verify bypass installed.');
        } catch (e) {
            send('[-] BoringSSL bypass failed: ' + e);
        }
    }

    // ===== Security.framework hooks =====
    function hookSecurityFramework() {
        const securityHooks = [
            {
                name: "SecTrustEvaluate",
                callback: function(trust, resultPtr) {
                    if (resultPtr) {
                        Memory.writeU8(resultPtr, 1); // kSecTrustResultProceed
                    }
                    send("[+] SecTrustEvaluate() bypassed.");
                    return 0; // errSecSuccess
                },
                returnType: 'int',
                paramTypes: ['pointer', 'pointer']
            },
            {
                name: "SecTrustEvaluateWithError",
                callback: function(trust, result) {
                    if (result) {
                        Memory.writeU8(result, 1); // true
                    }
                    send("[+] SecTrustEvaluateWithError() bypassed.");
                    return 1;
                },
                returnType: 'bool',
                paramTypes: ['pointer', 'pointer']
            }
        ];

        // Apply security framework hooks
        securityHooks.forEach(hook => {
            try {
                const func = Module.findExportByName("Security", hook.name);
                if (func) {
                    Interceptor.replace(func, new NativeCallback(hook.callback, hook.returnType, hook.paramTypes));
                }
            } catch (e) {
                send(`[-] ${hook.name} not found or failed to hook: ${e.message}`);
            }
        });

        // Hook SecTrustSetAnchorCertificates for monitoring
        try {
            const setAnchor = Module.findExportByName("Security", "SecTrustSetAnchorCertificates");
            if (setAnchor) {
                Interceptor.attach(setAnchor, {
                    onEnter: function(args) {
                        send("[+] Attempt to set custom anchor certificates - bypassed.");
                    }
                });
            }
        } catch (e) {
            send('[-] SecTrustSetAnchorCertificates not found or failed to hook: ' + e.message);
        }
    }

    // Main execution with optimizations
    const iosVersion = get_ios_version();
    send("[+] Calling SSL pinning bypass for iOS " + iosVersion);
    
    // Always hook Security framework first (works across all iOS versions)
    hookSecurityFramework();
    
    // Call version-specific bypass with better error handling
    try {
        if (iosVersion <= 10) {
            bypass_ssl_pinning_ios10();
        } else if (iosVersion === 11) {
            bypass_ssl_pinning_ios11();
        } else if (iosVersion === 12) {
            bypass_ssl_pinning_ios12();
        } else if (iosVersion === 13) {
            bypass_ssl_pinning_ios13();
        } else if (iosVersion >= 14) {
            bypass_ssl_pinning_ios14_plus();
        }
    } catch (e) {
        send("[-] Error during version-specific bypass: " + e);
    }
    
    send("[+] SSL pinning bypass completed for iOS " + iosVersion);
    
}