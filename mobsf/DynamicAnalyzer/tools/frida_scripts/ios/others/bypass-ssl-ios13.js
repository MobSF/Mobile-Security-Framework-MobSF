/* Description: iOS 13 SSL Bypass based on https://codeshare.frida.re/@machoreverser/ios12-ssl-bypass/ and https://github.com/nabla-c0d3/ssl-kill-switch2
 *  Author:     @apps3c
 */

try {
    Module.ensureInitialized("libboringssl.dylib");
} catch(err) {
    send("libboringssl.dylib module not loaded. Trying to manually load it.")
    Module.load("libboringssl.dylib");
}

var SSL_VERIFY_NONE = 0;
var ssl_set_custom_verify;
var ssl_get_psk_identity;

ssl_set_custom_verify = new NativeFunction(
    Module.findExportByName("libboringssl.dylib", "SSL_set_custom_verify"),
    'void', ['pointer', 'int', 'pointer']
);

/* Create SSL_get_psk_identity NativeFunction
* Function signature https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_get_psk_identity
*/
ssl_get_psk_identity = new NativeFunction(
    Module.findExportByName("libboringssl.dylib", "SSL_get_psk_identity"),
    'pointer', ['pointer']
);

/** Custom callback passed to SSL_CTX_set_custom_verify */
function custom_verify_callback_that_does_not_validate(ssl, out_alert){
    return SSL_VERIFY_NONE;
}

/** Wrap callback in NativeCallback for frida */
var ssl_verify_result_t = new NativeCallback(function (ssl, out_alert){
    custom_verify_callback_that_does_not_validate(ssl, out_alert);
},'int',['pointer','pointer']);

Interceptor.replace(ssl_set_custom_verify, new NativeCallback(function(ssl, mode, callback) {
    //  |callback| performs the certificate verification. Replace this with our custom callback
    ssl_set_custom_verify(ssl, mode, ssl_verify_result_t);
}, 'void', ['pointer', 'int', 'pointer']));

Interceptor.replace(ssl_get_psk_identity, new NativeCallback(function(ssl) {
    return "notarealPSKidentity";
}, 'pointer', ['pointer']));

send("[+] Bypass successfully loaded ");
