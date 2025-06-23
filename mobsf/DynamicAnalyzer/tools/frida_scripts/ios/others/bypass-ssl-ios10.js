/************************************************************************
 * Name: SSL Pinning Bypass for iOS 10
 * OS: iOS
 * Author: @dki
 * Source: https://codeshare.frida.re/@dki/ios10-ssl-bypass/
 * Modified to support Frida 17.0.0+
*************************************************************************/

try {
    var tls_helper_create_peer_trust = new NativeFunction(
        Module.getGlobalExportByName("tls_helper_create_peer_trust"),
        'int', ['pointer', 'bool', 'pointer']
        );

    var errSecSuccess = 0;

    Interceptor.replace(tls_helper_create_peer_trust, new NativeCallback(function(hdsk, server, trustRef) {
        return errSecSuccess;
    }, 'int', ['pointer', 'bool', 'pointer']));
    send("SSL certificate validation bypass active");
} catch (e) {
    send("Error loading iOS 10 SSL bypass: " + e);
}