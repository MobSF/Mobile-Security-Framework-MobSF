/************************************************************************
 * Name: SSL Pinning Bypass for iOS 11
 * OS: iOS
 * Author: @dki
 * Source: https://codeshare.frida.re/@dki/ios10-ssl-bypass/
 * Modified to support Frida 17.0.0+
*************************************************************************/

try {
    /* OSStatus nw_tls_create_peer_trust(tls_handshake_t hdsk, bool server, SecTrustRef *trustRef); */
    var tls_helper_create_peer_trust = new NativeFunction(
        Module.getGlobalExportByName("nw_tls_create_peer_trust"),
        'int', ['pointer', 'bool', 'pointer']
        );

    var errSecSuccess = 0;

    Interceptor.replace(tls_helper_create_peer_trust, new NativeCallback(function(hdsk, server, trustRef) {
        return errSecSuccess;
    }, 'int', ['pointer', 'bool', 'pointer']));
    send("SSL certificate validation bypass active");
} catch (e) {
    send("Error loading iOS 11 SSL bypass: " + e);
}