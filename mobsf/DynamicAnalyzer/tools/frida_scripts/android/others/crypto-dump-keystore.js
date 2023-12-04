// https://github.com/sensepost/objection/blob/f8e78d8a29574c6dadd2b953a63207b45a19b1cf/objection/hooks/android/keystore/list.js
// Dump entries in the Android Keystore, together with a flag
// indicating if its a key or a certificate.
//
// Ref: https://developer.android.com/reference/java/security/KeyStore.html

var KeyStore = Java.use('java.security.KeyStore');
var entries = [];

// Prepare the AndroidKeyStore keystore provider and load it. 
// Maybe at a later stage we should support adding other stores
// like from file or JKS.
var ks = KeyStore.getInstance('AndroidKeyStore');
ks.load(null, null);

// Get the aliases and loop through them. The aliases() method
// return an Enumeration<String> type.
var aliases = ks.aliases();

while (aliases.hasMoreElements()) {

    var alias = aliases.nextElement();

    entries.push({
        'alias': alias.toString(),
        'is_key': ks.isKeyEntry(alias),
        'is_certificate': ks.isCertificateEntry(alias)
    })
}


send(JSON.stringify(entries, null, 2));

// - Sample Java
//
// KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
// ks.load(null);
// Enumeration<String> aliases = ks.aliases();
//
// while(aliases.hasMoreElements()) {
//     Log.e("E", "Aliases = " + aliases.nextElement());
// }