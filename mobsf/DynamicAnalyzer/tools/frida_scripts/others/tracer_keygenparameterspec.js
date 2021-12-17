/*
    Source: https://github.com/FSecureLABS/android-keystore-audit/tree/master/frida-scripts
    Hooks KeyGenParameterSpec.Builder and gives visibility into how keystore keys are protected
*/


Java.perform(function () {

    hookSetInvalidatedByBiometricEnrollment();
    try {hookSetUnlockedDeviceRequired();} catch (error){send("[AUXILIARY] [TRACER KEYGEN] hookSetUnlockedDeviceRequired not supported on this android version")}
    try {hookSetUserConfirmationRequired();} catch (error){send("[AUXILIARY] [TRACER KEYGEN] hookSetUserConfirmationRequired not supported on this android version")}
    try {hookSetUserAuthenticationValidityDurationSeconds();} catch (error){send("[AUXILIARY] [TRACER KEYGEN] hookSetUserAuthenticationValidityDurationSeconds not supported on this android version")}
    hookSetUserAuthenticationRequired();
    try {hookSetUserPresenceRequired();} catch (error){send("[AUXILIARY] [TRACER KEYGEN] hookSetUserPresenceRequired not supported on this android version")}
    hookSetRandomizedEncryptionRequired();
    hookSetInvalidatedByBiometricEnrollment()
    try {hookSetIsStrongBoxBacked();} catch (error){send("[AUXILIARY] [TRACER KEYGEN] hookSetIsStrongBoxBacked not supported on this android version")}
    hookSetUserAuthenticationValidityDurationSeconds()
    hookSetKeySize();
});
send("[AUXILIARY] [TRACER KEYGEN] KeyGenParameterSpec.Builder hooks loaded!");

var cipherList = [];
var StringCls = null;
Java.perform(function () {
    StringCls = Java.use('java.lang.String');
});

function hookSetInvalidatedByBiometricEnrollment()
{
    var keyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder')['setInvalidatedByBiometricEnrollment'];
    keyGenParameterSpec.implementation = function(flag) {
        send("[AUXILIARY] [TRACER KEYGEN] [!!!!][KeyGenParameterSpec.setInvalidatedByBiometricEnrollment()]: flag: " + flag );
        return this.setInvalidatedByBiometricEnrollment(flag);
    }   
}

function hookSetUnlockedDeviceRequired()
{
    var keyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder')['setUnlockedDeviceRequired'];
    keyGenParameterSpec.implementation = function(flag) {
        send("[AUXILIARY] [TRACER KEYGEN] [KeyGenParameterSpec.setUnlockedDeviceRequired()]: flag: " + flag );
        return this.setUnlockedDeviceRequired(flag);
    }   
}

function hookSetUserConfirmationRequired()
{
    var keyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder')['setUserConfirmationRequired'];
    keyGenParameterSpec.implementation = function(flag) {
        send("[AUXILIARY] [TRACER KEYGEN] [KeyGenParameterSpec.setUserConfirmationRequired()]: flag: " + flag );
        return this.setUserConfirmationRequired(flag);
    }   
}

function hookSetUserAuthenticationValidityDurationSeconds()
{
    var keyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder')['setUserAuthenticationValidityDurationSeconds'];
    keyGenParameterSpec.implementation = function(sec) {
        send("[AUXILIARY] [TRACER KEYGEN] [KeyGenParameterSpec.setUserAuthenticationValidityDurationSeconds()]: seconds: " + sec );
        return this.setUserAuthenticationValidityDurationSeconds(sec);
    }   
}

function hookSetUserAuthenticationRequired()
{
    var keyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder')['setUserAuthenticationRequired'];
    keyGenParameterSpec.implementation = function(flag) {
        send("[AUXILIARY] [TRACER KEYGEN] [KeyGenParameterSpec.setUserAuthenticationRequired()]: flag: " + flag );
        return this.setUserAuthenticationRequired(flag);
    }   
}

function hookSetUserPresenceRequired()
{
    var keyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder')['setUserPresenceRequired'];
    keyGenParameterSpec.implementation = function(flag) {
        send("[AUXILIARY] [TRACER KEYGEN] [KeyGenParameterSpec.setUserPresenceRequired()]: flag: " + flag );
        return this.setUserPresenceRequired(flag);
    }   
}

function hookSetRandomizedEncryptionRequired()
{
    var keyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder')['setRandomizedEncryptionRequired'];
    keyGenParameterSpec.implementation = function(flag) {
        send("[AUXILIARY] [TRACER KEYGEN] [KeyGenParameterSpec.setRandomizedEncryptionRequired()]: flag: " + flag );
        return this.setRandomizedEncryptionRequired(flag);
    }   
}


function hookSetInvalidatedByBiometricEnrollment()
{
    var keyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder')['setInvalidatedByBiometricEnrollment'];
    keyGenParameterSpec.implementation = function(flag) {
        send("[AUXILIARY] [TRACER KEYGEN] [KeyGenParameterSpec.setInvalidatedByBiometricEnrollment()]: flag: " + flag );
        return this.setInvalidatedByBiometricEnrollment(flag);
    }   
}

function hookSetIsStrongBoxBacked()
{
    var keyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder')['setIsStrongBoxBacked'];
    keyGenParameterSpec.implementation = function(flag) {
        send("[AUXILIARY] [TRACER KEYGEN] [KeyGenParameterSpec.setIsStrongBoxBacked()]: flag: " + flag );
        return this.setIsStrongBoxBacked(flag);
    }   
}

function hookSetUserAuthenticationValidityDurationSeconds()
{
    var keyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder')['setUserAuthenticationValidityDurationSeconds'];
    keyGenParameterSpec.implementation = function(flag) {
        send("[AUXILIARY] [TRACER KEYGEN] [KeyGenParameterSpec.setUserAuthenticationValidityDurationSeconds()]: flag: " + flag );
        return this.setUserAuthenticationValidityDurationSeconds(flag);
    }   
}

function hookSetKeySize()
{
    var keyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder')['setKeySize'];
    keyGenParameterSpec.implementation = function(flag) {
        send("[AUXILIARY] [TRACER KEYGEN] [KeyGenParameterSpec.setKeySize()]: keySize: " + flag );
        return this.setKeySize(flag);
    }   
}

