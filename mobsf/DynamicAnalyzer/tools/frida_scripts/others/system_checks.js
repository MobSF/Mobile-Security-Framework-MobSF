Java.perform(function() {

    // Config
    var CONFIG = {
        // if TRUE print stack trace
        printStackTrace: false
    };


    // Declaring Android Objects
    var telephonyManager = Java.use('android.telephony.TelephonyManager');

    telephonyManager.getImei.overloads[0].implementation = function() {
        send('[System Check] Application checking for device IMEI, returning: ' + '35253108' + '852947' + '2');
        if (CONFIG.printStackTrace) {stackTrace();}
        return('35253108' + '852947' + '2');
    };
    telephonyManager.getImei.overloads[1].implementation = function(slot) {
        send('[System Check] Application checking for device IMEI, returning: ' + '35253108' + '852947' + '2');
        if (CONFIG.printStackTrace) {stackTrace();}
        return('35253108' + '852947' + '2');
    };

    telephonyManager.getSimOperator.overload().implementation = function() {
        send('[System Check] getSimOperator call detected, returning:' + payl0ad);
        if (CONFIG.printStackTrace) {stackTrace();}
        return payl0ad;
    };
    telephonyManager.getSimOperator.overload('int').implementation = function(sm) {
        send('[System Check] getSimOperator call detected, returning:' + payl0ad);
        if (CONFIG.printStackTrace) {stackTrace();}
        return payl0ad;
    };

    telephonyManager.getSimOperatorName.overload().implementation = function() {
        send('[System Check] Application checking for SIM operator name, returning: ' + 'Vodafone');
        if (CONFIG.printStackTrace) {stackTrace();}
        return 'Vodafone';
    };

    telephonyManager.getNetworkCountryIso.overload().implementation = function() {
        send('[System Check] Application checking for Network Country ISO, returning: ' + 'deu');
        if (CONFIG.printStackTrace) {stackTrace();}
        return 'deu';
    };
    telephonyManager.getNetworkCountryIso.overload('int').implementation = function() {
        send('[System Check] Application checking for Network Country ISO, returning: ' + 'deu');
        if (CONFIG.printStackTrace) {stackTrace();}
        return 'deu';
    };

    telephonyManager.getSimCountryIso.overload().implementation = function() {
        send('[System Check] Application checking for SIM Country ISO, returning: ' + 'deu');
        if (CONFIG.printStackTrace) {stackTrace();}
        return 'deu';
    };



    // Stack Trace Function
    function stackTrace() {
        Java.perform(function() {
            send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        });
    };
});