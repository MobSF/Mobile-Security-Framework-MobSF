Java.perform(function() {

    // Config
    var CONFIG = {
        // if TRUE print stack trace
        printStackTrace: false
    };


    // Declaring Android Objects
    var telephonyManager = Java.use('android.telephony.TelephonyManager');

    telephonyManager.getImei.overloads[0].implementation = function() {
        send('--------------------\n[System Check] Application checking for device IMEI, returning: ' + '35253108' + '852947' + '2');
        return('35253108' + '852947' + '2');
    };
    telephonyManager.getImei.overloads[1].implementation = function(slot) {
        send('--------------------\n[System Check] Application checking for device IMEI, returning: ' + '35253108' + '852947' + '2');
        return('35253108' + '852947' + '2');
    };

    telephonyManager.getSimOperator.overload().implementation = function() {
        send('--------------------\n[System Check] getSimOperator call detected, returning:' + payl0ad);
        return payl0ad;
    };
    telephonyManager.getSimOperator.overload('int').implementation = function(sm) {
        send('--------------------\n[System Check] getSimOperator call detected, returning:' + payl0ad);
        return payl0ad;
    };

    telephonyManager.getSimOperatorName.overload().implementation = function() {
        send('--------------------\n[System Check] Application checking for SIM operator name, returning: ' + 'Vodafone');
        return 'Vodafone';
    };

    telephonyManager.getNetworkCountryIso.overload().implementation = function() {
        send('--------------------\n[System Check] Application checking for Network Country ISO, returning: ' + 'deu');
        return 'deu';
    };
    telephonyManager.getNetworkCountryIso.overload('int').implementation = function() {
        send('--------------------\n[System Check] Application checking for Network Country ISO, returning: ' + 'deu');
        return 'deu';
    };

    telephonyManager.getSimCountryIso.overload().implementation = function() {
        send('--------------------\n[System Check] Application checking for SIM Country ISO, returning: ' + 'deu');
        return 'deu';
    };
});