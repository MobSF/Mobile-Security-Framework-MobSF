Java.perform(function() {

    // Print Initalisation
    send("[Initialised] SystemChecks");

    // Config
    var CONFIG = {
        // if TRUE print stack trace
        printStackTrace: false
    };



    // Spoofed Data
    var phoneNumber = '+49 1522 343333';
    var IMEINumber = '35253108' + '852947' + '2';
    var SIMOperatorCode = '049' + '262';
    var SIMOperatorName = 'Vodafone';
    var countryCode = 'deu';
    var bluetoothMACAddress = 'F7:B0:AB:E9:2B:B1';
    var wifiMACAddress = 'EB:FD:C5:32:9D:75';
    var routerMACAddress = '84:29:CD:A7:35:BA';
    var wifiSSID = 'CorporateNetwork01';



    // Declaring Android Objects
    var telephonyManager = Java.use('android.telephony.TelephonyManager');
    var build = Java.use('android.os.Build')
    var wifiInfo = Java.use('android.net.wifi.WifiInfo');
    var bluetoothAdapter = Java.use('android.bluetooth.BluetoothAdapter');
    var securityExecption = Java.use('java.lang.SecurityException')



    // BUILD Get Serial Number
    build.getSerial.implementation = function() {
        serialNumber = this.getSerial();
        send('[SystemCheck.DeviceSerial] Application checking for Device serial, returning -> ' + serialNumber);
        if (CONFIG.printStackTrace) {stackTrace();}
        return serialNumber;
    };



    // Telephony Manager Get Phone Number
    telephonyManager.getLine1Number.overloads[0].implementation = function() {
        send('[SystemCheck.PhoneNumber] Application checking for Phone Number, returning -> ' + phoneNumber);
        if (CONFIG.printStackTrace) {stackTrace();}
        return phoneNumber;
    };

    // Telephony Manager Get Subscriber ID (IMSI)
    telephonyManager.getSubscriberId.overload().implementation = function() {
        exception = securityExecption.$init();
        send('[SystemCheck.SubscriberID] Application checking for Subscriber ID, returning -> ' + exception);
        if (CONFIG.printStackTrace) {stackTrace();}
        return exception;
    };

    // Telephony Manager Get Device ID (IMEI)
    telephonyManager.getDeviceId.overloads().implementation = function() {
        send('[SystemCheck.IMEI] Application asks for device IMEI, returning -> ' + IMEINumber);
        if (CONFIG.printStackTrace) {stackTrace();}
        return IMEINumber;
    };
    telephonyManager.getDeviceId.overloads('int').implementation = function(slot) {
        send('[SystemCheck.IMEI] Application asks for device IMEI, returning -> ' + IMEINumber);
        if (CONFIG.printStackTrace) {stackTrace();}
        return IMEINumber;
    };

    // Telephony Manager Get IMEI Number
    telephonyManager.getImei.overloads[0].implementation = function() {
        send('[SystemCheck.IMEI] Application checking for device IMEI, returning -> ' + IMEINumber);
        if (CONFIG.printStackTrace) {stackTrace();}
        return IMEINumber;
    };
    telephonyManager.getImei.overloads[1].implementation = function(slot) {
        send('[SystemCheck.IMEI] Application checking for device IMEI, returning -> ' + IMEINumber);
        if (CONFIG.printStackTrace) {stackTrace();}
        return IMEINumber;
    };

    // Telephony Manager Get SIM Operator
    telephonyManager.getSimOperator.overload().implementation = function() {
        send('[SystemCheck.SIMOperator] Application checking for SIM operator, returning -> ' + SIMOperatorCode);
        if (CONFIG.printStackTrace) {stackTrace();}
        return SIMOperatorCode;
    };
    telephonyManager.getSimOperator.overload('int').implementation = function(sm) {
        send('[SystemCheck.SIMOperator] Applicaiton checking for SIM operator, returning -> ' + SIMOperatorCode);
        if (CONFIG.printStackTrace) {stackTrace();}
        return SIMOperatorCode;
    };

    // Telephony Manager Get SIM Operator Name
    telephonyManager.getSimOperatorName.overload().implementation = function() {
        send('[SystemCheck.SIMOperatorName] Application checking for SIM operator name, returning -> ' + SIMOperatorName);
        if (CONFIG.printStackTrace) {stackTrace();}
        return SIMOperatorName;
    };

    // Telephony Manager Get SIM Serial Number
    telephonyManager.getSimSerialNumber.overload().implementation = function() {
        exception = securityExecption.$init();
        send('[SystemCheck.SIMSerial] Application checking for SIM Serial Number, returning -> ' + exception);
        if (CONFIG.printStackTrace) {stackTrace();}
        return exception;
    }

    // Telephony Manager Get SIM Country ISO
    telephonyManager.getSimCountryIso.overload().implementation = function() {
        send('[SystemCheck.Country] Application checking for SIM Country ISO, returning -> ' + countryCode);
        if (CONFIG.printStackTrace) {stackTrace();}
        return countryCode;
    };

    // Telephony Manager Get Network Country ISO
    telephonyManager.getNetworkCountryIso.overload().implementation = function() {
        send('[SystemCheck.Country] Application checking for Network Country ISO, returning -> ' + countryCode);
        if (CONFIG.printStackTrace) {stackTrace();}
        return countryCode;
    };
    telephonyManager.getNetworkCountryIso.overload('int').implementation = function() {
        send('[SystemCheck.Country] Application checking for Network Country ISO, returning -> ' + countryCode);
        if (CONFIG.printStackTrace) {stackTrace();}
        return countryCode;
    };



    // Bluetooth Addapter Get MAC Address
    bluetoothAdapter.getAddress.implementation = function() {
        send('[NetworkCheck.BluetoothMAC] Application chekcing Bluetooth MAC Address, returning -> ' + bluetoothMACAddress);
        if (CONFIG.printStackTrace) {stackTrace();}
        return bluetoothMACAddress;
    };



    // Wifi Info Get MAC Address
    wifiInfo.getMacAddress.implementation = function() {
        send('[NetworkCheck.WifiMAC] Application checking Wifi MAC Address, returning -> ' + wifiMACAddress);
        if (CONFIG.printStackTrace) {stackTrace();}
        return wifiMACAddress;
    };

    // Wifi Info Get SSID
    wifiInfo.getSSID.implementation = function() {
        send('[NetworkCheck.WifiSSID] Applicaiton checking Wifi SSID, returning -> ' + wifiSSID);
        if (CONFIG.printStackTrace) {stackTrace();}
        return wifiSSID;
    };

    // Wifi Info Get Router MAC Address
    wifiInfo.getBSSID.implementation = function() {
        send('[NetworkCheck.RouterMAC] Application checking Router MAC Address, returning -> ' + routerMACAddress);
        if (CONFIG.printStackTrace) {stackTrace();}
        return routerMACAddress;
    };



    // Stack Trace Function
    function stackTrace() {
        send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
    };
});