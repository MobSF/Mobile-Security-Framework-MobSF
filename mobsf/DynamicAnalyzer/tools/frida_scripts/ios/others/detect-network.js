function safeToString(obj) {
    return (obj && obj.toString) ? obj.toString() : "null";
}


var host = ObjC.classes.NSHost.currentHost();
send("Host name: " + safeToString(host.name()));

var addresses = host.addresses();
for (var i = 0; i < addresses.count(); i++) {
    send("Address: " + safeToString(addresses.objectAtIndex_(i)));
}

var networkInfo = ObjC.classes.CTTelephonyNetworkInfo.alloc().init();
var providers = networkInfo.serviceSubscriberCellularProviders();
var keys = providers.allKeys();

for (var i = 0; i < keys.count(); i++) {
    var key = keys.objectAtIndex_(i);
    var carrier = providers.objectForKey_(key);
    send("Carrier for " + safeToString(key) + ":");
    send("  Carrier Name: " + safeToString(carrier.carrierName()));
    send("  Mobile Country Code: " + safeToString(carrier.mobileCountryCode()));
    send("  Mobile Network Code: " + safeToString(carrier.mobileNetworkCode()));
    send("  ISO Country Code: " + safeToString(carrier.isoCountryCode()));
    send("  Allows VOIP: " + carrier.allowsVOIP());
}
