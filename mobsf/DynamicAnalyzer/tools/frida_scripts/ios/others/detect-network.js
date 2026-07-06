function safeToString(obj) {
    return obj?.toString?.() ?? "null";
}


const host = ObjC.classes.NSHost.currentHost();
send("Host name: " + safeToString(host.name()));

const addresses = host.addresses();
for (let i = 0; i < addresses.count(); i++) {
    send("Address: " + safeToString(addresses.objectAtIndex_(i)));
}

const networkInfo = ObjC.classes.CTTelephonyNetworkInfo.alloc().init();
const providers = networkInfo.serviceSubscriberCellularProviders();
const keys = providers.allKeys();

for (let j = 0; j < keys.count(); j++) {
    const key = keys.objectAtIndex_(j);
    const carrier = providers.objectForKey_(key);
    send("Carrier for " + safeToString(key) + ":");
    send("  Carrier Name: " + safeToString(carrier.carrierName()));
    send("  Mobile Country Code: " + safeToString(carrier.mobileCountryCode()));
    send("  Mobile Network Code: " + safeToString(carrier.mobileNetworkCode()));
    send("  ISO Country Code: " + safeToString(carrier.isoCountryCode()));
    send("  Allows VOIP: " + carrier.allowsVOIP());
}
