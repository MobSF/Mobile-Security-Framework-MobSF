/*
    Description: iOS TrustKit Certificate Pinning ByPass
    Updated for Frida 17+
*/

function bypassTrustKit() {
    if (!ObjC.available) {
        send("❌ Objective-C Runtime is not available!");
        return;
    }

    send("🔐 SSLUnPinning Enabled");

    try {
        const classMap = ObjC.enumerateLoadedClassesSync();
        let found = false;

        for (const image in classMap) {
            for (const className of classMap[image]) {
                if (className === "TrustKit") {
                    found = true;

                    send("✅ Found TrustKit class in: " + image);

                    const method = ObjC.classes.TrustKit["+ initSharedInstanceWithConfiguration:"];
                    if (!method || method.implementation.isNull()) {
                        send("❌ TrustKit method not found or invalid.");
                        return;
                    }

                    Interceptor.replace(method.implementation, new NativeCallback(function () {
                        send("✅ Hooked TrustKit: +initSharedInstanceWithConfiguration:");
                        return;
                    }, 'int', []));

                    send("✅ TrustKit bypass hook installed.");
                    return;
                }
            }
        }

        if (!found) {
            send("❌ TrustKit class not found.");
        }
    } catch (err) {
        send("❌ Error during TrustKit bypass: " + err.message);
    }
}

setImmediate(bypassTrustKit);
