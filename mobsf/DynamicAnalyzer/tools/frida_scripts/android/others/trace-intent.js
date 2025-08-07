Java.perform(function () {
    // Hook the startActivity method in the Activity class
    var Activity = Java.use("android.app.Activity");

    Activity.startActivity.overload("android.content.Intent").implementation = function (intent) {
        send("Intercepted startActivity with Intent:");

        // Dump the Intent details
        dumpIntent(intent);

        // Call the original startActivity method to ensure normal behavior
        this.startActivity(intent);
    };

    // Function to dump intent details
    function dumpIntent(intent) {
        // Action
        var action = intent.getAction();
        send("  Action: " + (action ? action : "None"));

        // Data URI
        var dataUri = intent.getDataString();
        send("  Data URI: " + (dataUri ? dataUri : "None"));

        // Component (target package and class)
        var component = intent.getComponent();
        if (component) {
            send("  Component:");
            send("    Package: " + component.getPackageName());
            send("    Class: " + component.getClassName());
        } else {
            send("  Component: None");
        }

        // Flags
        var flags = intent.getFlags();
        send("  Flags: " + flags);

        // Extras
        var extras = intent.getExtras();
        if (extras) {
            send("  Extras:");
            var iterator = extras.keySet().iterator();
            while (iterator.hasNext()) {
                var key = iterator.next();
                var value = extras.get(key);
                if (value !== null) {
                    send("    " + key + ": " + valueToString(value));
                }
            }
        } else {
            send("  Extras: None");
        }
    }

    // Helper function to convert intent extras to string for logging
    function valueToString(value) {
        // Check if the value is a Bundle and handle it accordingly
        if (value.getClass().getName() === "android.os.Bundle") {
            return bundleToString(Java.cast(value, Java.use("android.os.Bundle")));
        }
        return value.toString();
    }

    // Function to handle nested Bundles (if any)
    function bundleToString(bundle) {
        var result = "{";
        var iterator = bundle.keySet().iterator();
        while (iterator.hasNext()) {
            var key = iterator.next();
            var value = bundle.get(key);
            result += key + ": " + (value !== null ? value.toString() : "null") + ", ";
        }
        result = result.slice(0, -2); // Remove trailing comma and space
        result += "}";
        return result;
    }
});
