// Source: https://codeshare.frida.re/@leolashkevych/android-deep-link-observer/
Java.perform(function() {
    var Intent = Java.use("android.content.Intent");
    Intent.getData.implementation = function() {
        var action = this.getAction() !== null ? this.getAction().toString() : false;
        if (action) {
            console.log("[*] Intent.getData() was called");
            console.log("[*] Activity: " + this.getComponent().getClassName());
            console.log("[*] Action: " + action);
            var uri = this.getData();
            if (uri !== null) {
                console.log("\n[*] Data");
                uri.getScheme() && console.log("- Scheme:\t" + uri.getScheme() + "://");
                uri.getHost() && console.log("- Host:\t\t/" + uri.getHost());
                uri.getQuery() && console.log("- Params:\t" + uri.getQuery());
                uri.getFragment() && console.log("- Fragment:\t" + uri.getFragment());
                console.log("\n\n");
            } else {
                console.log("[-] No data supplied.");
            }
        }
        return this.getData();
    }
});