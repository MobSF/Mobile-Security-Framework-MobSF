function detect_network_libraries() {
    if (!ObjC.available) {
        send("❌ Objective-C runtime is not available.");
        return;
    }

    const knownLibs = {
        "NSURLSession": "Apple (Modern HTTP API)",
        "NSURLConnection": "Apple (Deprecated HTTP API)",
        "CFNetwork": "Apple (C-level networking)",
        "AFURLSessionManager": "AFNetworking (ObjC)",
        "AFHTTPSessionManager": "AFNetworking (ObjC)",
        "Alamofire.Session": "Alamofire (Swift)",
        "Alamofire.Request": "Alamofire (Swift)",
        "SDWebImageDownloader": "SDWebImage (HTTP Image Fetcher)",
        "SocketRocket.SRWebSocket": "SocketRocket (WebSockets)",
        "GRPCClient": "gRPC (Objective-C)",
        "GTMSessionFetcher": "Google API Client",
        "FIRMessagingConnection": "Firebase Messaging",
        "FBSDKGraphRequest": "Facebook SDK",
        "AWSNetworking": "AWS iOS SDK",
        "ASIHTTPRequest": "ASIHTTPRequest (Legacy ObjC)"
    };

    send("🔍 Scanning for known networking libraries...");

    const present = [];

    for (const className in knownLibs) {
        if (ObjC.classes.hasOwnProperty(className)) {
            present.push({ name: className, source: knownLibs[className] });
        }
    }

    if (present.length === 0) {
        send("❌ No known networking classes found.");
    } else {
        send("✅ Detected networking classes/libraries:");
        present.forEach(entry => {
            send(`   • ${entry.name}  ➜  ${entry.source}`);
        });
    }

    // Extra: enumerate loaded modules that may hint at networking libs
    const loadedModules = Process.enumerateModules();
    const moduleHints = ["AFNetworking", "Alamofire", "CFNetwork", "GTMSession", "SocketRocket", "libcurl", "libgrpc"];

    loadedModules.forEach(mod => {
        moduleHints.forEach(hint => {
            if (mod.name.indexOf(hint) !== -1) {
                send(`📦 Loaded module: ${mod.name} (possible: ${hint})`);
            }
        });
    });
}

setImmediate(detect_network_libraries);
