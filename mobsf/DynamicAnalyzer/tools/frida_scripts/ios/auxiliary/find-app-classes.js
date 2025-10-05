function listAppClasses() {
    if (!ObjC.available) {
        send("❌ Objective-C runtime is not available.");
        return;
    }

    try {
        const loaded = ObjC.enumerateLoadedClassesSync();
        let count = 0;

        for (const imagePath in loaded) {
            if (!imagePath.includes(".app")) continue;

            const classList = loaded[imagePath];
            send(`📦 Classes in ${imagePath}: ${classList.length}`);

            for (const className of classList) {
                send(`[AUXILIARY] ${className}`);
                count++;
            }
        }

        send(`✅ Total app-owned classes found: ${count}`);
    } catch (err) {
        send("❌ Error during enumeration: " + err.message);
    }
}

setImmediate(listAppClasses);
