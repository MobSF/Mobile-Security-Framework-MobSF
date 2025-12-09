function findClasses(pattern) {
    const foundClasses = [];

    if (!ObjC.available) {
        send("❌ Objective-C runtime is not available.");
        return foundClasses;
    }

    try {
        const classMap = ObjC.enumerateLoadedClassesSync();

        for (const imagePath in classMap) {
            if (!imagePath.includes(".app")) continue;  // App-only classes

            for (const className of classMap[imagePath]) {
                if (pattern.test(className)) {
                    foundClasses.push(className);
                }
            }
        }
    } catch (err) {
        send("❌ Error during class enumeration: " + err.message);
    }

    return foundClasses;
}

function getMatches() {
    try {
        const pattern = /{{PATTERN}}/i;  // Replace this with your actual search
        send("🔍 Searching for class names matching pattern: " + pattern);

        const matches = findClasses(pattern);

        if (matches.length > 0) {
            send(`✅ Found [${matches.length}] match(es):`);
            matches.forEach(className => send("[AUXILIARY] " + className));
        } else {
            send("❌ No matches found.");
        }
    } catch (err) {
        send("❌ Error during pattern match: " + err.message);
    }
}

try {
    setImmediate(getMatches);
} catch (err) {
    send("❌ Script scheduling failed: " + err.message);
}
