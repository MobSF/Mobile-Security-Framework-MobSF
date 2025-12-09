function dumpMethodsOfClass(className) {
    if (!ObjC.available) {
        send("❌ Objective-C runtime not available");
        return;
    }

    try {
        const klass = ObjC.classes[className];
        if (!klass) {
            send(`❌ Class not found: ${className}`);
            return;
        }

        send(`✅ Found class: ${className}`);
        const methods = klass.$methods; // includes inherited and static methods

        if (methods.length === 0) {
            send(`[AUXILIARY] ⚠️ No methods found for class ${className}`);
            return;
        }

        send(`[AUXILIARY] 🧬 Methods for ${className} (${methods.length} total):`);
        methods.forEach(method => send(`  [-] ${method}`));
    } catch (err) {
        send(`❌ Error dumping methods for ${className}: ${err.message}`);
    }
}

setImmediate(dumpMethodsOfClass, "{{CLASS}}");