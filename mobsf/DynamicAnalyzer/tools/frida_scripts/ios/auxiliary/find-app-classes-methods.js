function run_show_app_classes_methods_only() {
    send("Started: Find App's Classes and Methods");

    try {
        const free = new NativeFunction(
            Process.getModuleByName('libc++abi.dylib').getExportByName('free'),
            'void',
            ['pointer']
        );

        const copyClassNamesForImage = new NativeFunction(
            Process.getModuleByName('libobjc.A.dylib').getExportByName('objc_copyClassNamesForImage'),
            'pointer',
            ['pointer', 'pointer']
        );

        const path = ObjC.classes.NSBundle.mainBundle().executablePath().UTF8String();
        const pPath = Memory.allocUtf8String(path);
        const pCount = Memory.alloc(Process.pointerSize);
        pCount.writeUInt(0);

        const pClasses = copyClassNamesForImage(pPath, pCount);
        const count = pCount.readUInt();

        send(`[AUXILIARY] Classes found in app image: ${count}`);

        for (let i = 0; i < count; i++) {
            const classPtr = pClasses.add(i * Process.pointerSize).readPointer();
            const className = classPtr.readUtf8String();

            if (!ObjC.classes.hasOwnProperty(className)) {
                continue;
            }

            const klass = ObjC.classes[className];
            send(`[AUXILIARY] Class: ${className}`);

            const methods = klass.$ownMethods;
            for (const methodName of methods) {
                send(`  [-] Method: ${methodName}`);

                try {
                    const method = klass[methodName];
                    send(`      ├─ Args: ${method.argumentTypes}`);
                    send(`      └─ Return: ${method.returnType}`);
                } catch (err) {
                    send(`      ⚠️  Failed to inspect method: ${err.message}`);
                }
            }
        }

        free(pClasses);
    } catch (err) {
        send(`❌ Error: ${err.message}`);
    }

    send("Completed: Find App's Classes");
}

function show_app_classes_methods_only() {
    try {
        setImmediate(run_show_app_classes_methods_only);
    } catch (err) {
        send(`❌ Unexpected error: ${err.message}`);
    }
}

show_app_classes_methods_only();
