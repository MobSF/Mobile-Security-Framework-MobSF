function hook_class_method(className, methodName) {
    try {
        const method = ObjC.classes[className][methodName];
        const impl = method?.implementation;

        if (!impl || impl.isNull()) {
            send(`⚠️ Skipping ${methodName} — no implementation.`);
            return;
        }

        Interceptor.attach(impl, {
            onEnter: function (args) {
                send(`[AUXILIARY] Detected call to: ${className} -> ${methodName}`);

                for (let i = 0; i < method.argumentTypes.length; i++) {
                    try {
                        const arg = args[i];
                        if (arg.isNull && arg.isNull()) {
                            send(`[AUXILIARY]   arg[${i}]: null`);
                        } else {
                            try {
                                const str = arg.readUtf8String();
                                send(`[AUXILIARY]   arg[${i}]: "${str}"`);
                            } catch {
                                send(`[AUXILIARY]   arg[${i}]: ${arg}`);
                            }
                        }
                    } catch (err) {
                        send(`[AUXILIARY]   arg[${i}]: <error reading: ${err.message}>`);
                    }
                }
            },

            onLeave: function (retval) {
                try {
                    if (retval.isNull && retval.isNull()) {
                        send(`[AUXILIARY]   return: null`);
                    } else {
                        send(`[AUXILIARY]   return: ${retval}`);
                    }
                } catch (err) {
                    send(`[AUXILIARY]   return: <error reading: ${err.message}>`);
                }
            }
        });
    } catch (err) {
        send(`❌ Failed to hook ${className} -> ${methodName}: ${err.message}`);
    }
}

function run_hook_all_methods_of_specific_class(className) {
    send(`📦 Started hooking all methods of: ${className}`);

    try {
        if (!ObjC.classes.hasOwnProperty(className)) {
            send(`❌ Class not found: ${className}`);
            return;
        }

        const methods = ObjC.classes[className].$ownMethods;

        for (const methodName of methods) {
            send(`[AUXILIARY] Hooking: ${methodName}`);
            hook_class_method(className, methodName);
        }

        send("✅ Completed hooking all methods.");
    } catch (err) {
        send(`❌ Error while hooking class: ${err.message}`);
    }
}

function hook_all_methods_of_specific_class(classNameArg) {
    try {
        setImmediate(run_hook_all_methods_of_specific_class, classNameArg);
    } catch (err) {
        send(`❌ Unexpected error: ${err.message}`);
    }
}

// Replace '{{CLASS}}' with the class name you want to hook
hook_all_methods_of_specific_class('{{CLASS}}');
