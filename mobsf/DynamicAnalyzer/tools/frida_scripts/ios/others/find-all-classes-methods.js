function run_show_classes_methods_of_app() {
    send("Enumerating Classes and Methods");

    let count = 0;

    try {
        const classesByImage = ObjC.enumerateLoadedClassesSync();

        for (const imageName in classesByImage) {
            // Only inspect classes from the app itself
            if (!imageName.includes(".app")) continue;

            const classList = classesByImage[imageName];

            for (const className of classList) {
                try {
                    const klass = ObjC.classes[className];
                    if (!klass) continue;

                    send("[AUXILIARY] Class: " + className);
                    count++;

                    const methods = klass.$ownMethods;

                    for (let i = 0; i < methods.length; i++) {
                        const methodName = methods[i];
                        send("[AUXILIARY] \t Method: " + methodName);

                        try {
                            const method = klass[methodName];
                            send("[AUXILIARY] \t\tArguments Type: " + method.argumentTypes);
                            send("[AUXILIARY] \t\tReturn Type: " + method.returnType);
                        } catch (err) {
                            send("[AUXILIARY] \t\t Error retrieving types: " + err.message);
                        }
                    }
                } catch (err) {
                    send("[AUXILIARY] Error accessing class: " + className + " — " + err.message);
                }
            }
        }

        send("[AUXILIARY] \n  Classes found: " + count);
    } catch (err) {
        send("Failed to enumerate classes: " + err.message);
    }

    send("Completed Enumerating Methods of All Classes");
}

function show_classes_methods_of_app() {
    setImmediate(run_show_classes_methods_of_app);
}

show_classes_methods_of_app();
