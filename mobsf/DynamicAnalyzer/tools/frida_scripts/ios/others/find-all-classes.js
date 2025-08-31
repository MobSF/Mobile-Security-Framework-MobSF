function run_show_classes_of_app() {
    send("Enumerating Classes");

    try {
        const classesByImage = ObjC.enumerateLoadedClassesSync();
        let count = 0;

        // Filter to only app-specific modules (e.g., containing ".app")
        for (const imageName in classesByImage) {
            if (!imageName.includes(".app")) continue;

            const classList = classesByImage[imageName];

            for (const className of classList) {
                send("[AUXILIARY] " + className);
                count++;
            }
        }

        send("[AUXILIARY] \n  Classes found: " + count);
    } catch (err) {
        send("❌ Error during class enumeration: " + err.message);
    }

    send("Completed Enumerating Classes");
}

function show_classes_of_app() {
    setImmediate(run_show_classes_of_app);
}

show_classes_of_app();