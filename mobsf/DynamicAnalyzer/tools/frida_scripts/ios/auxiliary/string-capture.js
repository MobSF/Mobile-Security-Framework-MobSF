function captureString() {
  if (!ObjC.available) {
    send("❌ Objective-C runtime is not available");
    return;
  }

  try {
    const classRef = ObjC.classes.NSString;
    if (!classRef || !classRef['+ stringWithUTF8String:']) {
      send("❌ NSString +stringWithUTF8String: not found");
      return;
    }

    send("📦 Hooking NSString +stringWithUTF8String:");

    Interceptor.attach(classRef['+ stringWithUTF8String:'].implementation, {
      onLeave: function (retval) {
        if (retval.isNull()) return;

        try {
          const str = new ObjC.Object(retval).toString();
          send("[AUXILIARY] [NSString stringWithUTF8String:] -> " + str);
        } catch (err) {
          send("[AUXILIARY] ⚠️ Failed to convert NSString: " + err.message);
        }
      }
    });
  } catch (err) {
    send("❌ Error while hooking NSString: " + err.message);
  }
}

try {
  setImmediate(captureString);
} catch (err) {
  send("❌ Unexpected error: " + err.message);
}
