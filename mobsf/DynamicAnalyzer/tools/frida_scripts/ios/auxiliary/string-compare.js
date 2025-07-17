function captureStringCompare() {
  if (!ObjC.available) {
    send("❌ Objective-C runtime not available.");
    return;
  }

  try {
    const cls = ObjC.classes.__NSCFString;
    if (!cls || !cls["- isEqualToString:"]) {
      send("❌ __NSCFString or method -isEqualToString: not available.");
      return;
    }

    Interceptor.attach(cls["- isEqualToString:"].implementation, {
      onEnter: function (args) {
        try {
          const str1 = new ObjC.Object(args[0]).toString();
          const str2 = new ObjC.Object(args[2]).toString();
          send(`[AUXILIARY] __NSCFString -isEqualToString:\n  ↳ string 1: ${str1}\n  ↳ string 2: ${str2}`);
        } catch (e) {
          send(`⚠️ Failed to capture comparison: ${e.message}`);
        }
      }
    });
  } catch (err) {
    send("❌ Hooking __NSCFString failed: " + err.message);
  }
}

function captureStringCompare2() {
  if (!ObjC.available) return;

  try {
    const cls = ObjC.classes.NSTaggedPointerString;
    if (!cls || !cls["- isEqualToString:"]) {
      send("❌ NSTaggedPointerString or method -isEqualToString: not available.");
      return;
    }

    Interceptor.attach(cls["- isEqualToString:"].implementation, {
      onEnter: function (args) {
        try {
          const str1 = new ObjC.Object(args[0]).toString();
          const str2 = new ObjC.Object(args[2]).toString();
          send(`[AUXILIARY] NSTaggedPointerString -isEqualToString:\n  ↳ string 1: ${str1}\n  ↳ string 2: ${str2}`);
        } catch (e) {
          send(`⚠️ Failed to capture tagged comparison: ${e.message}`);
        }
      }
    });
  } catch (err) {
    send("❌ Hooking NSTaggedPointerString failed: " + err.message);
  }
}

try {
  setImmediate(captureStringCompare);
} catch (err) {
  send("❌ Error scheduling captureStringCompare: " + err.message);
}

try {
  setImmediate(captureStringCompare2);
} catch (err) {
  send("❌ Error scheduling captureStringCompare2: " + err.message);
}
