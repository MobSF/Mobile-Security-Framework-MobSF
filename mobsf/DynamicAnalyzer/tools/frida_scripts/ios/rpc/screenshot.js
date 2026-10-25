getScreenshot: function (){
    let cachedApi = null;
    const CGFloat = (Process.pointerSize === 4) ? 'float' : 'double';
    const CGSize = [CGFloat, CGFloat];
    function getUIKitApi() {
    if (cachedApi !== null) return cachedApi;

    const uikit = Process.getModuleByName('UIKit');
    cachedApi = {
        UIApplication: ObjC.classes.UIApplication,
        UIWindow: ObjC.classes.UIWindow,
        NSThread: ObjC.classes.NSThread,
        UIGraphicsBeginImageContextWithOptions: new NativeFunction(
        uikit.getExportByName('UIGraphicsBeginImageContextWithOptions'),
        'void', [CGSize, 'bool', CGFloat]
        ),
        UIGraphicsEndImageContext: new NativeFunction(
        uikit.getExportByName('UIGraphicsEndImageContext'),
        'void', []
        ),
        UIGraphicsGetImageFromCurrentImageContext: new NativeFunction(
        uikit.getExportByName('UIGraphicsGetImageFromCurrentImageContext'),
        'pointer', []
        ),
        UIImagePNGRepresentation: new NativeFunction(
        uikit.getExportByName('UIImagePNGRepresentation'),
        'pointer', ['pointer']
        )
    };

    return cachedApi;
    }

    function performOnMainThread(action) {
    const api = getUIKitApi();
    if (api.NSThread.isMainThread()) {
        action();
    } else {
        ObjC.schedule(ObjC.mainQueue, action);
    }
    }

    function captureScreenshot(view = null) {
    const api = getUIKitApi();

    if (!view) {
        const windows = api.UIApplication.sharedApplication().windows();
        for (let i = 0; i < windows.count(); i++) {
        const win = windows.objectAtIndex_(i);
        if (win.isKeyWindow()) {
            view = win;
            break;
        }
        }
    }

    if (!view) {
        console.log("❌ No key window found.");
        return;
    }

    const bounds = view.bounds();
    const size = bounds[1];
    api.UIGraphicsBeginImageContextWithOptions(size, 0, 0);
    view.drawViewHierarchyInRect_afterScreenUpdates_(bounds, true);
    const image = api.UIGraphicsGetImageFromCurrentImageContext();
    api.UIGraphicsEndImageContext();

    const pngData = new ObjC.Object(api.UIImagePNGRepresentation(image));
    const bytePtr = pngData.bytes();
    const buffer = bytePtr.readByteArray(pngData.length());
    const path = "/tmp/screenshot.png";
    const f = new File(path, "wb");
    f.write(buffer);
    f.flush();
    f.close();

    send("✅ Screenshot Captured");
    }


    function capture(){
        performOnMainThread(() => {
            try {
                captureScreenshot();
            } catch (e) {
                console.log("❌ Error capturing screenshot: " + e.message);
            }
        });
    }
    capture();
}