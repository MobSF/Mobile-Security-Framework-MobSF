/* 
    Description: iOS Enable WebInspector
    Credit: leolashkevych
    Src: https://github.com/rsenet/FriList/blob/main/01_Observer/Network/WebInspector/ios-webinspector-enable.js
    Enable WebView debugging for all iOS apps. Before running the script, enable Web Inspector in Safari settings
    (see https://github.com/OWASP/owasp-mastg/blob/master/Document/0x06h-Testing-Platform-Interaction.md#safari-web-inspector).
    Jailbreak required.
*/

const CFRelease = new NativeFunction(Module.findExportByName(null, 'CFRelease'), 'void', ['pointer']);
const CFStringGetCStringPtr = new NativeFunction(Module.findExportByName(null, 'CFStringGetCStringPtr'),'pointer', ['pointer', 'uint32']);
const kCFStringEncodingUTF8 = 0x08000100;
const SecTaskCopyValueForEntitlement = Module.findExportByName(null, 'SecTaskCopyValueForEntitlement');

const entitlements = [
    'com.apple.security.get-task-allow',
    'com.apple.webinspector.allow',
    'com.apple.private.webinspector.allow-remote-inspection',
    'com.apple.private.webinspector.allow-carrier-remote-inspection'
];

Interceptor.attach(SecTaskCopyValueForEntitlement, 
{
    onEnter: function(args) 
    {
        const pEntitlement = CFStringGetCStringPtr(args[1], kCFStringEncodingUTF8)
        const entitlement = Memory.readUtf8String(pEntitlement)
        
        if (entitlements.indexOf(entitlement) > -1) 
        {
            this.shouldOverride = true
            this.entitlement = entitlement
        }
    },

    onLeave: function(retVal) 
    {
        if (this.shouldOverride) 
        {
            console.log('Overriding value for entitlement: ', this.entitlement)
            if (!retVal.isNull()) 
            {
                console.log('Old value: ', retVal)
                CFRelease(retVal)
            }
            retVal.replace(ObjC.classes.NSNumber.numberWithBool_(1));
            console.log('New value: ', retVal)
        }
    }
});