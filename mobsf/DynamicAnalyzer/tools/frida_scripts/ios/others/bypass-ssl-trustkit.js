/* 
    Description: iOS TrustKit Certificate Pinning ByPass
    Usage: frida -U -f XXX -l ios-trustkit-pinning-bypass.js
    Credit: Unknown
    Src: https://github.com/rsenet/FriList/blob/main/02_SecurityBypass/CertificatePinning/ios-trustkit-pinning-bypass.js
*/

if (ObjC.available) 
{
    console.log("SSLUnPinning Enabled");

    for (var className in ObjC.classes) 
    {
        if (ObjC.classes.hasOwnProperty(className)) 
        {
            if (className == "TrustKit") 
            {
                console.log("Found our target class : " + className);
                var hook = ObjC.classes.TrustKit["+ initSharedInstanceWithConfiguration:"];

                Interceptor.replace(hook.implementation, new NativeCallback(function() 
                {
                    console.log("Hooking TrustKit");
                    return;
                }, 'int', []));
            }
        }
    }
} 
else 
{
    console.log("Objective-C Runtime is not available!");
}