/* 
    Description: iOS WebView Observer
    Usage: frida -U -f XXX -l ios-webview-observer.js
    Credit: MASTG
    Src: https://github.com/rsenet/FriList/blob/main/01_Observer/Network/Webview/ios-webview-observer.js
    Link:
        https://developer.apple.com/documentation/uikit/uiwebview
        https://developer.apple.com/documentation/webkit/wkwebview
        https://developer.apple.com/documentation/safariservices/sfsafariviewcontroller
*/

if (ObjC.available) 
{
    ObjC.choose(ObjC.classes['UIWebView'], 
    {
        onMatch: function (ui) 
        {
            console.log('onMatch: ', ui);
            console.log('URL: ', ui.request().toString());
        },
        onComplete: function () 
        {
            console.log('done for UIWebView!');
        }
    });

    ObjC.choose(ObjC.classes['WKWebView'], 
    {
        onMatch: function (wk) 
        {
            console.log('onMatch: ', wk);
            console.log('URL: ', wk.URL().toString());
            console.log('javaScriptEnabled: ', wk.configuration().preferences().javaScriptEnabled());
            console.log('allowFileAccessFromFileURLs: ', wk.configuration().preferences().valueForKey_('allowFileAccessFromFileURLs').toString());
            console.log('hasOnlySecureContent: ', wk.hasOnlySecureContent().toString());
            console.log('allowUniversalAccessFromFileURLs: ', wk.configuration().valueForKey_('allowUniversalAccessFromFileURLs').toString());
        },
        onComplete: function () 
        {
            console.log('done for WKWebView!');
        }
    });

    ObjC.choose(ObjC.classes['SFSafariViewController'], 
    {
        onMatch: function (sf) 
        {
            console.log('onMatch: ', sf);
        },
        onComplete: function () 
        {
            console.log('done for SFSafariViewController!');
        }
    });
} 
else 
{
    console.log("Objective-C Runtime is not available!");
}