function getPath(nspath){
    return ObjC.classes.NSFileManager.defaultManager().URLsForDirectory_inDomains_(nspath, 1).lastObject().path().toString();
}

String.prototype.rsplit = function(sep, maxsplit) {
    var split = this.split(sep);
    return maxsplit ? [ split.slice(0, -maxsplit).join(sep) ].concat(split.slice(-maxsplit)) : split;
}

function app_env_info() {
    send('App Executable Path: ' +  ObjC.classes.NSBundle.mainBundle().executablePath().toString());
    var mainBundlePath = String(ObjC.classes.NSBundle.mainBundle())
    mainBundlePath = mainBundlePath.substring(0, mainBundlePath.indexOf(">"))
    mainBundlePath = mainBundlePath.substring(mainBundlePath.indexOf("<") + 1)
    send('App Bundle Path: ' + mainBundlePath);
    var libPath = getPath(5)
    send('App Container Path: ' + libPath.rsplit('Library', 1)[0]);
    send('App Document Path: ' + getPath(9));
    send('App Library Path: ' + libPath);
    send('App Cache Path: ' + getPath(13));
    
    // try { 
    //     //Credit: https://github.com/iddoeldor/frida-snippets#find-ios-application-uuid
    //     var mainBundleContainerPathIdentifier = "";
    //     var bundleIdentifier = String(ObjC.classes.NSBundle.mainBundle().objectForInfoDictionaryKey_('CFBundleIdentifier'));
    //     var path_prefix = "/var/mobile/Containers/Data/Application/";
    //     var plist_metadata = "/.com.apple.mobile_container_manager.metadata.plist";
    //     var folders = ObjC.classes.NSFileManager.defaultManager().contentsOfDirectoryAtPath_error_(path_prefix, NULL);
    //     if (!folders){
    //         send('Unable to identify App Container Path.')
    //     } else {
    //         for (var i = 0, l = folders.count(); i < l; i++) {
    //             var uuid = folders.objectAtIndex_(i);
    //             var metadata = path_prefix + uuid + plist_metadata;
    //             var dict = ObjC.classes.NSMutableDictionary.alloc().initWithContentsOfFile_(metadata);
    //             var enumerator = dict.keyEnumerator();
    //             var key;
    //             while ((key = enumerator.nextObject()) !== null) {
    //                 if (key == 'MCMMetadataIdentifier') {
    //                     var appId = String(dict.objectForKey_(key));
    //                     if (appId.indexOf(bundleIdentifier) != -1) {
    //                         mainBundleContainerPathIdentifier = uuid;
    //                         break;
    //                     }
    //                 }
    //             }
    //         }
    //         send("App Container Path: /var/mobile/Containers/Data/Application/" + mainBundleContainerPathIdentifier + "/");
    //     }
    // } catch (e){
    // }

}
app_env_info()
