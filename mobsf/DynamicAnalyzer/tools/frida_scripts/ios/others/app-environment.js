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
}
app_env_info();