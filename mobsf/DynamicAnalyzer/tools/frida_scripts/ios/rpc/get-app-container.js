getContainer: function () {
    try{
        var libPath = ObjC.classes.NSFileManager.defaultManager().URLsForDirectory_inDomains_(5, 1).lastObject().path().toString();
        const sep = 'Library'
        var split = libPath.split(sep);
        var rsplit = 1 ? [ split.slice(0, -1).join(sep) ].concat(split.slice(-1)) : split;
        return rsplit[0];
    } catch(err) {
        return false;
    }
}