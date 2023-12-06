send("[*] Started: Dumping UI")
if (ObjC.available)
{
    var keyWin = ObjC.classes.UIWindow.keyWindow()
    if (keyWin)
    {
        console.log(keyWin.recursiveDescription().toString());
    }
}
else
{
    send("Objective-C Runtime is not available!");
}
