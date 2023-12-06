/* 
    Description: ReactNatice Emulator Detection Bypass frida script
    Credit: https://twitter.com/KhantZero

    Src: https://github.com/rsenet/FriList/blob/main/02_SecurityBypass/DebugMode_Emulator/react-native-emulator-detection-bypass.js
    Link:
        https://github.com/react-native-device-info/react-native-device-info/blob/master/android/src/main/java/com/learnium/RNDeviceInfo/RNDeviceModule.java
*/

if (Java.available) 
{
    Java.perform(function() 
    {
        try 
        {
            var Activity = Java.use("com.learnium.RNDeviceInfo.RNDeviceModule");
            Activity.isEmulatorSync.implementation = function() 
            {
                return(false);
            }
        } 
        catch (error) 
        {
            console.log((error.stack));
        }
    });
} 
else 
{
    console.log("[-] Java is Not available");
}