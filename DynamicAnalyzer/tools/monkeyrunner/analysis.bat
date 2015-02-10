ping -n 11 127.0.0.1 > NULL
adb.exe shell screencap -p /system/screen.png
adb.exe shell am startservice com.appxpose.app/.AppXposeService
adb.exe pull /system/screen.png "C:\\Xenotix ASDA\\APK Analyzer\\App_Data\\tools\\monkeyrunner\\Results\\screenshot51299266ECBC1B26D8CED685BB1FEA2E0D1478.png"
adb.exe logcat -d dalvikvm:W ActivityManager:I > Results\logcat51299266ECBC1B26D8CED685BB1FEA2E0D1478.txt
adb.exe shell dumpsys > Results\dump51299266ECBC1B26D8CED685BB1FEA2E0D1478.txt
adb shell am force-stop com.earn.rewards.rewardometer
