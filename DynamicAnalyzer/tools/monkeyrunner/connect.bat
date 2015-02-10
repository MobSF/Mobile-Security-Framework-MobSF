cd C:\\Xenotix ASDA\\APK Analyzer\\App_Data\\tools\\monkeyrunner
adb.exe kill-server
adb.exe start-server
ping -n 3 127.0.0.1 > NULL
adb.exe connect 10.118.7.26
adb.exe wait-for-device
adb.exe shell mount -o rw,remount -t rfs /dev/block/sda6 /system
adb.exe install "C:\\Xenotix ASDA\\APK Analyzer\\App_Data\\uploads\\51299266ECBC1B26D8CED685BB1FEA2E0D1478.apk"
adb.exe shell am start -n com.earn.rewards.rewardometer/com.earn.rewards.rewardometer.SplashScreen
