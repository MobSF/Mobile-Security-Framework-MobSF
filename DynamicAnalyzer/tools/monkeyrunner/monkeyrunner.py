from com.android.monkeyrunner import MonkeyRunner, MonkeyDevice
import subprocess
import logging
import sys,os
apkpath=sys.argv[1]
pkgname=sys.argv[2]
mainactivity=sys.argv[3]
filename=sys.argv[4]

# Connects to the current device, returning a MonkeyDevice object
device=None
while device==None:
     try:
          device = MonkeyRunner.waitForConnection()
          print "Connected to Device"
     except:
          pass


# Installs the Android package. Returns Boolean.
if (device.installPackage(apkpath)):
     print "Installing : "+ str(apkpath)
else:
     print "Installation Failed"

# sets the name of the component to start
runComponent = pkgname + '/' + mainactivity
# Runs the component
device.startActivity(component=runComponent)
process = subprocess.Popen(["adb", "shell", "am", "start", "-n","-w", runComponent], stdout=subprocess.PIPE)
out, err = process.communicate()
# Presses the Menu button
device.press('KEYCODE_MENU', MonkeyDevice.DOWN_AND_UP)

# Takes a screenshot
MonkeyRunner.sleep(6)
result = device.takeSnapshot()
print "Screenshot Saved"
# Writes the screenshot to a file
result.writeToFile("Results\\"+filename+'.png','png')
MonkeyRunner.sleep(5)
print "Taking Logcat Dumps"
os.system("adb.exe logcat -d dalvikvm:W ActivityManager:I >Results\logcat.txt")
print "Taking Memory Dumps"
os.system("adb.exe shell dumpsys >Results\dump.txt")
