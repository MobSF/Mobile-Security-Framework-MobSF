from com.android.monkeyrunner import MonkeyRunner, MonkeyDevice
import subprocess
import logging
import sys
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
process = subprocess.Popen(["adb", "shell", "am", "start", "-n", runComponent], stdout=subprocess.PIPE)
out, err = process.communicate()
# Presses the Menu button
#device.press('KEYCODE_MENU', MonkeyDevice.DOWN_AND_UP)

# Takes a screenshot
MonkeyRunner.sleep(2)
result = device.takeSnapshot()
print "Screenshot Saved"
# Writes the screenshot to a file
result.writeToFile(filename+'.png','png')
'''

#Open the adb logcat
adb = Popen(["adb", "logcat", "DroidBox:W", "dalvikvm:W", "ActivityManager:I"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
#Wait for the application to start
while 1:
     try:
          logcatInput = adb.stdout.readline()
          if not logcatInput:
               raise Exception("We have lost the connection with ADB.")
          #Application started?
          if (stringApplicationStarted in logcatInput):
               applicationStarted = 1
               break;
     except:
	break;
if (applicationStarted == 0):
     print("Analysis has not been done.")
#Kill ADB, otherwise it will never terminate
     os.kill(adb.pid, signal.SIGTERM)
     sys.exit(1)
print("Application started")
print("Analyzing the application during %s seconds..." % (duration if (duration !=0) else "infinite time"))
count = CountingThread()
count.start()
timeStamp = time.time()
if duration:
     signal.signal(signal.SIGALRM, interruptHandler)
     signal.alarm(duration)
	#Collect DroidBox logs
while 1:
     try:
          logcatInput = adb.stdout.readline() 
          if not logcatInput:
               raise Exception("We have lost the connection with ADB.")
          boxlog = logcatInput.split('DroidBox:')
          if len(boxlog) > 1:
               try:
                    load = json.loads(decode(boxlog[1]))
                    # DexClassLoader
                    if load.has_key('DexClassLoader'):
                         load['DexClassLoader']['type'] = 'dexload'
                         dexclass[time.time() - timeStamp] = load['DexClassLoader']
                         count.increaseCount()
                         # service started
                    if load.has_key('ServiceStart'):
                         load['ServiceStart']['type'] = 'service'
                         servicestart[time.time() - timeStamp] = load['ServiceStart']
                         count.increaseCount()
               except ValueError:
                    pass
     except:
          try:
               count.stopCounting()
               count.join()
          finally:
               break;
	  

			# received data from net
			if load.has_key('RecvNet'):   
			    host = load['RecvNet']['srchost']
			    port = load['RecvNet']['srcport']

			    recvnet[time.time() - timeStamp] = recvdata = {'type': 'net read', 'host': host, 'port': port, 'data': load['RecvNet']['data']}
			    count.increaseCount()

			# fdaccess
			if load.has_key('FdAccess'):
			    accessedfiles[load['FdAccess']['id']] = hexToStr(load['FdAccess']['path'])

			# file read or write     
			if load.has_key('FileRW'):
			    load['FileRW']['path'] = accessedfiles[load['FileRW']['id']]
			    if load['FileRW']['operation'] == 'write':
			        load['FileRW']['type'] = 'file write'
			    else:
			        load['FileRW']['type'] = 'file read'

			    fdaccess[time.time()-timeStamp] = load['FileRW']
			    count.increaseCount()

			# opened network connection log
			if load.has_key('OpenNet'):
			    opennet[time.time()-timeStamp] = load['OpenNet']
			    count.increaseCount()

			# closed socket
			if load.has_key('CloseNet'):
			    closenet[time.time()-timeStamp] = load['CloseNet']
			    count.increaseCount()

			# outgoing network activity log
			if load.has_key('SendNet'):
			    load['SendNet']['type'] = 'net write'
			    sendnet[time.time()-timeStamp] = load['SendNet']
			    
			    count.increaseCount()                                          

			# data leak log
			if load.has_key('DataLeak'):
			    my_time = time.time()-timeStamp
			    load['DataLeak']['type'] = 'leak'
			    load['DataLeak']['tag'] = getTags(int(load['DataLeak']['tag'], 16))
			    dataleaks[my_time] = load['DataLeak']
			    count.increaseCount()

			    if load['DataLeak']['sink'] == 'Network':
				load['DataLeak']['type'] = 'net write'
				sendnet[my_time] = load['DataLeak']
				count.increaseCount()

			    elif load['DataLeak']['sink'] == 'File':	
				load['DataLeak']['path'] = accessedfiles[load['DataLeak']['id']]
				if load['DataLeak']['operation'] == 'write':
				    load['DataLeak']['type'] = 'file write'
				else:
				    load['DataLeak']['type'] = 'file read'

				fdaccess[my_time] = load['DataLeak']
				count.increaseCount()

			    elif load['DataLeak']['sink'] == 'SMS':
				load['DataLeak']['type'] = 'sms'
				sendsms[my_time] = load['DataLeak']
				count.increaseCount()

			# sent sms log
			if load.has_key('SendSMS'):
			    load['SendSMS']['type'] = 'sms'
			    sendsms[time.time()-timeStamp] = load['SendSMS']
			    count.increaseCount()

			# phone call log
			if load.has_key('PhoneCall'):
			    load['PhoneCall']['type'] = 'call'
			    phonecalls[time.time()-timeStamp] = load['PhoneCall']
			    count.increaseCount()

			# crypto api usage log
			if load.has_key('CryptoUsage'):
			    load['CryptoUsage']['type'] = 'crypto'                                                                   
			    cryptousage[time.time()-timeStamp] = load['CryptoUsage']
			    count.increaseCount()
		    except ValueError:
			pass

	    except:
		try:
			count.stopCounting()
			count.join()
		finally:
			break;
	    
	#Kill ADB, otherwise it will never terminate
	os.kill(adb.pid, signal.SIGTERM)
	'''
