import subprocess
import thread, threading
import re
from subprocess import call, PIPE, Popen
adb = subprocess.Popen(["adb", "logcat","DroidBox:W", "dalvikvm:W", "ActivityManager:I"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
while 1:
     try:
          logcatInput = adb.stdout.readline()
          if not logcatInput:
               raise Exception("We have lost the connection with ADB.")
     except:
          break
duration=30
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
                         if load.has_key('DexClassLoader'):
                              load['DexClassLoader']['type'] = 'dexload'
                              dexclass[time.time() - timeStamp] = load['DexClassLoader']
                              print load['DexClassLoader']
                              count.increaseCount()
                              # service started
                         if load.has_key('ServiceStart'):
                              load['ServiceStart']['type'] = 'service'
                              servicestart[time.time() - timeStamp] = load['ServiceStart']
                              print load['ServiceStart']
                              count.increaseCount()
                              # received data from net
                         if load.has_key('RecvNet'):
                              host = load['RecvNet']['srchost']
                              port = load['RecvNet']['srcport']
                              print load['RecvNet']['srchost']
                              recvnet[time.time() - timeStamp] = recvdata = {'type': 'net read', 'host': host, 'port': port, 'data': load['RecvNet']['data']}
                              count.increaseCount()
                              # fdaccess
                         if load.has_key('FdAccess'):
                              accessedfiles[load['FdAccess']['id']] = hexToStr(load['FdAccess']['path'])
                              print hexToStr(load['FdAccess']['path'])
                             # file read or write
                         if load.has_key('FileRW'):
                              load['FileRW']['path'] = accessedfiles[load['FileRW']['id']]
                              print accessedfiles[load['FileRW']['id']]
                         if load['FileRW']['operation'] == 'write':
                              load['FileRW']['type'] = 'file write'
                         else:
                              load['FileRW']['type'] = 'file read'
                              fdaccess[time.time()-timeStamp] = load['FileRW']
                              count.increaseCount()
                              # opened network connection log
                         if load.has_key('OpenNet'):
                              opennet[time.time()-timeStamp] = load['OpenNet']
                              print load['OpenNet']
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
                              print load['SendSMS']
                              count.increaseCount()
                              # phone call log
                         if load.has_key('PhoneCall'):
                              load['PhoneCall']['type'] = 'call'
                              phonecalls[time.time()-timeStamp] = load['SendSMS']
                              print load['SendSMS']
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
