# Mobile-Security-Framework
Version: v0.8beta
![mobsecfav](https://cloud.githubusercontent.com/assets/4301109/7418958/68ec3d44-ef8f-11e4-97e2-b26a3d723814.png)

Mobile Security Framework is an intelligent, all-in-one open source mobile application (Android/iOS) automated pen-testing framework capable of performing static and dynamic analysis. We've been depending on multiple tools to carry out reversing, decoding, debugging, code review, and pen-test and this process requires a lot of effort and time. Mobile Security Framework can be used for effective and fast security analysis of Android and iOS Applications. It supports binaries (APK & IPA) and zipped source code.

The static analyzer is able to perform automated code review, detect insecure permissions and configurations, and detect insecure code like ssl overriding, ssl bypass, weak crypto, obfuscated codes, improper permissions, hardcoded secrets, improper usage of dangerous APIs, leakage of sensitive/PII information, and insecure file storage. 
The dynamic analyzer runs the application in a VM or on a configured device and detects the issues at run time. Further analysis is done on the captured network packets, decrypted HTTPS traffic, application dumps, logs, error or crash reports, debug information, stack trace, and on the application assets like setting files, preferences, and databases. This framework is highly scalable that you can add your custom rules with ease. A quick and clean report can be generated at the end of the tests. We will be extending this framework to support other mobile platforms like Tizen, WindowsPhone etc. in future. 
###Static Analysis - Android APK 
![android-1](https://cloud.githubusercontent.com/assets/4301109/7418316/a200f318-ef8a-11e4-9828-8d696e386847.png)
![android-2](https://cloud.githubusercontent.com/assets/4301109/7418317/a28dac4a-ef8a-11e4-8716-09fa42532ee8.png)
###Static Analysis - iOS IPA
![ios](https://cloud.githubusercontent.com/assets/4301109/7418318/a29b1f88-ef8a-11e4-8d76-9883b7664501.png)

Sample Report: http://opensecurity.in/research/security-analysis-of-android-browsers.html

#Requirements

* Python 2.7
* JDK 1.7 or above

NOTE: iOS IPA Binary Analysis requires MAC.

#How to Use

###Configuring Static Analyzer

Tested on Windows 7, 8, 8.1, Ubuntu, OSX Marvicks

 Install Django version 1.8a1

``` pip install Django==1.8a1```

 Specify Java PATH

Go to YodleeMobSec/settings.py and provide the correct Path to your Java Installation in the line that contains JAVA_PATH=
```
if platform.system()=="Windows":
    JAVA_PATH='C:/Program Files/Java/jdk1.7.0_17/bin/'  # Use "/" instead of "\" while setting the path.
else:
    JAVA_PATH='/usr/bin/' #For OSX and Linux
```

 To Run

```python manage.py runserver 127.0.0.1:8000```

Open your browser and navigate to http://127.0.0.1:8000

#Queries

* Features and Updates : [@ajinabraham](http://twitter.com/ajinabraham) or [@OpenSecurity_IN](http://twitter.com/OpenSecurity_IN). 
* Open Bugs Here - https://github.com/ajinabraham/YSO-Mobile-Security-Framework/issues

### Configuring Dynamic Analyzer

Pending....

#v0.8 Changelog
 
* View AndroidManifest.xml & Info.plist
* Supports iOS Binary (IPA)
* Bug Fix for Linux (Ubuntu), missing MIME Type Detection
* Check for Hardcoded Certificates
* Added Code to prevent from Directory Traversal

#Credits
 
* Anto Joseph (@antojosep007) - For the help with SuperSU.
* Tim Brown (@timb_machine) - For the iOS Binary Analysis Ruleset.
* Abhinav Sejpal (@Abhinav_Sejpal) - For poking me with bugs and feature requests.
