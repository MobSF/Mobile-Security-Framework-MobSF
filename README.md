# YSO-Mobile-Security-Framework

YSO Mobile Security Framework is an intelligent, all-in-one open source mobile application (Android/iOS) automated pen-testing framework capable of performing static and dynamic analysis. We've been depending on multiple tools to carry out reversing, decoding, debugging, code review, and pen-test and this process requires a lot of effort and time. YSO Mobile Security Framework can be used for effective and fast security analysis of Android APK/Android app source code/iOS app source code.

![YSO](http://opensecurity.in/wp-content/uploads/2015/03/Screen-Shot-2015-03-01-at-12.30.31-pm.png)

The static analyzer is able to perform automated code review, detect insecure permissions and configurations, and detect insecure code like ssl overriding, ssl bypass, weak crypto, obfuscated codes, permission bypasses, hardcoded secrets, improper usage of dangerous APIs, leakage of sensitive/PII information, and insecure file storage. The dynamic analyzer runs the application in a VM and detects the issues at run time. Further analysis is done on the captured network packets, decrypted HTTPS traffic, application dumps, logs, error or crash reports, debug information, stack trace, and the application assets like files, preferences, and databases. This framework is highly scalable that you can add your custom rules with ease. We will be extending this framework to support other mobile platforms like Tizen, Windows phone etc. in future. A quick and clean report can be generated at the end of the tests.

Sample Report: http://opensecurity.in/research/security-analysis-of-android-browsers.html

##How to Use
* For Using Static Analyzer

Tested on Windows 7, 8, 8.1

 Install Django version 1.8a1

``` pip install Django==1.8a1```

 Specify Java PATH

Go to YodleeMobSec/settings.py and provide the correct Path to your Java Installation in the line that contains JAVA_PATH=

 To Run

```python manage.py runserver```

* For Dynamic Analyzer

 Pending....
