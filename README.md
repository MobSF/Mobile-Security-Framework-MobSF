# Mobile-Security-Framework (MobSF)
Version: v0.9beta
![mobsecfav](https://cloud.githubusercontent.com/assets/4301109/7418958/68ec3d44-ef8f-11e4-97e2-b26a3d723814.png)

Mobile Security Framework (MobSF) is an intelligent, all-in-one open source mobile application (Android/iOS) automated pen-testing framework capable of performing static and dynamic analysis. It can be used for effective and fast security analysis of Android and iOS Applications and supports both binaries (APK &amp; IPA) and zipped source code. MobSF can also perform Web API Security testing with it's API Fuzzer that can do Information Gathering, analyze Security Headers, identify Mobile API specific vulnerabilities like XXE, SSRF, Path Traversal, IDOR, and logical issues related to Session and API Rate Limiting.

The static analyzer is able to perform automated code review, detect insecure permissions and configurations, and detect insecure code like ssl overriding, ssl bypass, weak crypto, obfuscated codes, improper permissions, hardcoded secrets, improper usage of dangerous APIs, leakage of sensitive/PII information, and insecure file storage. 
The dynamic analyzer runs the application in a VM or on a configured device and detects the issues at run time. Further analysis is done on the captured network packets, decrypted HTTPS traffic, application dumps, logs, error or crash reports, debug information, and on the application assets like setting files, preferences, and databases.
The API Fuzzer performs Web API Security testing on the captured Web Traffic uncovering Mobile API specific security issues.
A quick and clean report can be generated at the end of the tests.

## Documentation
* https://github.com/ajinabraham/Mobile-Security-Framework-MobSF/wiki

## Video Course
* Automated Mobile Application Security Assessment with MobSF: https://opsecx.com/index.php/course/automated-mobile-application-security-assessment-with-mobsf/?p=github

## Queries

* Features Requests: [@ajinabraham](http://twitter.com/ajinabraham) or [@OpenSecurity_IN](http://twitter.com/OpenSecurity_IN). 
* Open Bugs Here:  https://github.com/ajinabraham/YSO-Mobile-Security-Framework/issues

## Screenshots and Sample Report
###Static Analysis - Android APK 

###Static Analysis - iOS IPA

Sample Report: http://opensecurity.in/research/security-analysis-of-android-browsers.html

###Dynamic Analysis - Android APK

See Changelog here : https://github.com/ajinabraham/Mobile-Security-Framework-MobSF/wiki/3.-Changelog

##Credits

* Bharadwaj Machiraju (@tunnelshade_) - For writing pyWebProxy from scratch
* Thomas Abraham - For JS Hacks on UI.
* Anto Joseph (@antojosep007) - For the help with SuperSU.
* Tim Brown (@timb_machine) - For the iOS Binary Analysis Ruleset.
* Abhinav Sejpal (@Abhinav_Sejpal) - For poking me with bugs and feature requests.
* Anant Srivastava (@anantshri) - For Activity Tester Idea

