# Mobile-Security-Framework (MobSF)
Version: v0.8.8beta
![mobsecfav](https://cloud.githubusercontent.com/assets/4301109/7418958/68ec3d44-ef8f-11e4-97e2-b26a3d723814.png)

Mobile Security Framework (MobSF) is an intelligent, all-in-one open source mobile application (Android/iOS) automated pen-testing framework capable of performing static and dynamic analysis. We've been depending on multiple tools to carry out reversing, decoding, debugging, code review, and pen-test and this process requires a lot of effort and time. Mobile Security Framework can be used for effective and fast security analysis of Android and iOS Applications. It supports binaries (APK & IPA) and zipped source code.

The static analyzer is able to perform automated code review, detect insecure permissions and configurations, and detect insecure code like ssl overriding, ssl bypass, weak crypto, obfuscated codes, improper permissions, hardcoded secrets, improper usage of dangerous APIs, leakage of sensitive/PII information, and insecure file storage. 
The dynamic analyzer runs the application in a VM or on a configured device and detects the issues at run time. Further analysis is done on the captured network packets, decrypted HTTPS traffic, application dumps, logs, error or crash reports, debug information, stack trace, and on the application assets like setting files, preferences, and databases. This framework is highly scalable that you can add your custom rules with ease. A quick and clean report can be generated at the end of the tests. We will be extending this framework to support other mobile platforms like Tizen, WindowsPhone etc. in future. 

## Documentation
* https://github.com/ajinabraham/Mobile-Security-Framework-MobSF/wiki/Documentation

## Video Course
* Automated Mobile Application Security Assessment with MobSF: https://opsecx.com/index.php/course/automated-mobile-application-security-assessment-with-mobsf/

## Queries

* Features Requests: [@ajinabraham](http://twitter.com/ajinabraham) or [@OpenSecurity_IN](http://twitter.com/OpenSecurity_IN). 
* Open Bugs Here:  https://github.com/ajinabraham/YSO-Mobile-Security-Framework/issues

## Screenshots and Sample Report
###Static Analysis - Android APK 
![android-1](https://cloud.githubusercontent.com/assets/4301109/7418316/a200f318-ef8a-11e4-9828-8d696e386847.png)
![android-2](https://cloud.githubusercontent.com/assets/4301109/7418317/a28dac4a-ef8a-11e4-8716-09fa42532ee8.png)

###Static Analysis - iOS IPA
![ios](https://cloud.githubusercontent.com/assets/4301109/7418318/a29b1f88-ef8a-11e4-8d76-9883b7664501.png)

Sample Report: http://opensecurity.in/research/security-analysis-of-android-browsers.html

###Dynamic Analysis - Android APK
![android-dynamic](https://cloud.githubusercontent.com/assets/4301109/9771195/1374d99a-5752-11e5-9b33-70ac6347164a.png)

###v0.8.8 Changelog

* New name: Mobile Security Framework (MobSF)
* Added Dynamic Analysis
* VM Available for Download
* Fixed RCE
* Fixed Broken Manifest File Parsing Logic
* Sqlite DB Support
* Fixed Reporting with new PDF report
* Rescan Option
* Detect Root Detection
* Added Requiremnts.txt
* Automated Java Path Detection
* Improved Manifest and Code Analysis
* Fixed Unzipping error for Unix.
* Activity Tester Module
* Exported Activity Tester Module
* Device API Hooker with DroidMon
* SSL Certificate Pinning Bypass with JustTrustMe
* RootCloak to prevent root Detection
* Data Pusher to Dump Application Data
* pyWebproxy to decrypt SSL Traffic

###v0.8.7 Changelog

* Improved Static Analysis Rules
* Better AndroidManifest View
* Search in Files

###v0.8.6 Changelog

* Detects implicitly exported component from manifest.
* Added CFR decompiler support 
* Fixed Regex DoS on URL Regex

###v0.8.5 Changelog

* Bug Fix to support IPA MIME Type: application/x-itunes-ipa

###v0.8.4 Changelog

* Improved Android Static Code Analysis speed (2X performance)
* Static Code analysis on Dexguard protected APK.
* Fixed a Security Issue - Email Regex DoS.
* Added Logging Code.
* All Browser Support.
* MIME Type Bug fix to Support IE.
* Fixed Progress Bar.

###v0.8.3 Changelog
 
* View AndroidManifest.xml & Info.plist
* Supports iOS Binary (IPA)
* Bug Fix for Linux (Ubuntu), missing MIME Type Detection
* Check for Hardcoded Certificates
* Added Code to prevent from Directory Traversal

##Credits

* Bharadwaj Machiraju (@tunnelshade_) - For writing pyWebProxy from scratch
* Thomas Abraham - For JS Hacks on UI.
* Anto Joseph (@antojosep007) - For the help with SuperSU.
* Tim Brown (@timb_machine) - For the iOS Binary Analysis Ruleset.
* Abhinav Sejpal (@Abhinav_Sejpal) - For poking me with bugs and feature requests.
* Anant Srivastava (@anantshri) - For Activity Tester Idea

