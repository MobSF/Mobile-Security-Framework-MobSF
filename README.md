# Mobile Security Framework (MobSF)
Version: v0.9.3 beta
<p align="center">
  <img src="https://cloud.githubusercontent.com/assets/4301109/20019521/cc61f7fc-a2f2-11e6-95f3-407030d9fdde.png">
</p>


Mobile Security Framework (MobSF) is an intelligent, all-in-one open source mobile application (Android/iOS/Windows) automated pen-testing framework capable of performing static and dynamic analysis. It can be used for effective and fast security analysis of Android, iOS and Windows mobile Applications and supports both binaries (APK, IPA &amp; APPX ) and zipped source code. MobSF can also perform Web API Security testing with it's API Fuzzer that can do Information Gathering, analyze Security Headers, identify Mobile API specific vulnerabilities like XXE, SSRF, Path Traversal, IDOR, and other logical issues related to Session and API Rate Limiting.

Made with <img src="https://cloud.githubusercontent.com/assets/4301109/16754758/82e3a63c-4813-11e6-9430-6015d98aeaab.png" alt="Love"> in India

[![ToolsWatch Best Security Tools 2016](https://img.shields.io/badge/ToolsWatch-Rank%205%20%7C%20Year%202016-red.svg)](http://www.toolswatch.org/2017/02/2016-top-security-tools-as-voted-by-toolswatch-org-readers/)
[![support](https://baikal.io/badges/ajinabraham/mobsf)](https://baikal.io/ajinabraham/mobsf) [![License](https://img.shields.io/:license-gpl3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.html)
[![platform](https://img.shields.io/badge/platform-osx%2Flinux%2Fwindows-green.svg)](https://github.com/MobSF/Mobile-Security-Framework-MobSF/)
[![python](https://img.shields.io/badge/python-2.7-blue.svg)](https://www.python.org/downloads/)
[![Code Issues](https://www.quantifiedcode.com/api/v1/project/d49e36d69236411bb854214737f6dfa1/badge.svg)](https://www.quantifiedcode.com/app/project/d49e36d69236411bb854214737f6dfa1)

MobSF is also bundled with [Android Tamer](https://androidtamer.com/tamer4-release) and [BlackArch](https://blackarch.org/mobile.html)
## Documentation
* https://github.com/MobSF/Mobile-Security-Framework-MobSF/wiki/1.-Documentation

## Collaborators

* [Ajin Abraham](https://in.linkedin.com/in/ajinabraham)
* [Dominik Schlecht](https://github.com/DominikSchlecht)

## Presentations
* OWASP APPSEC EU 2016 - [Slides](http://www.slideshare.net/ajin25/automated-mobile-application-security-assessment-with-mobsf) | [Video](https://www.youtube.com/watch?v=h00v1euuFXg)
* NULLCON 2016 - [Slides](https://www.slideshare.net/ajin25/nullcon-goa-2016-automated-mobile-application-security-testing-with-mobile-security-framework-mobsf)
* c0c0n 2015 - [Slides](https://www.slideshare.net/ajin25/automated-security-analysis-of-android-ios-applications-with-mobile-security-framework-c0c0n-2015)

## Video Course
* Automated Mobile Application Security Assessment with MobSF: https://opsecx.com/index.php/product/automated-mobile-application-security-assessment-with-mobsf/

## What's New?
* See Changelog: https://github.com/MobSF/Mobile-Security-Framework-MobSF/wiki/3.-Changelog

## Contribution, Feature Requests & Bugs

* Read [CONTRIBUTING.md](https://github.com/ajinabraham/Mobile-Security-Framework-MobSF/blob/master/CONTRIBUTING.md) before opening bugs, feature requests and pull request.
* Features Requests: [@ajinabraham](https://twitter.com/ajinabraham) or [@OpenSecurity_IN](https://twitter.com/OpenSecurity_IN). 
* For discussions use our Slack Channel: https://mobsf.slack.com/ , Get Invitation: https://goo.gl/6cYU5a
* Open Bugs after reading [Guidelines to Report a Bug](https://github.com/ajinabraham/Mobile-Security-Framework-MobSF/blob/master/CONTRIBUTING.md#using-the-issue-tracker)

## Screenshots

###Static Analysis - Android APK 

![android-static-analysis-apk](https://cloud.githubusercontent.com/assets/4301109/13614857/7a39189c-e598-11e5-90ff-6357b6c320bd.png)
![android-static-analysis-apk2](https://cloud.githubusercontent.com/assets/4301109/13614896/b7b7b53e-e598-11e5-84b5-e69c56c230a3.png)

###Static Analysis - iOS IPA

![ios-static-analysis-ipa](https://cloud.githubusercontent.com/assets/4301109/13614950/e8174ac8-e598-11e5-8e03-d40ad7d9e5a4.png)

###Static Analysis - Windows APPX
![windows-static-analysis-appx](https://cloud.githubusercontent.com/assets/4301109/20524598/1e139a1e-b0e1-11e6-8489-ee38c4392b4b.png)

###Dynamic Analysis - Android APK

![android-dynamic-analysis](https://cloud.githubusercontent.com/assets/4301109/13615043/6fe62028-e599-11e5-9c50-e44adbba114a.png)
![android-dynamic-report](https://cloud.githubusercontent.com/assets/4301109/13615800/104cc424-e59d-11e5-9a98-2e3b2aff7222.png)
![android-dynamic-report2](https://cloud.githubusercontent.com/assets/4301109/13615767/f04e5c1e-e59c-11e5-9ad1-b31598024ad4.png)
![android-dynamic-expact](https://cloud.githubusercontent.com/assets/4301109/13615882/6f4d9f16-e59d-11e5-9ec9-3b4c47e37389.png)

###Web API Fuzzer

![api-fuzzer-start-scan](https://cloud.githubusercontent.com/assets/4301109/13615144/e992ecda-e599-11e5-88d5-e7c310980b62.png)
![api-fuzzer-start-report](https://cloud.githubusercontent.com/assets/4301109/13615236/5d8df210-e59a-11e5-827a-ccf642e96609.png)

##Credits
* Dominik Schlecht - For the awesome work on adding Windows Phone App Static Analysis to MobSF
* Bharadwaj Machiraju (@tunnelshade_) - For writing pyWebProxy from scratch
* MindMac - For writing Android Blue Pill
* Thomas Abraham - For JS Hacks on UI.
* Anto Joseph (@antojosep007) - For the help with SuperSU.
* Tim Brown (@timb_machine) - For the iOS Binary Analysis Ruleset.
* Abhinav Sejpal (@Abhinav_Sejpal) - For poking me with bugs and feature requests.
* Anant Srivastava (@anantshri) - For Activity Tester Idea
* Amrutha VC (@amruthavc) - For the new MobSF logo
* Rahul (@c0dist) - Kali Support
* shuxin - Android Binary Analysis
* Esteban - Better Android Manifest Analysis and Static Analysis Improvement.
