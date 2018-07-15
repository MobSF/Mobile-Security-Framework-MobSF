# Mobile Security Framework (MobSF)
Version: v1.0 beta
![](https://cloud.githubusercontent.com/assets/4301109/20019521/cc61f7fc-a2f2-11e6-95f3-407030d9fdde.png)

Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing framework capable of performing static, dynamic and malware analysis. It can be used for effective and fast security analysis of Android, iOS and Windows mobile applications and support both binaries (APK, IPA & APPX ) and zipped source code. MobSF can do dynamic application testing at runtime for Android apps and has Web API fuzzing capabilities powered by [CapFuzz](https://github.com/MobSF/CapFuzz), a Web API specific security scanner. MobSF is designed to make your CI/CD or DevSecOps pipeline integration seamless.

Made with ![Love](https://cloud.githubusercontent.com/assets/4301109/16754758/82e3a63c-4813-11e6-9430-6015d98aeaab.png) in India

[![ToolsWatch Best Security Tools 2017](https://img.shields.io/badge/ToolsWatch-Rank%209%20%7C%20Year%202017-red.svg)](http://www.toolswatch.org/2018/01/black-hat-arsenal-top-10-security-tools/)
[![ToolsWatch Best Security Tools 2016](https://img.shields.io/badge/ToolsWatch-Rank%205%20%7C%20Year%202016-red.svg)](http://www.toolswatch.org/2017/02/2016-top-security-tools-as-voted-by-toolswatch-org-readers/)
[![Blackhat Arsenal Asia 2018](https://img.shields.io/badge/Black%20Hat%20Arsenal-Asia%202018-blue.svg)](https://www.blackhat.com/asia-18/arsenal.html#mobile-security-framework-mobsf)
[![Blackhat Arsenal Asia 2015](https://img.shields.io/badge/Black%20Hat%20Arsenal-Asia%202015-blue.svg)](https://www.blackhat.com/asia-15/arsenal.html#yso-mobile-security-framework)
[![support](https://baikal.io/badges/ajinabraham/mobsf)](https://baikal.io/ajinabraham/mobsf)
[![platform](https://img.shields.io/badge/platform-osx%2Flinux%2Fwindows-green.svg)](https://github.com/MobSF/Mobile-Security-Framework-MobSF/)
[![License](https://img.shields.io/:license-gpl3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.html)
[![python](https://img.shields.io/badge/python-3.6-blue.svg)](https://www.python.org/downloads/)
[![Requirements Status](https://requires.io/github/MobSF/Mobile-Security-Framework-MobSF/requirements.svg?branch=master)](https://requires.io/github/MobSF/Mobile-Security-Framework-MobSF/requirements/?branch=master)

MobSF is also bundled with [Android Tamer](https://androidtamer.com/tamer4-release) and [BlackArch](https://blackarch.org/mobile.html)

## Buy us a Coffee!
**Your generous donations will keep us motivated.**

*Paypal:* [![Donate via Paypal](https://user-images.githubusercontent.com/4301109/28491754-14774f54-6f14-11e7-9975-8a5faeda7e30.gif)](https://mobsf.github.io/Mobile-Security-Framework-MobSF/paypal.html)

*Bitcoin:* [![Donate Bitcoin](https://user-images.githubusercontent.com/4301109/30631105-cb8063c8-9e00-11e7-95df-43c20b840e52.png)](https://mobsf.github.io/Mobile-Security-Framework-MobSF/donate.html)

## Documentation
* [See MobSF Documentation](https://github.com/MobSF/Mobile-Security-Framework-MobSF/wiki/1.-Documentation)

## MobSF Static Analyzer Docker Image
Automated prebuilt docker image of MobSF Static Analyzer is available from [DockerHub](https://hub.docker.com/r/opensecurity/mobile-security-framework-mobsf/)
```
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```
### For persistence

```
docker run -it -p 8000:8000 -v <your_local_dir>:/root/.MobSF opensecurity/mobile-security-framework-mobsf:latest
```

## Collaborators

* [Ajin Abraham](https://in.linkedin.com/in/ajinabraham) ![india](https://user-images.githubusercontent.com/4301109/37564171-6549d678-2ab6-11e8-9b9d-21327c7f5d5b.png) 
* [Dominik Schlecht](https://github.com/DominikSchlecht) ![germany](https://user-images.githubusercontent.com/4301109/37564176-743238ba-2ab6-11e8-9666-5d98f0a1d127.png)
* [Matan Dobrushin](https://github.com/matandobr) ![israel](https://user-images.githubusercontent.com/4301109/37564177-782f1758-2ab6-11e8-91e5-c76bde37b330.png)
* [Vincent Nadal](https://github.com/superpoussin22) ![france](https://user-images.githubusercontent.com/4301109/37564175-71d6d92c-2ab6-11e8-89d7-d21f5aa0bda8.png) 

## Presentations
* OWASP APPSEC EU 2016 - [Slides](http://www.slideshare.net/ajin25/automated-mobile-application-security-assessment-with-mobsf)
* NULLCON 2016 - [Slides](https://www.slideshare.net/ajin25/nullcon-goa-2016-automated-mobile-application-security-testing-with-mobile-security-framework-mobsf)
* c0c0n 2015 - [Slides](https://www.slideshare.net/ajin25/automated-security-analysis-of-android-ios-applications-with-mobile-security-framework-c0c0n-2015)
*  OWASP AppSec EU 2016 - [Video](https://www.youtube.com/watch?v=h00v1euuFXg)
*  G4H Webcast 2015 - [Video](https://www.youtube.com/watch?v=CysfO6AZmo8)

## Video Course
* [Automated Mobile Application Security Assessment with MobSF](https://opsecx.com/index.php/product/automated-mobile-application-security-assessment-with-mobsf/)
* [Android Security Tools Expert](https://opsecx.com/index.php/product/android-security-tools-expert-atx/)

## What's New?
* [See Changelog](https://mobsf.github.io/Mobile-Security-Framework-MobSF/changelog.html)

## Contribution, Feature Requests & Bugs

* Read [CONTRIBUTING.md](https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/.github/CONTRIBUTING.md) before opening bugs, feature requests and pull request.
* Feature Requests: [@ajinabraham](https://twitter.com/ajinabraham) or [@OpenSecurity_IN](https://twitter.com/OpenSecurity_IN). 
* For discussions use our Slack Channel: [https://mobsf.slack.com/](https://mobsf.slack.com/) , Get Invitation: [https://goo.gl/6cYU5a](https://goo.gl/6cYU5a)
* Open Bugs after reading [Guidelines to Report a Bug](https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/.github/CONTRIBUTING.md#using-the-issue-tracker)

## Screenshots

### Static Analysis - Android APK 

![android-static-analysis-apk](https://cloud.githubusercontent.com/assets/4301109/13614857/7a39189c-e598-11e5-90ff-6357b6c320bd.png)
![android-static-analysis-apk2](https://cloud.githubusercontent.com/assets/4301109/13614896/b7b7b53e-e598-11e5-84b5-e69c56c230a3.png)

### Static Analysis - iOS IPA

![ios-static-analysis-ipa](https://cloud.githubusercontent.com/assets/4301109/13614950/e8174ac8-e598-11e5-8e03-d40ad7d9e5a4.png)

### Static Analysis - Windows APPX
![windows-static-analysis-appx](https://cloud.githubusercontent.com/assets/4301109/20524598/1e139a1e-b0e1-11e6-8489-ee38c4392b4b.png)

### Dynamic Analysis - Android APK

![android-dynamic-analysis](https://cloud.githubusercontent.com/assets/4301109/13615043/6fe62028-e599-11e5-9c50-e44adbba114a.png)
![android-dynamic-report](https://cloud.githubusercontent.com/assets/4301109/13615800/104cc424-e59d-11e5-9a98-2e3b2aff7222.png)
![android-dynamic-report2](https://cloud.githubusercontent.com/assets/4301109/13615767/f04e5c1e-e59c-11e5-9ad1-b31598024ad4.png)
![android-dynamic-expact](https://cloud.githubusercontent.com/assets/4301109/13615882/6f4d9f16-e59d-11e5-9ec9-3b4c47e37389.png)

### Web API Fuzzer

![capfuzz](https://user-images.githubusercontent.com/4301109/37251800-af620840-253c-11e8-89ed-ce3594e243e9.png)
![capfuzz-scan](https://user-images.githubusercontent.com/4301109/37564069-561cef7a-2ab4-11e8-9048-bdf405d078ce.png)

## Credits
* Abhinav Sejpal (@Abhinav_Sejpal) - For poking me with bugs, feature requests, and UI & UX suggestions.
* Amrutha VC (@amruthavc) - For the new MobSF logo
* Anant Srivastava (@anantshri) - For Activity Tester Idea
* Anto Joseph (@antojosep007) - For the help with SuperSU.
* Bharadwaj Machiraju (@tunnelshade_) - For writing pyWebProxy from scratch
* Dominik Schlecht - For the awesome work on adding Windows Phone App Static Analysis to MobSF
* Esteban - Better Android Manifest Analysis and Static Analysis Improvement.
* Matan Dobrushin - For adding Android ARM Emulator support to MobSF - Special thanks goes for cuckoo-droid, I got inspierd by their code and idea for this implementation.
* MindMac - For writing Android Blue Pill
* Rahul (@c0dist) - Kali Support
* Shuxin - Android Binary Analysis
* Thomas Abraham - For JS Hacks on UI.
* Tim Brown (@timb_machine) - For the iOS Binary Analysis Ruleset.
* Oscar Alfonso Diaz - (@OscarAkaElvis) - For Dockerfile contributions
