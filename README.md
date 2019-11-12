# Mobile Security Framework (MobSF)
Version: v2.0 beta
![](https://cloud.githubusercontent.com/assets/4301109/20019521/cc61f7fc-a2f2-11e6-95f3-407030d9fdde.png)

Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis. MobSF support mobile app binaries (APK, IPA & APPX) along with zipped source code and provides REST APIs for seamless integration with your CI/CD or DevSecOps pipeline.The Dynamic Analyzer helps you to perform runtime security assessment and interactive instrumented testing.

Made with ![Love](https://cloud.githubusercontent.com/assets/4301109/16754758/82e3a63c-4813-11e6-9430-6015d98aeaab.png) in India

[![python](https://img.shields.io/badge/python-3.6-blue.svg)](https://www.python.org/downloads/)
[![platform](https://img.shields.io/badge/platform-osx%2Flinux%2Fwindows-green.svg)](https://github.com/MobSF/Mobile-Security-Framework-MobSF/)
[![License](https://img.shields.io/:license-gpl3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.html)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/cefbfb063c044b069e38af3501c1ee8e)](https://www.codacy.com/app/ajinabraham/Mobile-Security-Framework-MobSF)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=MobSF_Mobile-Security-Framework-MobSF&metric=alert_status)](https://sonarcloud.io/dashboard?id=MobSF_Mobile-Security-Framework-MobSF)
[![Build Status](https://travis-ci.com/MobSF/Mobile-Security-Framework-MobSF.svg?branch=master)](https://travis-ci.com/MobSF/Mobile-Security-Framework-MobSF)
[![Requirements Status](https://pyup.io/repos/github/MobSF/Mobile-Security-Framework-MobSF/shield.svg)](https://pyup.io/repos/github/MobSF/Mobile-Security-Framework-MobSF/)
[![ToolsWatch Best Security Tools 2017](https://img.shields.io/badge/ToolsWatch-Rank%209%20%7C%20Year%202017-red.svg)](http://www.toolswatch.org/2018/01/black-hat-arsenal-top-10-security-tools/)
[![ToolsWatch Best Security Tools 2016](https://img.shields.io/badge/ToolsWatch-Rank%205%20%7C%20Year%202016-red.svg)](http://www.toolswatch.org/2017/02/2016-top-security-tools-as-voted-by-toolswatch-org-readers/)
[![Blackhat Arsenal Asia 2018](https://img.shields.io/badge/Black%20Hat%20Arsenal-Asia%202018-blue.svg)](https://www.blackhat.com/asia-18/arsenal.html#mobile-security-framework-mobsf)
[![Blackhat Arsenal Asia 2015](https://img.shields.io/badge/Black%20Hat%20Arsenal-Asia%202015-blue.svg)](https://www.blackhat.com/asia-15/arsenal.html#yso-mobile-security-framework)


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
[![Try in PWD](https://raw.githubusercontent.com/play-with-docker/stacks/master/assets/images/button.png)](https://labs.play-with-docker.com/?stack=https://raw.githubusercontent.com/MobSF/Mobile-Security-Framework-MobSF/master/scripts/stack/docker-compose.yml)

Other docker options: [MobSF Docker Options](https://github.com/MobSF/Mobile-Security-Framework-MobSF/wiki/7.-Docker-Container-for-MobSF-Static-Analysis)


## Collaborators

* [Ajin Abraham](https://in.linkedin.com/in/ajinabraham) ![india](https://user-images.githubusercontent.com/4301109/37564171-6549d678-2ab6-11e8-9b9d-21327c7f5d5b.png)
* [Dominik Schlecht](https://github.com/DominikSchlecht) ![germany](https://user-images.githubusercontent.com/4301109/37564176-743238ba-2ab6-11e8-9666-5d98f0a1d127.png)
* [Magaofei](https://github.com/magaofei) ![china](https://user-images.githubusercontent.com/4301109/44515364-00bbe880-a6e0-11e8-944d-5b48a86427da.png)
* [Matan Dobrushin](https://github.com/matandobr) ![israel](https://user-images.githubusercontent.com/4301109/37564177-782f1758-2ab6-11e8-91e5-c76bde37b330.png)
* [Vincent Nadal](https://github.com/superpoussin22) ![france](https://user-images.githubusercontent.com/4301109/37564175-71d6d92c-2ab6-11e8-89d7-d21f5aa0bda8.png)

## Presentations
* OWASP APPSEC EU 2016 - [Slides](http://www.slideshare.net/ajin25/automated-mobile-application-security-assessment-with-mobsf), [Video](https://www.youtube.com/watch?v=h00v1euuFXg)
* NULLCON 2016 - [Slides](https://www.slideshare.net/ajin25/nullcon-goa-2016-automated-mobile-application-security-testing-with-mobile-security-framework-mobsf)
* c0c0n 2015 - [Slides](https://www.slideshare.net/ajin25/automated-security-analysis-of-android-ios-applications-with-mobile-security-framework-c0c0n-2015)
*  G4H Webcast 2015 - [Video](https://www.youtube.com/watch?v=CysfO6AZmo8)

## e-Learning Courses & Certifications
* [Automated Mobile Application Security Assessment with MobSF -MAS (Currently being updated)](https://opsecx.com/index.php/product/automated-mobile-application-security-assessment-with-mobsf/)
* [Android Security Tools Expert -ATX](https://opsecx.com/index.php/product/android-security-tools-expert-atx/)

## What's New?
* [See Changelog](https://mobsf.github.io/Mobile-Security-Framework-MobSF/changelog.html)

## Contribution, Feature Requests & Bugs

* Read [CONTRIBUTING.md](https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/.github/CONTRIBUTING.md) before opening bugs, feature requests and pull request.
* Feature Requests: [@ajinabraham](https://twitter.com/ajinabraham) or [@OpenSecurity_IN](https://twitter.com/OpenSecurity_IN).
* For discussions, questions and support, use our Slack Channel mobsf.slack.com: [Join MobSF Channel](https://mobsf.slack.com/join/shared_invite/enQtNzM2NTAyNzA1MjgxLTdjMzkzNDc3ZjdiMjkwZTZhMmFhNDlkZmMwZDhjNDNmYTAzYWE5NGZlMDIzYzliNTdiMDQ2MTRlYjU1MjkyNGM)
* Open Bugs after reading [Guidelines to Report a Bug](https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/.github/CONTRIBUTING.md#using-the-issue-tracker)

## Screenshots

### Static Analysis - Android APK

![android-static-analysis-apk](https://user-images.githubusercontent.com/4301109/65378793-5136b880-dcdb-11e9-890a-6a5148e6ab25.png)
![android-static-analysis-apk2](https://user-images.githubusercontent.com/4301109/65378792-4e3bc800-dcdb-11e9-91b0-74d8c1a3a452.png)
![compare-result](https://user-images.githubusercontent.com/4301109/65378790-454af680-dcdb-11e9-927c-af94cd97359f.png)

### Static Analysis - iOS IPA

![ios-static-analysis-ipa](https://user-images.githubusercontent.com/4301109/65378791-4aa84100-dcdb-11e9-963b-927ca669d6e1.png)

### Dynamic Analysis - Android APK

![android-dynamic-analysis](https://user-images.githubusercontent.com/4301109/65378800-5d227a80-dcdb-11e9-820b-b688ae6cfd5d.png)
![android-dynamic-frida-live](https://user-images.githubusercontent.com/4301109/65378803-614e9800-dcdb-11e9-88e7-3ca54ec0b0dd.png)
![android-dynamic-expact](https://user-images.githubusercontent.com/4301109/65378854-387ad280-dcdc-11e9-9a69-3ef4d1d28cb9.png)

### Web API Viewer

![android-dynamic-http-tools](https://user-images.githubusercontent.com/4301109/65378797-57c53000-dcdb-11e9-84e9-d5acf887f3aa.png)


## Credits
* Abhinav Sejpal (@Abhinav_Sejpal) - For poking me with bugs, feature requests, and UI & UX suggestions.
* Amrutha VC (@amruthavc) - For the new MobSF logo
* Anant Srivastava (@anantshri) - For Activity Tester Idea
* Anto Joseph (@antojosep007) - For the help with SuperSU.
* Bharadwaj Machiraju (@tunnelshade_) - For writing pyWebProxy from scratch
* Dominik Schlecht - For the awesome work on adding Windows Phone App Static Analysis to MobSF
* Esteban - Better Android Manifest Analysis and Static Analysis Improvement.
* Matan Dobrushin - For adding Android ARM Emulator support to MobSF - Special thanks goes for cuckoo-droid, I got inspired by their code and idea for this implementation.
* MindMac - For writing Android Blue Pill
* Rahul (@c0dist) - Kali Support
* Shuxin - Android Binary Analysis
* Thomas Abraham - For JS Hacks on UI.
* Tim Brown (@timb_machine) - For the iOS Binary Analysis Ruleset.
* Oscar Alfonso Diaz - (@OscarAkaElvis) - For Dockerfile contributions
* Abhinav Saxena - (@xandfury) - For Travis CI and Logging integration
