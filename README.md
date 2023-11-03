# Mobile Security Framework (MobSF)
Version: v3.7 beta

![](https://cloud.githubusercontent.com/assets/4301109/20019521/cc61f7fc-a2f2-11e6-95f3-407030d9fdde.png)

Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis. MobSF supports mobile app binaries (APK, XAPK, IPA & APPX) along with zipped source code and provides REST APIs for seamless integration with your CI/CD or DevSecOps pipeline.The Dynamic Analyzer helps you to perform runtime security assessment and interactive instrumented testing.

Made with ![Love](https://cloud.githubusercontent.com/assets/4301109/16754758/82e3a63c-4813-11e6-9430-6015d98aeaab.png) in India

[![python](https://img.shields.io/badge/python-3.9+-blue.svg?logo=python&labelColor=yellow)](https://www.python.org/downloads/)
[![PyPI version](https://badge.fury.io/py/mobsf.svg)](https://badge.fury.io/py/mobsf)
[![platform](https://img.shields.io/badge/platform-osx%2Flinux%2Fwindows-green.svg)](https://github.com/MobSF/Mobile-Security-Framework-MobSF/)
[![License](https://img.shields.io/:license-GPL--3.0--only-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.html)
[![Docker Pulls](https://img.shields.io/docker/pulls/opensecurity/mobile-security-framework-mobsf?style=social)](https://hub.docker.com/r/opensecurity/mobile-security-framework-mobsf/)

[![MobSF tests](https://github.com/MobSF/Mobile-Security-Framework-MobSF/workflows/MobSF%20tests/badge.svg?branch=master)](https://github.com/MobSF/Mobile-Security-Framework-MobSF/actions)
[![Requirements Status](https://pyup.io/repos/github/MobSF/Mobile-Security-Framework-MobSF/shield.svg)](https://pyup.io/repos/github/MobSF/Mobile-Security-Framework-MobSF/)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=MobSF_Mobile-Security-Framework-MobSF&metric=alert_status)](https://sonarcloud.io/dashboard?id=MobSF_Mobile-Security-Framework-MobSF)
![GitHub closed issues](https://img.shields.io/github/issues-closed/MobSF/Mobile-Security-Framework-MobSF)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/6392/badge)](https://bestpractices.coreinfrastructure.org/projects/6392)


[![ToolsWatch Best Security Tools 2016](https://img.shields.io/badge/ToolsWatch-Rank%205%20%7C%20Year%202016-red.svg)](http://www.toolswatch.org/2017/02/2016-top-security-tools-as-voted-by-toolswatch-org-readers/)
[![ToolsWatch Best Security Tools 2017](https://img.shields.io/badge/ToolsWatch-Rank%209%20%7C%20Year%202017-red.svg)](http://www.toolswatch.org/2018/01/black-hat-arsenal-top-10-security-tools/)
[![Blackhat Arsenal Asia 2015](https://img.shields.io/badge/Black%20Hat%20Arsenal-Asia%202015-blue.svg)](https://www.blackhat.com/asia-15/arsenal.html#yso-mobile-security-framework)
[![Blackhat Arsenal Asia 2018](https://img.shields.io/badge/Black%20Hat%20Arsenal-Asia%202018-blue.svg)](https://www.blackhat.com/asia-18/arsenal.html#mobile-security-framework-mobsf)

MobSF is also bundled with [Android Tamer](https://tamerplatform.com), [BlackArch](https://blackarch.org/mobile.html) and [Pentoo](https://www.pentoo.ch/).

## Support MobSF

[![Donate to MobSF](https://user-images.githubusercontent.com/4301109/117404264-7aab5480-aebe-11eb-9cbd-da82d7346bb3.png)](https://opensecurity.in/donate)

If you liked MobSF and find it useful, please consider donating.

*It's easy to build open source, try maintaining a project once. Long live open source!*

## Documentation

Quick setup

```
docker pull opensecurity/mobile-security-framework-mobsf:latest
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

[![See MobSF Documentation](https://user-images.githubusercontent.com/4301109/70686099-3855f780-1c79-11ea-8141-899e39459da2.png)](https://mobsf.github.io/docs)
[![See MobSF Documentation in Chinese](https://user-images.githubusercontent.com/4301109/117404947-b09d0880-aebf-11eb-9db8-3d7360f47914.png)](https://mobsf.github.io/docs/#/zh-cn/)
[![See MobSF Documentation in Japanese](https://user-images.githubusercontent.com/4301109/148662149-7ee671b4-66a2-4232-9522-276b8e88d924.png)](https://mobsf.github.io/docs/#/ja-jp/)
[![See MobSF Documentation in Español](https://user-images.githubusercontent.com/4301109/173221657-ac1f7221-6ae9-44d8-bf6b-8732d84bf120.png)](https://mobsf.github.io/docs/#/es/)

* Try MobSF Static Analyzer Online: [mobsf.live](https://mobsf.live)
* MobSF in CI/CD: [mobsfscan](https://github.com/MobSF/mobsfscan)
* Conference Presentations: [Slides & Videos](https://mobsf.github.io/Mobile-Security-Framework-MobSF/presentations.html)
* MobSF Online Course: [OpSecX MAS](https://opsecx.com/index.php/product/automated-mobile-application-security-assessment-with-mobsf/)
* What's New: [See Changelog](https://mobsf.github.io/Mobile-Security-Framework-MobSF/changelog.html)

## Collaborators

[Ajin Abraham](https://in.linkedin.com/in/ajinabraham) ![india](https://user-images.githubusercontent.com/4301109/37564171-6549d678-2ab6-11e8-9b9d-21327c7f5d5b.png)  | [Magaofei](https://github.com/magaofei) ![china](https://user-images.githubusercontent.com/4301109/44515364-00bbe880-a6e0-11e8-944d-5b48a86427da.png) | [Matan Dobrushin](https://github.com/matandobr) ![israel](https://user-images.githubusercontent.com/4301109/37564177-782f1758-2ab6-11e8-91e5-c76bde37b330.png) | [Vincent Nadal](https://github.com/superpoussin22) ![france](https://user-images.githubusercontent.com/4301109/37564175-71d6d92c-2ab6-11e8-89d7-d21f5aa0bda8.png)

## e-Learning Courses & Certifications
![MobSF Course](https://user-images.githubusercontent.com/4301109/76344880-ad68b580-62d8-11ea-8cde-9e3475fc92f6.png) [Automated Mobile Application Security Assessment with MobSF -MAS](https://opsecx.com/index.php/product/automated-mobile-application-security-assessment-with-mobsf/)

![Android Security Tools Course](https://user-images.githubusercontent.com/4301109/76344939-c709fd00-62d8-11ea-8208-774f1d5a7c52.png) [Android Security Tools Expert -ATX](https://opsecx.com/index.php/product/android-security-tools-expert-atx/)

## MobSF Support

* **Free Support:** Free limited support, questions, help and discussions, join our Slack channel [![Join_MobSF_Slack](https://img.shields.io/badge/mobsf%20slack-join-green?logo=slack&labelColor=4A154B)](https://join.slack.com/t/mobsf/shared_invite/zt-153nfus2r-hMCGrwzm8Lyy3OxsihnolQ)
* **Enterprise Support:** Priority feature requests, live support & onsite training, see [![MobSF Support Packages](https://img.shields.io/badge/enterprise-support%20package-blue?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAGMAAABaCAMAAACbkBjCAAAAAXNSR0IB2cksfwAAAAlwSFlzAAALEwAACxMBAJqcGAAAAkNQTFRFAAAA////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////o1yoNQAAAMF0Uk5TAAQ1YH6IXzYFAUqq9P/1rU4CPdHWQ4X+jgOkro+hVWYR6vIajJvz+XN/z9sjLW6lrNPX+PsGHyE5TE9XWV1hW0k6LC7hs7SEhgr2sGRiFBCXJf38sgwOtmpoIiDf68vSGS+Z9yeR70RNvUEVfOa/WgdCR8XuUeeA8Du7Vporrx66SwlcqWV92g2HY+2Ki/GQJjxpM8TVcIGodjJ3ybETJOjUyiop4sxYkkVSGJ/pD6cdwlTOHNnIZ+B13bXkKL7NMOC0/xQAAAPPSURBVHic7dn5PxVRFADwY0sPN0t4Uj0vLQq9lkelRVFRKklZs+RRiiTtSbRoD9GuhdK+Ky3S9qf1Zu68bczcO5rjhz4f5yfnOud9mTszd+Y+gLH4f8PL28fXz893nP/4UQIMAYFBRIoJwSGho0CETSQeER6BLYRGGoksjFGTcIlouSDEZNRpmaJEEDIVkTApE4TEoBHmaWpG7HQsY4YaQchMJMI8S92IQ/pHZqsThMzBMeJZRgIKkcgiCJmLYcSwDQuGMY9tzMcwFrCNhQiEl5VtJCXrNxaxCUIW6zf8ecYS/UYKz1iq31jGM5brN1bwDB/9RirPQFhDuMdqpX5jFc9I0W+k8Yww/UY6z1it3zDzDLN+A9awiTUIBKxlGxkYRibbWIdhLGUbCLcrgPUTWETWegyDPSEbUAjYyDI24RjZWepE7GYcA3LUjSlIBGzJVSO2JmIZsG2UZ1wI1TUEYZ11RJ7KrFvz8Qy1S6QAkYBCZaMI0yhWNrZjGlCiRJSiElCmZJSPGWOGrtiheKFjGhW2yiVVO+XL+i6bz9pqHCB09x77B9YA1O6tcwHGffX7oYGQsnr9+2R5MeHiZx4QkmTTQSocsqUL+WHh5yNHs3UJxVHHpL87RBo5HphkbDwhvS770N9lNZ38Z6Gm2bXGmpyjLa7l1eI8cqdO/8tW7JmNHnutZ6XhtJzA1nOOx7bzbgUXLBdHKLRcKvU8iS4Lo2YL3de4cpXe1Ns8Sto7ro1A6AxMkl8KXQDXbc5tapLbuNsA0CSvumHy0gTkF96Ut9rjFtyWjRwFuDO8ruRuLVfoblLePLwH4bKRmwAFSpXW6E4WYC66rwjYw3fYY8MDgIMqxeWWh8qAobq1Uk0gJBJ6ej0GensAHqmWW1urDQoH6bE6YI82gD53pPeJvecpq+OZt5x4ztkJewEeSG+f0NTObIlL9SReDjtZZWEDd4QSoaqP2jRyX7kTr49wCPJGrKuqE5O34h0R3vGaYqvcjAxeNXlPC+k7biZNPnC7+l1EA7eYBNPKVjG5QxPuLgchH51GP79YetP/JCbxNDnOb5voIE7ya0kjvYboTSCInvsBGvocG5odGmrpkR2QsgF6vmvos0nGZw21X8TKCClrELOvGvq+UYK7SSwEnYIiKesSs0EtjXSl6dZSGi6WOr5ei3I7kTnRrd34LpYOSdmQmL1ANn6IpQlSRr+8mYpsiK9MyY672lbx4acZ2WgXKp84059C+gvZsAqVrt0ycWPsN7JhNHicrIPus6PBMJu0hPAcWOHM/giNKVr6zDAWI4i/nmw15nhs85kAAAAASUVORK5CYII=)](https://opensecurity.in/#support)


## Contribution, Feature Requests & Bugs

* Read [CONTRIBUTING.md](https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/.github/CONTRIBUTING.md) before opening bugs, feature requests and pull request.
* For Project updates and announcements, follow [@ajinabraham](https://twitter.com/ajinabraham) or [@OpenSecurity_IN](https://twitter.com/OpenSecurity_IN).
* Github Issues are only for tracking bugs and feature requests. Do not post support or help queries there. We have a slack channel for that.

### Static Analysis - Android

![mobsf_android_static_analysis](https://user-images.githubusercontent.com/4301109/95506503-f9b6c980-097d-11eb-803a-f88321e1feb7.gif)

### Static Analysis - Android Source Tree-view

![mobsf_android_static_analysis_tree_view](https://user-images.githubusercontent.com/6709304/101240296-1578ea80-36f7-11eb-810a-3827f238c231.gif)

### Static Analysis - iOS

![mobsf_ios_ipa_static_analysis](https://user-images.githubusercontent.com/4301109/95507865-16540100-0980-11eb-9e4d-887668d46969.gif)

### Dynamic Analysis - Android APK

![mobsf_dynamic_analysis](https://user-images.githubusercontent.com/4301109/95514697-5e782100-098a-11eb-8390-47bb3822a2d7.gif)

### Web API Viewer

![ mobsf_web_api_fuzzing_with_burp](https://user-images.githubusercontent.com/4301109/95516560-69808080-098d-11eb-9e0b-fb5a25e96585.gif)

## Past Collaborators

* [Dominik Schlecht](https://github.com/sn0b4ll) ![germany](https://user-images.githubusercontent.com/4301109/37564176-743238ba-2ab6-11e8-9666-5d98f0a1d127.png)

## Honorable Contributors

* Amrutha VC - For the new MobSF logo
* Dominik Schlecht - For the awesome work on adding Windows Phone App Static Analysis to MobSF
* Esteban - Better Android Manifest Analysis and Static Analysis Improvement.
* Matan Dobrushin - For adding Android ARM Emulator support to MobSF - Special thanks goes for cuckoo-droid
* Shuxin - Android Binary Analysis
* Abhinav Saxena - (@xandfury) - For Travis CI and Logging integration
* ![netguru](https://user-images.githubusercontent.com/4301109/76340877-a3dc4f00-62d2-11ea-8631-b4cc8d9e42ed.png) [Netguru](https://www.netguru.com/) (@karolpiateknet, @mtbrzeski) - For iOS Swift support, Rule contributions and SAST refactoring.
* Maxime Fawe - (@Arenash13) - For Matching Strategy implementation of SAST pattern matching algorithms.

## Shoutouts

* Abhinav Sejpal (@Abhinav_Sejpal) - For poking me with bugs, feature requests, and UI & UX suggestions
* Anant Srivastava (@anantshri) - For Activity Tester Idea
* Anto Joseph (@antojoseph) - For the help with SuperSU
* Bharadwaj Machiraju (@tunnelshade) - For writing pyWebProxy from scratch
* Rahul (@c0dist) - Kali Support
* MindMac - For writing Android Blue Pill
* Oscar Alfonso Diaz - (@OscarAkaElvis) - For Dockerfile contributions
* Thomas Abraham - For JS Hacks on UI
* Tim Brown (@timb_machine) - For the iOS Binary Analysis Ruleset
* Shanil Prasad (@Rajuraju14) - For improving iOS ATS Analysis
* Jovan Petrovic (@JovanPetrovic) - For sponsoring a server to host mobsf.live
