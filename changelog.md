### v3.0.1 Beta Changelog
- Features or Enhancements
   - Simplified REST API
   - Improved Android App Name detection
   - Dynamic Analysis proper Root CA naming
   - Changes to Support Android x86 Docker
   - Dependency updates
   - Code QA

- Bug Fixes
  - Handle Invalid ATS domain entries iOS
  - Fixes a Template Bug

### v3.0.0 Beta Changelog
- Features or Enhancements
   - OWASP Mobile Top 10 2016 is supported
   - Major UI Update for MobSF
   - Major Schema changes to rest API
   - iOS URLs Scheme
   - iOS ATS Analysis improved
   - New iOS Static Analysis Rules
   - New iOS Static Analysis Rules
   - New Android Manifest Analysis Rules
   - Updated dependencies
   - Optimized Windows Setup
   - Updated Scoring mechanisms
   - Improved Tracker detection
   - Remove Global Proxy after dynamic analysis
   - Android Permission database update
   - Added Play with Docker support 
   - AppMonsta support
   - Code QA

- Bug Fixes
  - Fix Security issue #1197 (Directory Traversal)
  - iOS Static Analyzer fixes
  - Typo Fix
  - Moved to oscrypto and distro
  - Windows binscope bug fix
  - Reduce False positives 

### v2.0.0 Beta Changelog
- Features or Enhancements
   - Dynamic Analysis Support for Genymotion Android VMs 4.1 -9.0 x86
   - Improved Recent Scan
   - Replaced CapFuzz with HTTPtools
   - Automatic MobSFy with Xposed and Frida
   - Streaming logcat
   - Live API Monitor
   - Better SQlite DB View
   - Inbuilt Frida scripts for basic tasks
   - Custom Frida Script support
   - Frida Log Viewer
   - UI Changes
   - Browser PDF print support
   - Updated Tools
   - Baksmali performance improvements
   - Improved malware domain check
   - Multi OS Travis Support
   - Code QA

- Bug Fixes
  - Typo Fix
  - Reduce False positives 

### v1.1.6 Beta Changelog
- Features or Enhancements
   - 70x performance improvements for large APKs
   - CVSS, CWE tagging with results
   - Trackers Detection
   - App Store/ Playstore Details of supported packages
   - Added Security Score, Average CVSS Score, VirusTotal & Tracker Detection
   - Coloured logging
   - Better Logging and Exception Handling
   - Travis CI/CD integration
   - Optimized & Updated Dockerfile
   - Super fast java decompiling with JADX
   - Large scale Code QA
   - Enforced mandatory code linting
   - Integrated automated travis tests in Linux and OSX
   - Moved to proper production servers Gunicorn & Waitress
   - Improved icon detection
   - Android APK app real name
   - Moved from Oracle JDK to OpenJDK
   - Reduce False Positives
   - Enforced Least privilege mode
   - Improved Setup scripts
   - Moved to androguard based certificate printing
   - File less local db updates for better cross platform support
   - Static Analyzer rule updates and accuracy improvement
   - REST API - Recent Scans
   - classdump support for iOS swift binaries
   - Updated dependencies

- Bug Fixes
  - Fixed bug in Appx Analysis
  - Dynamic Analysis Bug Fix
  - Fix plist bug in iOS SCA
  - Performance Improvements
  
### v1.0.3 Beta Changelog
- Features or Enhancements
   - Android APK Scan Results Diffing Support
   - VirtualBox VM Headless mode
   - UI Changes
   - Improved Android icon analysis
   - CapFuzz for API Fuzzing
   - JSON Report REST API
   - Dependency Updates
   - Code QA and Refactoring
   - More unit tests
   - Update 3rd party tools
   - Improved APKiD Scans
   - Added Basic Environment Checks on first run
   - Docker support for PostgreSQL
   - Improved REST APIs
   - Android AVD 6 Support (Broken)
   - iOS IPA Analysis support in Linux
   - Improved Form Handling
   - REST API CORS Support
   - Improved Plist Parsing
   - Removed Faulty Binary Analysis
   - Improved Manifest Analysis
   - Updated Android Permission Mappings
   - New Setup and Run scripts for easy installation and usage
   - Updated Dockerfile
   - Multi Dex Support
   - Upstream Proxy Support
   - Improved String Extraction for Android

- Bug Fixes
  - Fixed manifest view
  - Performance improvements
  - Find Java Bug fixes
  - Fixed APK String extraction
  - Fixed Regression Bug
  - Fixed Byte Bug

### v0.9.5.4 Beta Changelog
- Features or Enhancements
   - REST API for MobSF and API Docs
   - Icon Extractor Android Static Analysis
   - Updating Libraries to latest
   - Malware Analysis Code refactoring
   - Updated ADB binaries
   - Code Refactoring Android Static Analysis
   - Android and iOS new static analysis rules added

- Bug Fixes
  - iOS file analysis bug fix
  - iOS Classdump exception fix
  - Unicode Unzip fix
  - sqlitedb isinstance bug fix
  - Dockerfile error fix
  - Bug Fix in skip classes
  - Bug Fix in https traffic decryption due to tornado upgrade
  - iOS Binary analysis regex fix
  - Android binary analysis bug fix

### v0.9.5.2 Beta Changelog

* Features or Enhancements
  * Supports Android ARM Emulator for Android Dynamic Analysis. Thanks to Matan Dobrushin - [Documentation](https://github.com/MobSF/Mobile-Security-Framework-MobSF/wiki/1.-Documentation#configuring-dynamic-analyzer-with-with-mobsf-android-412-arm-emulator)
  * Android Dynamic Analysis Code QA and Refactoring
  * Delete Scan Results from DB and related files under Recent Scan
  * Detects Apps Signed with SHA1-RSA
  * Added APKiD to MobSF Android APK Static Analysis
  * Python Dependency updates
  * Dockerfile updated
  * Added unit test for delete scan
  
* Bug Fixes
  * Fixed Android Certificate Analyzer find match bug
  * Android Static Analyzer content provider rules bug fix
  * Windows Static Analyzer Bugfixes
  * Moved from buggy syntaxhighlighter to highlightjs

### v0.9.4 Beta Changelog

* Features or Enhancements
  * Android Binary/ELF Analysis and Resource Analysis
  * Android App Static Analysis: Tapjacking Detection
  * Android App Static Analysis: Better Exported Component Analysis
  * iOS App Static Analysis: Listing App Permissions
  * iOS App Static Analysis: ATS Check
  * Better and Faster PDF Generation
  * Updated Dependencies
  * Optimised DB Interactions
  * Unit Tests for Static Analyzer, PDF Report Generation

* Bug Fixes
  * Windows App Static Analyzer Bug Fix
  * Fixed all PDF Related Bugs
  * Windows App Static Analyzer: BinScope Bug Fix
  * iOS App Static Analysis: Plist Bug Fix

### v0.9.3 Beta Changelog


* Features or Enhancements
  * Added Docker File
  * Clipboard Monitor for Android Dynamic Analysis
  * Windows APPX Static Analysis Support
  * Added Support for Kali Linux
  * Code Quality and Lintering
  * Partial PEP8 Formating, Code Refactoring and Restructuring
  * Imporved Static Analyzer Regex
  * Disabling Syntax Highlighter Edit mode
  * More MIME Type additions
  * Update File Upload Size to 100 MB
  * MobSFfy script to support commandline args
  * New strings.py tool for string extraction in iOS Apps.
  * Updated iOS Static Analysis ruleset.
  * Django Upgrade to 1.10
  * MobSF VM 0.3 Released

* Bug Fixes
  * Fixed Code Analyis Regex Error
  * Fixed iOS Binary Analyis and File Analysus PDF Generation bug
  * API Fuzzer Bug Fixes
  * SQLite3 Bug Fix
  * Fixed Bug when no code signing cert is present
  * Fixed Bug in xhtml2pdf
  * Dynamic Analysis Bug Fixes
  * Unicode Bug Fixes
  * Fixed MobSFy upload error
  * Fixed Variable redefining bug

* Security Fixes
  * Fixed Local File Inclusion casued due to incorrect regex

### v0.9.2 Beta Changelog

* Features
  * Drag and Drop support, allows upto 8 files in Web GUI
  * Mass Static Analysis - Mass static analysis on a directory of app binaries or zipped source code
  * Domain Malware check
  * CFR Decompiler updated to 0_115
  * Added Google Enjarify
  * Added procyon decompiler
  * Allows user to skip inbuilt android classes. (Performance improvement ~ 20%)
  * Android Code signing certificate check
  * Detect hardcoded Keystores
  * Static Analyzer rules updated for Android and iOS
  * Better Android Manifest analysis rule set
  * Dynamic Analysis Base64 Decoding
  * Support for Home Directory - Move all user created files and settings to Home directory

* Bug Fix
  * Dynamic Analyzer report print in Landscape mode
  * Windows fix for command prompt color support
  * Fixed Upper case file extension bug
  * PDF Creator unicode error fixed
  * Fixed manifest analyzer bug
  * Ptrace API recommendation enhancement

### v0.9.1 Beta Changelog

* Minor Bug Fixes
* Static Analyzer rules updated

### v0.9 Beta Changelog

* Improved and Responsive UI
* Search stored Static Analysis reports with APK MD5
* Recent Scan View
* Added Live Device/VM ScreenCast on Dynamic Analyzer view
* Added Basic Touch event based Interaction with ScreenCast
* Better Error Handling and Logging
* Improved Web Proxy
* Added a centralized log file for MobSF
* A new UI component to show the count of vulnerable components of Android App
* Tooltips explaining code nature
* All new API Fuzzer that can do Information Gathering, detect Security Headers, identify vulnerabilities like XXE, SSRF, Path Traversal, IDOR, Rate Limit Checking and perform Session related logical checks.
api tester
* Update APKs and pushed them to VM
* Updated and stable MobSF VM 0.2
* Added rules to static analyzer
* Added Custom VM and Android Device Support for MobSF Dynamic Analysis
* MobSF VM can now bypass Anti-Emulator Checks
* Support for Dynamically Installing and Removing MobSF RootCA
* Bug Fixes
  * Fixed Java path finding issue in windows
  * Fixed Set-Cookie Handling issue of Web Proxy
  * Fixed some UI issues
  * Fixed a bug in finding VirtualBox path in Mac and Linux

### v0.8.8 Beta Changelog

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

### v0.8.7 Beta Changelog

* Improved Static Analysis Rules
* Better AndroidManifest View
* Search in Files

### v0.8.6 Beta Changelog

* Detects implicitly exported component from manifest.
* Added CFR decompiler support 
* Fixed Regex DoS on URL Regex

### v0.8.5 Beta Changelog

* Bug Fix to support IPA MIME Type: application/x-itunes-ipa

### v0.8.4 Beta Changelog

* Improved Android Static Code Analysis speed (2X performance)
* Static Code analysis on Dexguard protected APK.
* Fixed a Security Issue - Email Regex DoS.
* Added Logging Code.
* All Browser Support.
* MIME Type Bug fix to Support IE.
* Fixed Progress Bar.

### v0.8.3 Beta Changelog
 
* View AndroidManifest.xml & Info.plist
* Supports iOS Binary (IPA)
* Bug Fix for Linux (Ubuntu), missing MIME Type Detection
* Check for Hardcoded Certificates
* Added Code to prevent from Directory Traversal
