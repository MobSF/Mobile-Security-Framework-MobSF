# MobSF Android Security Improvements

## Overview
This document describes the comprehensive security improvements and modernization updates implemented for MobSF's Android analysis capabilities, with focus on supporting modern Android versions (14/15) and contemporary rooting methods.

## Implementation Date
November 6, 2025

---

## 1. Enhanced Root Detection Bypass (Dynamic Analysis)

### File Modified
- `mobsf/DynamicAnalyzer/tools/frida_scripts/android/default/root_bypass.js`

### Changes Implemented

#### 1.1 Modern Root Package Detection
Added support for detecting and bypassing modern root management solutions:

**New Packages Supported:**
- **Magisk** (Official and Forks)
  - `com.topjohnwu.magisk`
  - `io.github.huskydg.magisk`
  - `com.topjohnwu.magisk.canary`

- **KernelSU**
  - `me.weishu.kernelsu`

- **APatch**
  - `io.github.apatch`
  - `me.tool.passkey`

#### 1.2 Modern Root Binary Detection
Extended binary detection to include:
- `magisk`, `magisk32`, `magisk64`
- `magiskhide`, `magiskpolicy`, `magiskinit`
- `resetprop`
- Modern su implementations

#### 1.3 Modern Root Paths
Added comprehensive path checking for:

**Magisk Paths:**
- `/data/adb/magisk`
- `/data/adb/modules`
- `/data/adb/post-fs-data.d`
- `/data/adb/service.d`
- `/sbin/.magisk`, `/cache/.magisk`
- `/metadata/.magisk`, `/persist/.magisk`
- `/dev/magisk/mirror`

**KernelSU Paths:**
- `/data/adb/ksu`
- `/data/adb/ksud`

**APatch Paths:**
- `/data/adb/ap`
- `/data/adb/apd`

#### 1.4 Enhanced System Properties Spoofing
Added modern bootloader and security properties:
- `ro.boot.verifiedbootstate` → green
- `ro.boot.flash.locked` → 1
- `ro.boot.veritymode` → enforcing
- `ro.boot.warranty_bit` → 0
- `ro.warranty_bit` → 0
- `sys.oem_unlock_allowed` → 0

#### 1.5 New Bypass Capabilities

**SELinux Detection Bypass:**
- Hooks `android.os.SELinux.isSELinuxEnabled()`
- Hooks `android.os.SELinux.isSELinuxEnforced()`
- Returns proper values to indicate enforcing mode

**Build.TAGS Modification:**
- Dynamically changes `Build.TAGS` from `test-keys` to `release-keys`
- Prevents detection via build signature checking

**Mount Namespace Detection:**
- Filters suspicious mount entries (magisk, zygisk, kernelsu, apatch)
- Prevents detection via `/proc/mounts` parsing

**RootBeer Library Bypass:**
- Complete bypass for standalone RootBeer library usage
- Hooks all detection methods:
  - `isRooted()`
  - `isRootedWithoutBusyBoxCheck()`
  - `detectRootManagementApps()`
  - `checkForMagiskBinary()`

**Google Play Integrity API:**
- Hooks for Play Integrity Manager
- SafetyNet API interception (legacy)

**Enhanced File.exists() Bypass:**
- Checks both file names and full paths
- Blocks detection of modern root paths
- Improved logging for debugging

---

## 2. Android 14/15 Manifest Analysis

### Files Modified
- `mobsf/StaticAnalyzer/views/android/manifest_analysis.py`
- `mobsf/StaticAnalyzer/views/android/kb/android_manifest_desc.py`

### Changes Implemented

#### 2.1 New API Level Constants
```python
ANDROID_13_0_LEVEL = 33  # Android 13
ANDROID_14_0_LEVEL = 34  # Android 14
ANDROID_15_0_LEVEL = 35  # Android 15
```

#### 2.2 Android 14+ Security Checks

**Foreground Service Type Detection:**
- **Rule:** `has_foreground_service_type`
- **Level:** Info
- **Purpose:** Validates that services declare proper foreground service types as required by Android 14
- **Valid Types:** camera, connectedDevice, dataSync, health, location, mediaPlayback, mediaProjection, microphone, phoneCall, remoteMessaging, shortService, specialUse, systemExempted

**Missing Foreground Service Type Warning:**
- **Rule:** `missing_foreground_service_type_android14`
- **Level:** Warning
- **Purpose:** Warns about services that may fail on Android 14+ due to missing type declaration
- **Impact:** Apps will throw `MissingForegroundServiceTypeException` on Android 14+

**Predictive Back Gesture Support:**
- **Rule:** `predictive_back_enabled`
- **Level:** Info
- **Purpose:** Detects if app supports Android 14's predictive back gesture
- **Implementation:** Checks for `android:enableOnBackInvokedCallback="true"`

**Predictive Back Gesture Warning:**
- **Rule:** `predictive_back_not_enabled_android14`
- **Level:** Info
- **Purpose:** Recommends implementing predictive back for better UX

#### 2.3 Android 13+ Privacy Checks

**Legacy Photo/Media Access Detection:**
- **Rule:** `uses_legacy_photo_access_android13`
- **Level:** Warning
- **Purpose:** Identifies apps using legacy `READ_MEDIA_IMAGES` or `READ_MEDIA_VIDEO` permissions
- **Recommendation:** Migrate to Photo Picker API for better privacy
- **Benefit:** Reduces permission scope, improves user privacy

---

## 3. Modern Root Detection Module (Static Analysis)

### New File Created
- `mobsf/StaticAnalyzer/views/android/modern_root_detection.py`

### Module Capabilities

#### 3.1 Package Detection
Scans decompiled code for references to:
- Magisk packages (official and forks)
- KernelSU packages
- APatch packages
- Legacy root packages (SuperSU, etc.)

**Detection Methods:**
- Java source code scanning
- Smali bytecode analysis
- Package name pattern matching

#### 3.2 String Analysis
Detects hardcoded root artifacts:
- Root binary paths
- Root binary names
- Suspicious build properties
- Mount points

**Resources Scanned:**
- XML resource files
- Text files
- String resources

#### 3.3 Native Library Detection
Identifies root detection libraries:
- `librootbeer`
- `libmagisk`
- `libsafetynet`
- `libintegrity`
- Custom root check libraries

#### 3.4 Risk Assessment
Automatically calculates risk levels:
- **High:** 10+ evidence points
- **Medium:** 5-10 evidence points
- **Low:** <5 evidence points

#### 3.5 Actionable Recommendations
Provides specific guidance based on detected root methods:
- Magisk → Use Magisk Hide/Zygisk DenyList
- KernelSU → Use KernelSU hide features
- APatch → Enable APatch hiding
- File-based detection → Use mount namespace isolation
- Native detection → Frida bypass required

### API Usage
```python
from mobsf.StaticAnalyzer.views.android.modern_root_detection import analyze_modern_root_detection

results = analyze_modern_root_detection(app_dir)

# Returns:
{
    'has_root_detection': bool,
    'root_packages': {...},
    'root_strings': {...},
    'root_libraries': {...},
    'risk_level': 'low|medium|high',
    'recommendations': [...]
}
```

---

## 4. Technical Improvements Summary

### 4.1 Compatibility
- ✅ Supports Android API 1-36 (Android 1.0 - Android 16)
- ✅ Special handling for Android 13, 14, 15 specific features
- ✅ Backward compatible with existing analyses

### 4.2 Security Enhancements
- ✅ Modern root method detection (Magisk, KernelSU, APatch)
- ✅ Zygisk framework awareness
- ✅ Mount namespace isolation detection
- ✅ SELinux status verification
- ✅ Play Integrity API hooks

### 4.3 Code Quality
- ✅ Comprehensive logging for debugging
- ✅ Error handling for all new features
- ✅ Documentation in code comments
- ✅ Follows existing code patterns

### 4.4 Analysis Depth
- ✅ Static analysis for root detection code
- ✅ Dynamic analysis bypass capabilities
- ✅ Risk-based severity assessment
- ✅ Actionable security recommendations

---

## 5. Testing Recommendations

### 5.1 Dynamic Analysis Testing
Test the enhanced root bypass with:
1. **Magisk**
   - Latest stable version
   - Canary builds
   - Zygisk modules

2. **KernelSU**
   - Latest release
   - With and without hide features

3. **APatch**
   - Current version
   - Various hide configurations

### 5.2 Static Analysis Testing
Test with APKs that include:
1. RootBeer library
2. Custom root detection code
3. SafetyNet/Play Integrity checks
4. Native (.so) root detection

### 5.3 Android 14/15 Testing
Test manifest analysis with:
1. Apps targeting API 34 (Android 14)
2. Apps targeting API 35 (Android 15)
3. Foreground services with/without types
4. Predictive back gesture implementations

---

## 6. Migration Guide

### For Existing MobSF Users

#### No Action Required
All improvements are backward compatible. Existing scans will automatically benefit from:
- Enhanced root detection bypass
- New Android 14/15 checks
- Modern root method awareness

#### Optional: Enable New Module
To use the modern root detection static analysis:

```python
# In your static analysis flow
from mobsf.StaticAnalyzer.views.android.modern_root_detection import analyze_modern_root_detection

# Add to analysis results
root_analysis = analyze_modern_root_detection(app_dir)
```

---

## 7. Known Limitations

### 7.1 Root Bypass
- May not bypass all custom implementations
- Requires Frida for dynamic analysis
- Some SafetyNet attestations may still fail (hardware attestation)

### 7.2 Static Analysis
- Cannot detect obfuscated root checks
- Native library analysis is signature-based
- May produce false positives on security apps

### 7.3 Android Version Support
- Some Android 15 features may not be final
- Android 16 support is based on preview releases

---

## 8. Future Enhancements

### Planned Improvements
1. **Shamiko Module Detection**
   - Detect and bypass Shamiko-based hiding
   - Whitelist analysis

2. **Play Integrity Verdict Analysis**
   - Parse integrity verdicts
   - Provide detailed attestation analysis

3. **Root Hiding Detection**
   - Detect if app is root-hiding aware
   - Assess hiding effectiveness

4. **Android 16 Features**
   - Stay updated with final Android 16 release
   - Add new security checks as announced

---

## 9. References

### Documentation
- [Android 14 Behavior Changes](https://developer.android.com/about/versions/14/behavior-changes-14)
- [Android 15 Behavior Changes](https://developer.android.com/about/versions/15/behavior-changes-15)
- [Foreground Service Types](https://developer.android.com/about/versions/14/changes/fgs-types-required)
- [Predictive Back Gesture](https://developer.android.com/guide/navigation/custom-back/predictive-back-gesture)

### Root Methods
- [Magisk Official](https://github.com/topjohnwu/Magisk)
- [KernelSU](https://github.com/tiann/KernelSU)
- [APatch](https://github.com/bmax121/APatch)

### Security Libraries
- [RootBeer](https://github.com/scottyab/rootbeer)
- [SafetyNet/Play Integrity](https://developer.android.com/google/play/integrity)

---

## 10. Contributors

These improvements were implemented to modernize MobSF's Android security testing capabilities and ensure compatibility with the latest Android versions and rooting methods.

For questions or issues related to these improvements, please refer to the main MobSF issue tracker.

---

## Changelog

### Version 4.4.3+ (November 2025)
- ✅ Added modern root detection bypass (Magisk, KernelSU, APatch)
- ✅ Implemented Android 14/15 specific security checks
- ✅ Created modern root detection static analysis module
- ✅ Enhanced Frida scripts for contemporary rooting methods
- ✅ Added comprehensive documentation
