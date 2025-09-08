from pathlib import Path

# 호환 import (여러 Androguard 버전 대응)
try:
    from androguard.core.bytecodes.apk import APK
except Exception:
    try:
        from androguard.core.apk import APK  # 일부 포크/버전
    except Exception as e:
        raise ImportError(
            "Androguard APK import 실패. venv에서 `pip install 'androguard==3.3.5'` 후 다시 시도하세요."
        ) from e

from androguard.core.bytecodes.apk import APK

DANGEROUS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
}

def manifest_findings(apk_path: Path):
    """권한/SDK 정보와 대표 위험 권한 리포트"""
    apk = APK(str(apk_path))
    perms = set(apk.get_permissions() or [])
    dangerous = sorted(p for p in perms if p in DANGEROUS)

    sdk_info = {
        "minSdkVersion": apk.get_min_sdk_version(),
        "targetSdkVersion": apk.get_target_sdk_version(),
        "maxSdkVersion": apk.get_max_sdk_version(),
    }

    return {
        "package": apk.get_package(),
        "sdk": sdk_info,
        "requested_permissions": sorted(perms),
        "dangerous_permissions": dangerous,
    }