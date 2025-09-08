import zipfile
from pathlib import Path

MARKERS = [
    b"DexClassLoader",
    b"PathClassLoader",
    b"loadClass(",
    b"Class.forName",
    b"getMethod(",
    b"invoke(",
    b"Base64.decode",
]

TEXT_EXTS = (".xml", ".txt", ".properties", ".json")

def detect_dynamic_loading_markers(apk_path: Path):
    """DexClassLoader 등 문자열 흔적을 APK 내부에서 폭넓게 스캔"""
    suspects = []
    with zipfile.ZipFile(apk_path, "r") as z:
        for name in z.namelist():
            lname = name.lower()
            if lname.endswith(TEXT_EXTS) or lname.startswith(("assets/", "res/raw/")) or lname.endswith((".dex", ".so", ".bin", ".dat")):
                try:
                    data = z.read(name)
                except KeyError:
                    continue
                if any(m in data for m in MARKERS):
                    suspects.append(name)
    return sorted(set(suspects))

def find_native_libs(apk_path: Path):
    import zipfile
    libs = []
    with zipfile.ZipFile(apk_path, "r") as z:
        for name in z.namelist():
            if name.lower().startswith("lib/") and name.lower().endswith(".so"):
                libs.append(name)
    return sorted(libs)
