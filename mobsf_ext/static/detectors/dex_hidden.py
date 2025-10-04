import zipfile
from pathlib import Path

DEX_HEADER = b"dex\n035"

COMMON_HIDE_PREFIX = ("assets/", "res/raw/", "lib/", "assets/bin/", "assets/obj/")

def find_hidden_dex(apk_path: Path):
    """APK 내부에서 classes.dex 외의 DEX 헤더를 탐색"""
    hits = []
    with zipfile.ZipFile(apk_path, "r") as z:
        for name in z.namelist():
            lower = name.lower()
            if lower.endswith(".dex") and lower != "classes.dex":
                hits.append(name)
                continue
            if lower.startswith(COMMON_HIDE_PREFIX) or lower.endswith((".dat", ".bin", ".jar", ".zip")):
                try:
                    data = z.read(name)
                except KeyError:
                    continue
                if DEX_HEADER in data:
                    hits.append(name)
    return sorted(set(hits))