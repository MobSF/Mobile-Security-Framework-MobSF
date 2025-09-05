#!/usr/bin/env python3
import sys, json
from pathlib import Path

from detectors.dex_hidden import find_hidden_dex
from detectors.dynamic_loading import detect_dynamic_loading_markers
from detectors.manifest_check import manifest_findings
from yara_scan import run_yara_scan

def main():
    if len(sys.argv) < 2:
        print("Usage: analyze_apk.py <path-to-apk>")
        sys.exit(1)

    apk_path = Path(sys.argv[1]).resolve()
    if not apk_path.exists():
        print(json.dumps({"error": "apk not found", "path": str(apk_path)}))
        sys.exit(2)

    result = {
        "apk": str(apk_path),
        "checks": {
            "hidden_dex_paths": [],
            "dynamic_loading_markers": [],
            "manifest": {},
            "yara_matches": []
        },
        "score": 0,
        "summary": ""
    }

    # 1) 숨겨진/은닉 DEX
    result["checks"]["hidden_dex_paths"] = find_hidden_dex(apk_path)

    # 2) DexClassLoader 등 런타임 로딩 흔적
    result["checks"]["dynamic_loading_markers"] = detect_dynamic_loading_markers(apk_path)

    # 3) Manifest 위험 권한 / SDK 정보 (Androguard 사용)
    result["checks"]["manifest"] = manifest_findings(apk_path)

    # 4) YARA 매치
    rules_dir = Path(__file__).resolve().parent / "yara" / "rules"
    result["checks"]["yara_matches"] = run_yara_scan(apk_path, rules_dir)

    # 5) 아주 러프한 점수화
    score = 0
    if result["checks"]["hidden_dex_paths"]:
        score += 40
    if result["checks"]["dynamic_loading_markers"]:
        score += 30
    if result["checks"]["manifest"].get("dangerous_permissions"):
        score += min(30, 5 * len(result["checks"]["manifest"]["dangerous_permissions"]))
    if result["checks"]["yara_matches"]:
        score += 30
    result["score"] = min(100, score)

    flags = []
    if result["checks"]["hidden_dex_paths"]:
        flags.append("은닉/암호화 DEX 의심")
    if result["checks"]["dynamic_loading_markers"]:
        flags.append("런타임 DEX 로딩 흔적")
    if result["checks"]["manifest"].get("dangerous_permissions"):
        flags.append("위험 권한 요청")
    if result["checks"]["yara_matches"]:
        flags.append("YARA 매치 있음")

    result["summary"] = " / ".join(flags) if flags else "특이점 미검출(정적 1차 패스)"
    out_file = Path("outputs") / (apk_path.stem + ".json")
    out_file.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] 결과 저장 완료: {out_file}")
    print(json.dumps(result, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()