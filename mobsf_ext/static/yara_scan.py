from pathlib import Path
from typing import List
try:
    import yara
except Exception:
    yara = None

def run_yara_scan(apk_path: Path, rules_dir: Path) -> List[str]:
    """yara-python 기반 스캔. 룰 파일 여러 개를 합쳐 컴파일."""
    if yara is None:
        return []

    rule_files = list(rules_dir.glob("*.yar")) + list(rules_dir.glob("*.yara"))
    if not rule_files:
        return []

    # filepaths로 여러 룰을 묶어 컴파일
    filemap = {f"rule_{i}": str(p) for i, p in enumerate(rule_files)}
    try:
        rules = yara.compile(filepaths=filemap)
        matches = rules.match(str(apk_path))
        return sorted({m.rule for m in matches})
    except Exception:
        return []