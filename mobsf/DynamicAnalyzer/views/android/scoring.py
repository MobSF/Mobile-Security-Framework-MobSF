import logging

logger = logging.getLogger(__name__)

def scoring(file_path: str):
    logs = open(file_path, 'r').read().split('\n')
    high_risk_score = 0
    suspicious_score = 0

    # High risk api calls scoring
    high_risk_score += rootDetectionScoring(logs)
    high_risk_score += debuggerCheckBypassScoring(logs)

    # Suspricious api calls scoring
    suspicious_score += dexScoring(logs)
    suspicious_score += systemChecksScoring(logs)
    suspicious_score += encodingScoring(logs)
    suspicious_score += encryptionScoring(logs)

    return {'high_risk_score': high_risk_score, 'suspicious_score': suspicious_score}


def rootDetectionScoring(logs) -> int:
    count = 0
    for line in logs:
        if "[RootDetection Bypass]" in line:
            count += 1
    return count

def debuggerCheckBypassScoring(logs) -> int:
    count = 0
    for line in logs:
        if "[Debugger Check Bypass]" in line:
            count += 1
    return count

def dexScoring(logs) -> int:
    count = 0
    for line in logs:
        if "[DexClassLoader]" in line:
            count += 1
    return count

def encodingScoring(logs) -> int:
    count = 0
    for line in logs:
        if "[Base64]" in line:
            count += 1
    return count

def encryptionScoring(logs) -> int:
    count = 0
    for line in logs:
        if "[Encryption]" in line:
            count += 1
    return count

def systemChecksScoring(logs) -> int:
    count = 0
    for line in logs:
        if "[System Check]" in line:
            count += 1
    return count
