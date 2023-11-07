import logging

logger = logging.getLogger(__name__)

def scoring(file_path: str):
    logs = open(file_path, 'r').read().split('\n')

    critical_score = []
    suspicious_score = []

    # High risk api calls scoring
    critical_score.append(rootDetectionScoring(logs))
    critical_score.append(debuggerCheckBypassScoring(logs))

    # Suspricious api calls scoring
    suspicious_score.append(dexScoring(logs))
    suspicious_score.append(systemChecksScoring(logs))
    suspicious_score.append(encodingScoring(logs))
    suspicious_score.append(encryptionScoring(logs))

    # Combining Scores
    critical_score = combine(critical_score)
    suspicious_score = combine(suspicious_score)

    return {'critical_score': critical_score[0], 'critical_score_max': critical_score[1], 'suspicious_score': suspicious_score[0], 'suspicious_score_max': suspicious_score[1]}



def rootDetectionScoring(logs) -> tuple[int, int]:
    for line in logs:
        if "[RootDetection Bypass]" in line:
            return 1, 1
    return 0, 1

def debuggerCheckBypassScoring(logs) -> tuple[int, int]:
    for line in logs:
        if "[Debugger Check Bypass]" in line:
            return 1, 1
    return 0, 1

def dexScoring(logs) -> tuple[int, int]:
    for line in logs:
        if "[DexClassLoader]" in line:
            return 1, 1
    return 0, 1

def encodingScoring(logs) -> tuple[int, int]:
    for line in logs:
        if "[Base64]" in line:
            return 1, 1
    return 0, 1

def encryptionScoring(logs) -> tuple[int, int]:
    for line in logs:
        if "[Encryption]" in line:
            return 1, 1
    return 0, 1

def systemChecksScoring(logs) -> tuple[int, int]:
    for line in logs:
        if "[System Check]" in line:
            count += 1
    return 0, 1



def combine(score_list) -> tuple[int, int]:
    score = 0
    max_score = 0
    for i in score_list:
        score += i[0]
        max_score += i [1]
    return score, max_score