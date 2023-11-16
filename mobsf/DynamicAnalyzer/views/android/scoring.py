import logging
import math

logger = logging.getLogger(__name__)

def scoring(file_path: str):
    logs = open(file_path, 'r').read().split('\n')

    # Detect Initialised Scripts
    initialisations = []
    for line in logs:
        if "[Initialised]" in line:
            initialisations.append(line)

    critical_score = []
    suspicious_score = []

    # High risk api calls scoring
    if "[Initialised] RootDetection Bypass" in initialisations:
        critical_score.append(rootDetectionScoring(logs))
        critical_score.append(listProcessScoring(logs))
    if "[Initialised] DebuggerCheck Bypass" in initialisations:
        critical_score.append(debuggerCheckBypassScoring(logs))
    if "[Initialised] HideApp" in initialisations:
        critical_score.append(hideAppIconScoring(logs))

    # Suspricious api calls scoring
    if "[Initialised] DexClassLoader" in initialisations:
        suspicious_score.append(dexScoring(logs))
    if "[Initialised] SystemChecks" in initialisations:
        suspicious_score.append(systemChecksScoring(logs))
    if "[Initialised] Base64" in initialisations:
        suspicious_score.append(encodingScoring(logs))
    if "[Initialised] Encryption" in initialisations:
        suspicious_score.append(encryptionScoring(logs))
    if "[Initialised] MediaRecorder" in initialisations:
        suspicious_score.append(mediaRecorderScoring(logs))
    if "[Initialised] SensitiveDataAccess" in initialisations:
        suspicious_score.append(localDataScoring(logs))

    # Combining Scores
    critical_score = combine(critical_score)
    suspicious_score = combine(suspicious_score)

    malware_score = malware_scoring(critical_score, suspicious_score)

    return {'malware_score': malware_score,'critical_score': critical_score[0], 'critical_score_max': critical_score[1], 'suspicious_score': suspicious_score[0], 'suspicious_score_max': suspicious_score[1]}



# Individual Category Scoring
def rootDetectionScoring(logs: list[str]) -> tuple[int, int]:
    for line in logs:
        if "[RootDetection Bypass]" in line:
            return 1, 1
    return 0, 1

def listProcessScoring(logs: list[str]) -> tuple[int, int]:
    for line in logs:
        if "[List Processes]" in line:
            return 1, 1
    return 0, 1

def debuggerCheckBypassScoring(logs: list[str]) -> tuple[int, int]:
    for line in logs:
        if "[Debugger Check Bypass]" in line:
            return 1, 1
    return 0, 1

def dexScoring(logs: list[str]) -> tuple[int, int]:
    for line in logs:
        if "[DexClassLoader]" in line:
            return 1, 1
    return 0, 1

def encodingScoring(logs: list[str]) -> tuple[int, int]:
    for line in logs:
        if "[Base64]" in line:
            return 1, 1
    return 0, 1

def encryptionScoring(logs: list[str]) -> tuple[int, int]:
    for line in logs:
        if "[Encryption]" in line:
            return 1, 1
    return 0, 1

def systemChecksScoring(logs: list[str]) -> tuple[int, int]:
    filteredLogs = []
    deviceSerial = False
    phoneNumber = False
    subscriberId = False
    imei = False
    simOperator = False
    simOperatorName = False
    simSerial = False
    country = False
    bluetoothMAC = False
    wifiMAC = False
    wifiSSID = False
    routerMAC = False

    for line in logs:
        if "[System Check" in line:
            filteredLogs.append(line)

    for line in filteredLogs:
        if "[SystemCheck.DeviceSerial]" in line:
            deviceSerial = True
        elif "[SystemCheck.PhoneNumber]" in line:
            phoneNumber = True
        elif "[SystemCheck.SubscriberID]" in line:
            subscriberId = True
        elif "[SystemCheck.IMEI]" in line:
            imei = True
        elif "[SystemCheck.SIMOperator]" in line:
            simOperator = True
        elif "[SystemCheck.SIMOperatorName]" in line:
            simOperatorName = True
        elif "[SystemCheck.Country]" in line:
            country = True
        elif "[NetworkCheck.BluetoothMAC]" in line:
            bluetoothMAC = True
        elif "[NetworkCheck.WifiMAC]" in line:
            wifiMAC = True
        elif "[NetworkCheck.WifiSSID]" in line:
            wifiSSID = True
        elif "[NetworkCheck.RouterMAC]" in line:
            routerMAC = True

    return (deviceSerial + phoneNumber + subscriberId + imei + simOperator + simOperatorName + simSerial + country + bluetoothMAC + wifiMAC + wifiSSID + routerMAC), 11

def mediaRecorderScoring(logs: list[str]) -> tuple[int, int]:
    filteredLogs = []
    audio = False
    video = False

    for line in logs:
        if "[Media Recorder" or "[Audio Record]" in line:
            filteredLogs.append(line)

    for line in filteredLogs:
        if "[Media Recorder.Audio]" or "[Audio Record]" in line:
            audio = True
        elif "[Media Recorder.Video]" in line:
            video = True

    return (audio + video), 2

def hideAppIconScoring(logs: list[str]) -> tuple[int, int]:
    for line in logs:
        if "[Hide App]" in line:
            return 1, 1
    return 0, 1

def localDataScoring(logs: list[str]) -> tuple[int, int]:
    filteredLogs = []
    contacts = False
    callLog = False
    sms = False

    for line in logs:
        if "[Access" in line:
            filteredLogs.append(line)

    for line in filteredLogs:
        if "[Access.Contacts]" in line:
            contacts = True
        elif "[Access.CallLogs]" in line:
            callLog = True
        elif "[Access.SMS]" in line:
            sms = True

    return (contacts + callLog + sms), 3



def malware_scoring(critical_score: tuple[int, int], suspicious_score):
    malware_score = round(100 * (1 - (math.exp(-critical_score[0])) + (math.exp(-critical_score[0]) * suspicious_score[0] / suspicious_score [1])), 2)
    return malware_score

def combine(score_list) -> tuple[int, int]:
    score = 0
    max_score = 0
    for i in score_list:
        score += i[0]
        max_score += i [1]
    return score, max_score