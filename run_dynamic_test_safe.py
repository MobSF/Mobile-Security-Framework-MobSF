#!/usr/bin/env python3
import frida, subprocess, time, os

# 테스트할 앱 패키지와 메인 액티비티 (Google 검색 앱)
APP_PKG = "com.android.quicksearchbox"
APP_MAIN = f"{APP_PKG}/.SearchActivity"
TEST_SECS = int(os.environ.get("TEST_SECS", "60"))

# JS 스크립트 통합 (observe_java_safe 포함)
JS_SCRIPTS = [
    os.path.join(os.path.dirname(__file__), "observe_java_safe.js"),
    os.path.join(os.path.dirname(__file__), "observe_native.js"),
    os.path.join(os.path.dirname(__file__), "bypass_java.js"),
    os.path.join(os.path.dirname(__file__), "bypass_native.js")
]

# 로그 디렉토리
BASE_LOG_DIR = "logs"
PKG_LOG_DIR = os.path.join(BASE_LOG_DIR, APP_PKG)
os.makedirs(PKG_LOG_DIR, exist_ok=True)
log_path = os.path.join(PKG_LOG_DIR, f"dynamic_log_{time.strftime('%Y%m%d_%H%M%S')}.txt")

def log_write(line: str):
    print(line)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def on_message(msg, data):
    ts = time.strftime("%H:%M:%S")
    if msg["type"] == "send":
        log_write(f"[{ts}] [FRIDA] {msg['payload']}")
    elif msg["type"] == "error":
        log_write(f"[{ts}] [FRIDA-ERR] {msg['stack']}")

def main():
    log_write(f"[*] Dynamic Test Start - Target: {APP_PKG}")
    log_write(f"[*] Logs will be saved to {log_path}")

    # 앱 재시작
    subprocess.run(["adb", "shell", "am", "force-stop", APP_PKG])
    subprocess.run(["adb", "shell", "am", "start", "-n", APP_MAIN])
    time.sleep(3)

    # Frida attach
    device = frida.get_usb_device()
    pid = device.spawn([APP_PKG])
    session = device.attach(pid)

    # JS 스크립트 로드
    for f in JS_SCRIPTS:
        with open(f, "r", encoding="utf-8") as file:
            script_content = file.read()
        script = session.create_script(script_content)
        script.on("message", on_message)
        script.load()
        log_write(f"[*] Loaded {f}")

    device.resume(pid)

    log_write(f"[*] Running dynamic test for {TEST_SECS}s...")
    time.sleep(TEST_SECS)
    log_write("[*] Test finished")

if __name__ == "__main__":
    main()
