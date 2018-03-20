import os
import time
import requests
import subprocess

import capfuzz as cp

'''
from capfuzz.__main__ import (
    CapFuzz
)
'''


def stop_capfuzz(port):
    """CapFuzz Kill"""
    # Invoke CapFuzz UI Kill Request
    try:
        requests.get("http://127.0.0.1:" + str(port) + "/kill", timeout=5)
        print("[INFO] Killing CapFuzz UI")
    except:
        pass

    # Inkoke CapFuzz Proxy Kill Request
    try:
        http_proxy = "http://127.0.0.1:" + str(port)
        headers = {"capfuzz": "kill"}
        url = "http://127.0.0.1"
        requests.get(url, headers=headers, proxies={
                     'http': http_proxy})
        print("[INFO] Killing CapFuzz Proxy")
    except:
        pass


def start_proxy(port, project):
    """Start CapFuzz in Proxy Mode"""
    subprocess.Popen(["capfuzz",
                      "-m", "capture", "-p", str(port), "-n", project])
    """
    capfuzz_obj = CapFuzz()
    proxy_trd = Thread(target=capfuzz_obj.start_proxy,
                       args=(port, "capture", project,))
    proxy_trd.daemon = True
    proxy_trd.start()
    """


def start_fuzz_ui(port):
    """Start Fuzz UI"""
    subprocess.Popen(["capfuzz",
                      "-m", "fuzz", "-p", str(port)])
    time.sleep(3)
    """
    capfuzz_obj = CapFuzz()
    ui_trd = Thread(target=capfuzz_obj.run_fuzz_server, args=(port,))
    ui_trd.daemon = True
    ui_trd.start()
    """


def get_ca_dir():
    """Get CA Dir"""
    capfuzz_dir = os.path.dirname(cp.__file__)
    return os.path.join(capfuzz_dir, "ca", "mitmproxy-ca-cert.cer")
