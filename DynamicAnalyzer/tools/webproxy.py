import os
import threading

import capfuzz as cp

from capfuzz.__main__ import (
    CapFuzz
)

capfuzz = CapFuzz()

from multiprocessing import Process
import os,time

def stop_proxy():
    """Stop CapFuzz"""
    print ("[INFO] CapFuzz Instance Cleanup")
    try:
        capfuzz.signal_handler()
        print ("[INFO] CapFuzz Proxy stopped!")
    except:
        pass

def start_proxy(port, project):
    """Start CapFuzz in Proxy Mode"""
    stop_proxy()
    trd = threading.Thread(target=capfuzz.start_proxy, args=(port, "capture", project,))
    trd.daemon = False
    trd.start()
   

def start_fuzz_ui(port):
    """Start Fuzz UI"""
    trd = threading.Thread(target=capfuzz.run_fuzz_server, args=(port,))
    trd.daemon = True
    trd.start()

def get_ca_dir():
    capfuzz_dir = os.path.dirname(cp.__file__)
    return os.path.join(capfuzz_dir, "ca", "mitmproxy-ca-cert.cer")
