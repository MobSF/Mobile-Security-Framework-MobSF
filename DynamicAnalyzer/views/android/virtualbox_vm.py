import time
import subprocess
from MobSF.utils import PrintException


def refresh_vm(uuid, snapshot_uuid, vbox_exe):
    """Refresh VirtualBox based VMs"""
    print("\n[INFO] Refreshing MobSF VM")
    try:
        if not vbox_exe:
            print("[ERROR] VirtualBox not found, Manually set VBOXMANAGE_BINARY in settings.py")
        # Close VM
        args = [vbox_exe, 'controlvm', uuid, 'poweroff']
        subprocess.call(args)
        print("\n[INFO] VM Closed")
        time.sleep(3)
        # Restore Snapshot
        args = [vbox_exe, 'snapshot', uuid, 'restore', snapshot_uuid]
        subprocess.call(args)
        print("\n[INFO] VM Restore Snapshot")
        # Start Fresh VM
        args = [vbox_exe, 'startvm', uuid]
        subprocess.call(args)
        print("\n[INFO] VM Starting")
    except:
        PrintException("[ERROR] Refreshing MobSF VM")
