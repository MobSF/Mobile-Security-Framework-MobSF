import time
import subprocess
import logging
from MobSF.utils import PrintException
from django.conf import settings
logger = logging.getLogger(__name__)


def refresh_vm(uuid, snapshot_uuid, vbox_exe):
    """Refresh VirtualBox based VMs"""
    logger.info("Refreshing MobSF VM")
    try:
        if not vbox_exe:
            logger.error("VirtualBox not found, Manually set VBOXMANAGE_BINARY in settings.py")
        # Close VM
        args = [vbox_exe, 'controlvm', uuid, 'poweroff']
        subprocess.call(args)
        logger.info("VM Closed")
        time.sleep(3)
        # Restore Snapshot
        args = [vbox_exe, 'snapshot', uuid, 'restore', snapshot_uuid]
        subprocess.call(args)
        logger.info("VM Restore Snapshot")
        # Start Fresh VM
        args = [vbox_exe, 'startvm', uuid]
        if settings.VBOX_HEADLESS:
            args += ['--type', 'headless']
        subprocess.call(args)
        logger.info("VM Starting")
    except:
        PrintException("[ERROR] Refreshing MobSF VM")
