import subprocess
import logging
import os

logging.basicConfig(format='%(message)s', level=logging.INFO)

# Starts a fresh copy of the VM
# Change the VM name if using a different one
def wipe_vm():
    
    # Specify the emulator executable filename
    emulator_filename = "emulator.exe"

    # Get the value of the APPDATA environment variable
    appdata_path = os.environ.get("AppData")

    if appdata_path is None:
        logging.info("APPDATA environment variable not found. Please specify the emulator path manually.")
        return
    else:
        logging.info("appdata_path is valid")
    
    appdata_components = appdata_path.split(os.sep)
    appdata_directory = os.sep.join(appdata_components[:-1])

    # Construct the emulator path based on the APPDATA environment variable
    emulator_path = os.path.join(appdata_directory, "Local/Android/Sdk/emulator", emulator_filename)

    if not os.path.isfile(emulator_path):
        logging.info("Emulator executable not found. Please specify the path manually.")
        return
    else:
        logging.info("starting android studios emulator")

    cmd = [emulator_path, '-wipe-data', '-avd', 'Pixel_XL_API_28', '-writable-system', '-no-snapshot']
    response = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    error = response.communicate()
    if response.returncode != 0:
        logging.info("VM had errors while opening.\nError:{}".format(error))
    else:
        logging.info("VM started successfully")

wipe_vm()
