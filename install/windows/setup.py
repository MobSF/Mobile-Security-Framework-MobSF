import configparser
import urllib.request
import subprocess
from setuptools import find_packages
import os
import sys
import re
import zipfile

# Only static URL, let's hope this never changes..
CONFIG_URL = (
    "https://raw.githubusercontent.com/DominikSchlecht/"
    "Mobile-Security-Framework-MobSF/master/install/windows/config.txt"
)

# Static path to config file as a starting point
CONFIG_PATH = "C:\\MobSF\\Config\\"
CONFIG_FILE = "config.txt"

# Static path to autostart
AUTOSTART = (
    "C:\\Users\\{}\\AppData\\Roaming\Microsoft\\"
    "Windows\\Start Menu\\Programs\\Startup\\".format(os.getlogin())
)

# Global var so we don't have to pass it every time..
config = ""

def download_config():
    """Download initial config file."""

    # Create config path
    os.makedirs(CONFIG_PATH, exist_ok=True)

    # Open File
    f = open(CONFIG_PATH + CONFIG_FILE, "wb")

    # Downloading File
    print("[*] Downloading config file..")
    file = urllib.request.urlopen(CONFIG_URL)

    # Save content
    print("[*] Saving to File {}".format(CONFIG_FILE))

    # Write content to file
    f.write(bytes(file.read()))

    # Aaaand close
    f.close()


def read_config():
    """Read the config file and write it to the global var."""

    print("[*] Reading config file..")

    global config
    config = configparser.ConfigParser()
    config.read(CONFIG_PATH + CONFIG_FILE)


def create_folders():
    """Create MobSF dirs."""

    print("[*] Creating other folders...")

    os.makedirs(config['MobSF']['subdir_downloads'], exist_ok=True)
    os.makedirs(config['MobSF']['subdir_tools'], exist_ok=True)
    os.makedirs(config['MobSF']['subdir_samples'], exist_ok=True)


def check_dependencies():
    """Check dependencies and install if necessary."""

    print("[*] Checking dependencies...")
    missing_deps = []
    try:
        import flask
        print("[+] flask is installed.")
    except ImportError as e:
        print("[!] Flask not installed!")
        missing_deps.append("flask")
    if len(missing_deps) > 0:
        print("[!] Please install these missing dependencies:")
        print(missing_deps)
    else:
        print("[+] Everything good.")


def tools_nuget():
    NUGET_URL = config['nuget']['url']
    MOBSF_SUBDIR_TOOLS = config['MobSF']['subdir_tools']
    NUGET_FILE = config['nuget']['file']

    # Open File
    f = open(MOBSF_SUBDIR_TOOLS + NUGET_FILE, "wb")

    # Downloading File
    print("[*] Downloading nuget..")
    file = urllib.request.urlopen(NUGET_URL)

    # Save content
    print("[*] Saving to File {}".format(NUGET_FILE))

    # Write content to file
    f.write(bytes(file.read()))

    # Aaaand close
    f.close()


def tools_binskim():
    """Download and extract binskim."""
    # Get dirs, urls etc.
    BINSKIM_NUGET = config['binskim']['nuget']
    MOBSF_SUBDIR_TOOLS = config['MobSF']['subdir_tools']
    NUGET = MOBSF_SUBDIR_TOOLS + config['nuget']['file']

    print("[*] Downloading and installing Binskim...")

    # Execute nuget to get binkim
    output = subprocess.check_output(
        [
            NUGET,
            "install", BINSKIM_NUGET, '-Pre',
            '-o', MOBSF_SUBDIR_TOOLS
        ]
    )

    # Some code to determine the version on the fly so we don't have to fix the
    # config file on every new release of binskim..

    # Search for the version number
    folder = re.search(b"Microsoft\.CodeAnalysis\.BinSkim\..*' ", output)
    try:
        # Substring-Foo for removing b'X's
        folder = str(folder.group(0)[:-2])[2:-1]
    except AttributeError:
        print("[!] Unable to parse folder from binskim nuget installation.")
        sys.exit()

    # Search for the exes
    binaries = _find_exe(MOBSF_SUBDIR_TOOLS + folder, [])
    if len(binaries) != 2:
        print("[!] Found more than 2 exes for binskim, panic!")
        sys.exit()

    # Determinde which one is for which arch
    if "x86" in binaries[0]:
        config['binskim']['file_x86'] = binaries[0]
        config['binskim']['file_x64'] = binaries[1]
    else:
        config['binskim']['file_x86'] = binaries[1]
        config['binskim']['file_x64'] = binaries[0]

    # Write to config
    with open('C:\\MobSF\\Config\\config.txt', 'w') as configfile:
        config.write(configfile)


def _find_exe(path, list):
    """Return a list of all exes in path, recursive"""
    for filename in os.listdir(path):
        if os.path.isfile(os.path.join(path, filename)):
            if ".exe" in filename:
                list.append(path + "\\" + filename)
        else:
            list = _find_exe(path + "\\" + filename, list)
    return list


def tools_rpcclient():
    """Download and install rpc-server for MobSF"""
    RPC_URL = config['rpc']['url']
    MOBSF_SUBDIR_TOOLS = config['MobSF']['subdir_tools']
    RPC_FILE = config['rpc']['file']

    # Open File
    f = open(MOBSF_SUBDIR_TOOLS + RPC_FILE, "wb")

    # Downloading File
    print("[*] Downloading rpc_server..")
    file = urllib.request.urlopen(RPC_URL)

    # Save content
    print("[*] Saving to File {}".format(RPC_FILE))

    # Write content to file
    f.write(bytes(file.read()))

    # Aaaand close
    f.close()


def tools_binscope():
    """Download and install Binscope for MobSF"""
    URL = config['binscope']['url']
    os.makedirs(config['MobSF']['subdir_tools']+'BinScope', exist_ok=True)
    print("""
    [!] Sadly for Binscope there is no automated install yet.
        Please download the installer from
        {}
        and install it to
        C:\\MobSF\\Tools\\BinScope""".format(URL))
    input("Press enter when done...")


def autostart():
    MOBSF_SUBDIR_TOOLS = config['MobSF']['subdir_tools']
    RPC_FILE = config['rpc']['file']
    AUTOSTART_FILE = config['autostart']['file']
    batch_file = AUTOSTART + AUTOSTART_FILE

    print("[*] Creating autostart binary...")

    # Open file
    f = open(batch_file, "wb")

    # Define bat-text
    text = """
    @echo off
    python {} %*
    pause""".format(MOBSF_SUBDIR_TOOLS + RPC_FILE)
    f.write(bytes(text, 'utf8'))

    # Close handle
    f.close()

    print("[*] Done. Start the server.")

    # Execute. Beware the " " because of windows strange paths..
    os.system('"'+batch_file+'"')

if __name__ == "__main__":
    download_config()
    read_config()
    create_folders()
    check_dependencies()
    tools_nuget()
    tools_binskim()
    tools_binscope()
    tools_rpcclient()
    autostart()
