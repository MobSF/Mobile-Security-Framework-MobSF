"""Setup script for the Windows vm for usage with MobSF for static analysis of Windows apps."""
# Most pylinter warnings are disabled because implementation happendend on a Python2 machine
# while the code is Python3
import os
import sys
import re

import configparser # pylint: disable-msg=E0401
import urllib.request # pylint: disable-msg=E0401,E0611
import subprocess

# pylint: disable=C0325,W0603

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
    "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\"
    "Windows\\Start Menu\\Programs\\Startup\\".format(os.getlogin())
)

# Global var so we don't have to pass it every time..
CONFIG = ""

def download_config():
    """Download initial config file."""

    # Create config path
    os.makedirs(CONFIG_PATH, exist_ok=True) # pylint: disable-msg=E1123

    # Open File
    conf_file_local = open(CONFIG_PATH + CONFIG_FILE, "wb")

    # Downloading File
    print("[*] Downloading config file..")
    conf_file = urllib.request.urlopen(CONFIG_URL) # pylint: disable-msg=E1101

    # Save content
    print("[*] Saving to File {}".format(CONFIG_FILE))

    # Write content to file
    conf_file_local.write(bytes(conf_file.read()))

    # Aaaand close
    conf_file_local.close()


def read_config():
    """Read the config file and write it to the global var."""

    print("[*] Reading config file..")

    global CONFIG
    CONFIG = configparser.ConfigParser()
    CONFIG.read(CONFIG_PATH + CONFIG_FILE)


def create_folders():
    """Create MobSF dirs."""

    print("[*] Creating other folders...")

    os.makedirs(CONFIG['MobSF']['subdir_downloads'], exist_ok=True) # pylint: disable-msg=E1123
    os.makedirs(CONFIG['MobSF']['subdir_tools'], exist_ok=True) # pylint: disable-msg=E1123
    os.makedirs(CONFIG['MobSF']['subdir_samples'], exist_ok=True) # pylint: disable-msg=E1123


def check_dependencies():
    """Check dependencies and install if necessary."""

    print("[*] Checking dependencies...")
    missing_deps = []

    try:
        import rsa
        print("[+] rsa is installed.")
    except ImportError: # pylint: disable-msg=C0103
        print("[!] rsa not installed!")
        missing_deps.append("rsa")


    if len(missing_deps) > 0:
        print("[!] Please install these missing dependencies:")
        print(missing_deps)
        sys.exit()
    else:
        print("[+] Everything good.")


def tools_nuget():
    """Download nuget."""
    # Get config params
    nuget_url = CONFIG['nuget']['url']
    mobsf_subdir_tools = CONFIG['MobSF']['subdir_tools']
    nuget_file_path = CONFIG['nuget']['file']

    # Open File
    nuget_file_local = open(mobsf_subdir_tools + nuget_file_path, "wb")

    # Downloading File
    print("[*] Downloading nuget..")
    nuget_file = urllib.request.urlopen(nuget_url) # pylint: disable-msg=E1101

    # Save content
    print("[*] Saving to File {}".format(nuget_file_path))

    # Write content to file
    nuget_file_local.write(bytes(nuget_file.read()))

    # Aaaand close
    nuget_file_local.close()


def tools_binskim():
    """Download and extract binskim."""
    # Get dirs, urls etc.
    binskim_nuget = CONFIG['binskim']['nuget']
    mobsf_subdir_tools = CONFIG['MobSF']['subdir_tools']
    nuget = mobsf_subdir_tools + CONFIG['nuget']['file']

    print("[*] Downloading and installing Binskim...")

    # Execute nuget to get binkim
    output = subprocess.check_output(
        [
            nuget,
            "install", binskim_nuget, '-Pre',
            '-o', mobsf_subdir_tools
        ]
    )

    # Some code to determine the version on the fly so we don't have to fix the
    # config file on every new release of binskim..

    # Search for the version number
    folder = re.search(
        b"Microsoft\.CodeAnalysis\.BinSkim\..*' ", output # pylint: disable-msg=W1401
    )
    try:
        # Substring-Foo for removing b'X's
        folder = str(folder.group(0)[:-2])[2:-1]
    except AttributeError:
        print("[!] Unable to parse folder from binskim nuget installation.")
        sys.exit()

    # Search for the exes
    binaries = _find_exe(mobsf_subdir_tools + folder, [])
    if len(binaries) != 2:
        print("[!] Found more than 2 exes for binskim, panic!")
        sys.exit()

    # Determinde which one is for which arch
    if "x86" in binaries[0]:
        CONFIG['binskim']['file_x86'] = binaries[0]
        CONFIG['binskim']['file_x64'] = binaries[1]
    else:
        CONFIG['binskim']['file_x86'] = binaries[1]
        CONFIG['binskim']['file_x64'] = binaries[0]

    # Write to config
    with open('C:\\MobSF\\Config\\config.txt', 'w') as configfile:
        CONFIG.write(configfile) # pylint: disable-msg=E1101


def _find_exe(path, exe_list):
    """Return a list of all exes in path, recursive"""
    for filename in os.listdir(path):
        if os.path.isfile(os.path.join(path, filename)):
            if ".exe" in filename:
                exe_list.append(path + "\\" + filename)
        else:
            exe_list = _find_exe(path + "\\" + filename, exe_list)
    return exe_list


def tools_rpcclient():
    """Download and install rpc-server for MobSF."""
    rpc_url = CONFIG['rpc']['url']
    mobsf_subdir_tools = CONFIG['MobSF']['subdir_tools']
    rpc_file_path = CONFIG['rpc']['file']

    # Open File
    rpc_local_file = open(mobsf_subdir_tools + rpc_file_path, "wb")

    # Downloading File
    print("[*] Downloading rpc_server..")
    rpc_file = urllib.request.urlopen(rpc_url) # pylint: disable-msg=E1101

    # Save content
    print("[*] Saving to File {}".format(rpc_file_path))

    # Write content to file
    rpc_local_file.write(bytes(rpc_file.read()))

    # Aaaand close
    rpc_local_file.close()


def tools_binscope():
    """Download and install Binscope for MobSF"""
    url = CONFIG['binscope']['url']
    os.makedirs( # pylint: disable-msg=E1123
        CONFIG['MobSF']['subdir_tools']+'BinScope', exist_ok=True
    )
    print("""
[!] Sadly for Binscope there is no automated install yet.
    Please download the installer from
    {}
    and install it to
    C:\\MobSF\\Tools\\BinScope""".format(url))
    input("Press enter when done...") # pylint: disable-msg=W0141


def generate_secret():
    """Generate rsa keys for authentication."""
    import rsa
    print("[*] Generating secret, please hang on.")
    # Generate keys, taken from https://stuvel.eu/python-rsa-doc/usage.html#generating-keys
    (pubkey, privkey) = rsa.newkeys(2048)

    # Save private and pub key
    priv_key_file = open(CONFIG['MobSF']['priv_key_file'], 'w')
    priv_key_file.write(privkey.save_pkcs1().decode('utf-8'))
    priv_key_file.close()
    pub_key_file = open(CONFIG['MobSF']['pub_key_file'], 'w')
    pub_key_file.write(pubkey.save_pkcs1().decode('utf-8'))
    pub_key_file.close()

    print(
        "[!] Please move the private key file\n"
        "\t{}\n"
        "\tto MobSF to the path specified in settings.py\n"
        "\t(default: Mobile-Security-Framework-MobSF/MobSF/windows_vm_priv_key.asc)"
        .format(CONFIG['MobSF']['priv_key_file'])
    )
    input("Please press any key when done..") # pylint: disable-msg=W0141


def autostart():
    """Create the autostart binary and run it."""
    mobsf_subdir_tools = CONFIG['MobSF']['subdir_tools']
    rpc_file = CONFIG['rpc']['file']
    autostart_file = CONFIG['autostart']['file']
    batch_file = AUTOSTART + autostart_file

    print("[*] Creating autostart binary...")

    # Open file
    autostart_file = open(batch_file, "wb")

    # Define bat-text
    text = """
    @echo off
    python {} %*
    pause""".format(mobsf_subdir_tools + rpc_file)
    autostart_file.write(bytes(text, 'utf8'))

    # Close handle
    autostart_file.close()

    print("[*] Done. Start the server.")

    # Execute. Beware the " " because of windows strange paths..
    os.system('"'+batch_file+'"')

def _place_lockfile():
    path = "C:\\MobSF\\setup_done.txt"
    open(path, 'a').close()

def install_locally():
    """Install the MobSF-Utils on the same system as MobSF."""
    download_config()
    read_config()
    create_folders()
    tools_nuget()
    tools_binskim()
    tools_binscope()
    _place_lockfile()

def _install_remote():
    """Install the MobSF-Utils on a Windows-VM for static analysis."""
    download_config()
    read_config()
    create_folders()
    check_dependencies()
    tools_nuget()
    tools_binskim()
    tools_binscope()
    tools_rpcclient()
    generate_secret()
    autostart()

if __name__ == "__main__":
    _install_remote()
