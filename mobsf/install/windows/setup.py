"""Static Analysis Setup Windows.

Setup script for the Windows vm for usage with MobSF for
static analysis of Windows apps.
"""
import configparser
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
from os.path import expanduser

from six.moves import input

try:
    import urllib.request as urlrequest
except ImportError:
    import urllib as urlrequest


logger = logging.getLogger(__name__)

# pylint: disable=C0325,W0603

# Only static URL, let's hope this never changes..
CONFIG_URL = (
    'https://raw.githubusercontent.com/MobSF/'
    'Mobile-Security-Framework-MobSF/master/'
    'mobsf/install/windows/config.txt'
)

# Static path to config file as a starting point
CONFIG_PATH = expanduser('~') + '\\MobSF\\Config\\'
CONFIG_FILE = 'config.txt'

# Static path to autostart
AUTOSTART = (
    expanduser('~') + '\\AppData\\Roaming\\Microsoft\\'
    'Windows\\Start Menu\\Programs\\Startup\\'
)

# Global var so we don't have to pass it every time..
CONFIG = ''


def windows_config_local(path):
    """Windows Configuration."""
    # Configure here if you are on windows
    # Path to lock-file (so setup is only run once)
    path_to_lock_file = os.path.join(path, 'setup_done.txt')
    if (os.path.isfile(path_to_lock_file) is False
            and platform.system() == 'Windows'
            and 'CI' not in os.environ):
        logger.info('Running first time setup for windows.')
        # Setup is to-be-executed
        install_locally(path)


def download_config():
    """Download initial config file."""
    # Create config path
    if not os.path.exists(CONFIG_PATH):
        os.makedirs(CONFIG_PATH)

    if os.path.exists(CONFIG_PATH + CONFIG_FILE):
        os.remove(CONFIG_PATH + CONFIG_FILE)

    # TODO(Give user time to modify config, but mayber after rewrite?)

    # Open File
    conf_file_local = open(CONFIG_PATH + CONFIG_FILE, 'wb')

    # Downloading File
    print('[*] Downloading config file..')
    conf_file = urlrequest.urlopen(CONFIG_URL)  # pylint: disable-msg=E1101

    # Save content
    print(('[*] Saving to File {}'.format(CONFIG_FILE)))

    # Write content to file
    conf_file_local.write(bytes(conf_file.read()))

    # Aaaand close
    conf_file_local.close()


def read_config():
    """Read the config file and write it to the global var."""
    print('[*] Reading config file..')

    global CONFIG
    CONFIG = configparser.ConfigParser()
    CONFIG.read(CONFIG_PATH + CONFIG_FILE)


def create_folders():
    """Create MobSF dirs."""
    print('[*] Creating other folders...')

    if not os.path.exists(CONFIG['MobSF']['downloads']):
        os.makedirs(CONFIG['MobSF']['downloads'])

    if not os.path.exists(CONFIG['MobSF']['tools']):
        os.makedirs(CONFIG['MobSF']['tools'])

    if not os.path.exists(CONFIG['MobSF']['samples']):
        os.makedirs(CONFIG['MobSF']['samples'])

    if not os.path.exists(CONFIG['MobSF']['key_path']):
        os.makedirs(CONFIG['MobSF']['key_path'])


def check_dependencies():
    """Check dependencies and install if necessary."""
    print('[*] Checking dependencies...')
    missing_deps = []

    try:
        import rsa  # noqa F401
        print('[+] rsa is installed.')
    except ImportError:  # pylint: disable-msg=C0103
        print('[!] rsa not installed!')
        missing_deps.append('rsa')

    if len(missing_deps) > 0:
        print('[!] Please install these missing dependencies:')
        print(missing_deps)
        sys.exit()
    else:
        print('[+] Everything good.')


def tools_nuget():
    """Download nuget."""
    # Get config params
    nuget_url = CONFIG['nuget']['url']
    mobsf_subdir_tools = CONFIG['MobSF']['tools']
    nuget_file_path = CONFIG['nuget']['file']

    # Open File
    nuget_file_local = open(os.path.join(
        mobsf_subdir_tools, nuget_file_path), 'wb')

    # Downloading File
    print('[*] Downloading nuget..')
    nuget_file = urlrequest.urlopen(nuget_url)  # pylint: disable-msg=E1101

    # Save content
    print(('[*] Saving to File {}'.format(nuget_file_path)))

    # Write content to file
    nuget_file_local.write(bytes(nuget_file.read()))

    # Aaaand close
    nuget_file_local.close()


def tools_binskim():
    """Download and extract binskim."""
    # Get dirs, urls etc.
    binskim_nuget = CONFIG['binskim']['nuget']
    mobsf_subdir_tools = CONFIG['MobSF']['tools']
    nuget = mobsf_subdir_tools + CONFIG['nuget']['file']

    print('[*] Downloading and installing Binskim...')
    # Execute nuget to get binkim
    output = subprocess.check_output(
        [
            nuget,
            'install', binskim_nuget, '-Pre',
            '-Version', '1.7.2',
            '-o', mobsf_subdir_tools])

    # Some code to determine the version on the fly so we don't have to fix the
    # config file on every new release of binskim..

    # Search for the version number
    folder = re.search(
        b'Microsoft\\.CodeAnalysis\\.BinSkim\\..{0,300}(\'|\") ', output)
    try:
        # Substring-Foo for removing b'X's in python3
        if sys.version_info.major == 3:
            folder = str(folder.group(0)[:-2])[2:-1]
        else:
            folder = folder.group(0)[:-2]
    except AttributeError:
        print('[!] Unable to parse folder from binskim nuget installation.')
        sys.exit()

    # Search for the exes
    binaries = _find_exe(mobsf_subdir_tools + folder, [])
    if len(binaries) != 2:
        print('[!] Found more than 2 exes for binskim, panic!')
        sys.exit()

    # Determinde which one is for which arch
    if 'x86' in binaries[0]:
        CONFIG['binskim']['file_x86'] = binaries[0]
        CONFIG['binskim']['file_x64'] = binaries[1]
    else:
        CONFIG['binskim']['file_x86'] = binaries[1]
        CONFIG['binskim']['file_x64'] = binaries[0]

    # Write to config
    with open(os.path.join(CONFIG_PATH, CONFIG_FILE), 'w') as configfile:
        CONFIG.write(configfile)  # pylint: disable-msg=E1101


def _find_exe(path, exe_list):
    """Return a list of all exes in path, recursive."""
    for filename in os.listdir(path):
        if os.path.isfile(os.path.join(path, filename)):
            if '.exe' in filename:
                exe_list.append(path + '\\' + filename)
        else:
            exe_list = _find_exe(path + '\\' + filename, exe_list)
    return exe_list


def tools_rpcclient():
    """Download and install rpc-server for MobSF."""
    rpc_url = CONFIG['rpc']['url']
    mobsf_subdir_tools = CONFIG['MobSF']['tools']
    rpc_file_path = CONFIG['rpc']['file']

    # Open File
    rpc_local_file = open(mobsf_subdir_tools + rpc_file_path, 'wb')

    # Downloading File
    print('[*] Downloading rpc_server..')
    rpc_file = urlrequest.urlopen(rpc_url)

    # Save content
    print(('[*] Saving to File {}'.format(rpc_file_path)))

    # Write content to file
    rpc_local_file.write(bytes(rpc_file.read()))

    # Aaaand close
    rpc_local_file.close()


def tools_binscope():
    """Download and install Binscope for MobSF."""
    mobsf_subdir_tools = CONFIG['MobSF']['tools']
    binscope_path = mobsf_subdir_tools + 'BinScope'

    # Download the right version for os
    if platform.machine().endswith('64'):
        binscope_url = CONFIG['binscope']['url_x64']
        binscope_installer_path = binscope_path + '\\BinScope_x64.msi'
    else:
        binscope_url = CONFIG['binscope']['url_x86']
        binscope_installer_path = binscope_path + '\\BinScope_x86.msi'

    if not os.path.exists(binscope_path):
        os.makedirs(binscope_path)

    binscope_installer_file = open(binscope_installer_path, 'wb')

    # Downloading File
    print('[*] Downloading BinScope..')
    binscope_installer = urlrequest.urlopen(binscope_url)

    # Save content
    print(('[*] Saving to File {}'.format(binscope_installer_path)))

    # Write content to file
    binscope_installer_file.write(bytes(binscope_installer.read()))

    # Aaaand close
    binscope_installer_file.close()
    # Execute the installer
    print(('[*] Installing BinScope to {}'.format(binscope_path)))
    cmd = ('msiexec INSTALLLOCATION='
           '"{}" /i "{}" /passive'.format(
               binscope_path,
               binscope_installer_path))
    os.system(cmd)

    CONFIG['binscope']['file'] = binscope_path + '\\Binscope.exe'

    # Write to config
    with open(os.path.join(CONFIG_PATH, CONFIG_FILE), 'w') as configfile:
        CONFIG.write(configfile)  # pylint: disable-msg=E1101


def generate_secret():
    """Generate rsa keys for authentication."""
    import rsa
    print('[*] Generating secret, please hang on.')
    # Generate keys, taken from
    # https://stuvel.eu/python-rsa-doc/usage.html#generating-keys
    (pubkey, privkey) = rsa.newkeys(2048)

    # Save private and pub key
    priv_key_file = open(CONFIG['MobSF']['priv_key'], 'w')
    priv_key_file.write(privkey.save_pkcs1().decode('utf-8'))
    priv_key_file.close()
    pub_key_file = open(CONFIG['MobSF']['pub_key'], 'w')
    pub_key_file.write(pubkey.save_pkcs1().decode('utf-8'))
    pub_key_file.close()
    config_path = os.path.join(
        expanduser('~'),
        '.MobSF',
        'config.py')
    print((
        '[!] Please move the private key file\n'
        '\t{}\n'
        '\tto MobSF to the path specified in {}\n'
        '\t(default: Mobile-Security-Framework-MobSF/'
        'mobsf/MobSF/windows_vm_priv_key.asc)'
        .format(CONFIG['MobSF']['priv_key'], config_path)
    ))
    input('Please press any key when done..')


def autostart():
    """Create the autostart binary and run it."""
    mobsf_subdir_tools = CONFIG['MobSF']['tools']
    rpc_file = CONFIG['rpc']['file']
    autostart_file = CONFIG['autostart']['file']
    batch_file = AUTOSTART + autostart_file

    print('[*] Creating autostart binary...')

    # Open file
    autostart_file = open(batch_file, 'wb')

    # Define bat-text
    text = """
    @echo off
    python "{}" %*
    pause""".format(mobsf_subdir_tools + rpc_file)
    autostart_file.write(bytes(text, 'utf8'))

    # Close handle
    autostart_file.close()

    print('[*] Done. Start the server.')

    # Execute. Beware the ' ' because of windows strange paths..
    os.system('"{}"'.format(batch_file))


def _place_lockfile(mobsf_home):
    path = os.path.join(mobsf_home, 'setup_done.txt')
    open(path, 'a').close()


def local_config():
    """Move local config and save paths."""
    # Set the CONFIG_PATH
    # Create path if it doesn't exist yet
    if not os.path.exists(CONFIG_PATH):
        os.makedirs(CONFIG_PATH)

    # Copy predefined config to MobSF folder
    shutil.copy(
        os.getcwd() + '\\mobsf\\install\\windows\\config.txt',
        os.path.join(CONFIG_PATH, CONFIG_FILE),
    )


def rewrite_local_config(mobsf_home):
    """For local installation some config-vars need to be rewritten."""
    CONFIG['MobSF']['subdir_tools'] = (
        mobsf_home
        + '\\mobsf\\StaticAnalyzer\\tools\\windows\\')
    CONFIG['MobSF']['dir'] = mobsf_home

    # Write to config
    with open(os.path.join(CONFIG_PATH, CONFIG_FILE), 'w') as configfile:
        CONFIG.write(configfile)  # pylint: disable-msg=E1101


def rewrite_config():
    """Rewrite the config to take the profile path as the base path."""
    # Take user path as base path
    CONFIG['MobSF']['dir'] = expanduser('~') + CONFIG['MobSF']['dir']

    # Rewrite config with new base path
    CONFIG['MobSF']['downloads'] = CONFIG['MobSF'][
        'dir'] + CONFIG['MobSF']['downloads']
    CONFIG['MobSF']['tools'] = CONFIG['MobSF'][
        'dir'] + CONFIG['MobSF']['tools']
    CONFIG['MobSF']['samples'] = CONFIG['MobSF'][
        'dir'] + CONFIG['MobSF']['samples']
    CONFIG['MobSF']['key_path'] = CONFIG['MobSF'][
        'dir'] + CONFIG['MobSF']['key_path']
    CONFIG['MobSF']['priv_key'] = CONFIG['MobSF'][
        'key_path'] + CONFIG['MobSF']['priv_key']
    CONFIG['MobSF']['pub_key'] = CONFIG['MobSF'][
        'key_path'] + CONFIG['MobSF']['pub_key']

    # Write to config
    with open(os.path.join(CONFIG_PATH, CONFIG_FILE), 'w') as configfile:
        CONFIG.write(configfile)  # pylint: disable-msg=E1101


def install_locally(mobsf_home):
    """Install the MobSF-Utils on the same system as MobSF."""
    local_config()
    read_config()
    rewrite_config()
    create_folders()
    tools_nuget()
    tools_binskim()
    tools_binscope()
    _place_lockfile(mobsf_home)


def _install_remote():
    """Install the MobSF-Utils on a Windows-VM for static analysis."""
    download_config()
    read_config()
    rewrite_config()
    create_folders()
    check_dependencies()
    tools_nuget()
    tools_binskim()
    tools_binscope()
    tools_rpcclient()
    generate_secret()
    autostart()


if __name__ == '__main__':
    # Gets directly run if setup.py is run on a remote machine
    _install_remote()
