"""Common Utils."""
import ast
import hashlib
import io
import logging
import ntpath
import os
import platform
import random
import re
import shutil
import signal
import subprocess
import sys
import unicodedata
import threading

import requests

from django.shortcuts import render

from install.windows.setup import windows_config_local

from . import settings

logger = logging.getLogger(__name__)


class Color(object):
    GREEN = '\033[92m'
    ORANGE = '\033[33m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'


def upstream_proxy(flaw_type):
    """Set upstream Proxy if needed."""
    if settings.UPSTREAM_PROXY_ENABLED:
        if not settings.UPSTREAM_PROXY_USERNAME:
            proxy_port = str(settings.UPSTREAM_PROXY_PORT)
            proxy_host = '{}://{}:{}'.format(
                settings.UPSTREAM_PROXY_TYPE,
                settings.UPSTREAM_PROXY_IP,
                proxy_port)
            proxies = {flaw_type: proxy_host}
        else:
            proxy_port = str(settings.UPSTREAM_PROXY_PORT)
            proxy_host = '{}://{}:{}@{}:{}'.format(
                settings.UPSTREAM_PROXY_TYPE,
                settings.UPSTREAM_PROXY_USERNAME,
                settings.UPSTREAM_PROXY_PASSWORD,
                settings.UPSTREAM_PROXY_IP,
                proxy_port)
            proxies = {flaw_type: proxy_host}
    else:
        proxies = {flaw_type: None}
    verify = bool(settings.UPSTREAM_PROXY_SSL_VERIFY)
    return proxies, verify


def api_key():
    """Print REST API Key."""
    if os.environ.get('MOBSF_API_KEY'):
        logger.info('\nAPI Key read from environment variable')
        return os.environ['MOBSF_API_KEY']

    secret_file = os.path.join(settings.MobSF_HOME, 'secret')
    if is_file_exists(secret_file):
        try:
            _api_key = open(secret_file).read().strip()
            return gen_sha256_hash(_api_key)
        except Exception:
            logger.exception('Cannot Read API Key')


def print_version():
    """Print MobSF Version."""
    logger.info(settings.BANNER)
    ver = settings.MOBSF_VER
    if platform.system() == 'Windows':
        logger.info('Mobile Security Framework %s', ver)
        print('REST API Key: ' + api_key())
    else:
        logger.info('\033[1m\033[34mMobile Security Framework %s\033[0m', ver)
        print('REST API Key: ' + Color.BOLD + api_key() + Color.END)
    logger.info('OS: %s', platform.system())
    logger.info('Platform: %s', platform.platform())
    if platform.dist()[0]:
        logger.info('Dist: %s', str(platform.dist()))
    find_java_binary()
    find_vboxmange_binary(True)
    check_basic_env()
    adb_binary_or32bit_support()
    thread = threading.Thread(target=check_update, name='check_update')
    thread.start()


def check_update():
    try:
        logger.info('Checking for Update.')
        github_url = ('https://raw.githubusercontent.com/'
                      'MobSF/Mobile-Security-Framework-MobSF/'
                      'master/MobSF/settings.py')
        try:
            proxies, verify = upstream_proxy('https')
        except Exception:
            logger.exception('Setting upstream proxy')
        response = requests.get(github_url, timeout=5,
                                proxies=proxies, verify=verify)
        html = str(response.text).split('\n')
        for line in html:
            if line.startswith('MOBSF_VER'):
                line = line.replace('MOBSF_VER', '').replace("'", '')
                line = line.replace('=', '').strip()
                if line != settings.MOBSF_VER:
                    logger.warning('A new version of MobSF is available, '
                                   'Please update from master branch or check '
                                   'for new releases.')
                else:
                    logger.info('No updates available.')
    except requests.exceptions.HTTPError:
        logger.warning('\nCannot check for updates..'
                       ' No Internet Connection Found.')
        return
    except Exception:
        logger.exception('Cannot Check for updates.')


def create_user_conf(mobsf_home):
    try:
        config_path = os.path.join(mobsf_home, 'config.py')
        if not is_file_exists(config_path):
            sample_conf = os.path.join(settings.BASE_DIR, 'MobSF/settings.py')
            with open(sample_conf, 'r') as f:
                dat = f.readlines()
            config = []
            add = False
            for line in dat:
                if '^CONFIG-START^' in line:
                    add = True
                if '^CONFIG-END^' in line:
                    break
                if add:
                    config.append(line.lstrip())
            config.pop(0)
            conf_str = ''.join(config)
            with open(config_path, 'w') as f:
                f.write(conf_str)
    except Exception:
        logger.exception('Cannot create config file')


def get_mobsf_home(use_home):
    try:
        mobsf_home = ''
        if use_home:
            mobsf_home = os.path.join(os.path.expanduser('~'), '.MobSF')
            # MobSF Home Directory
            if not os.path.exists(mobsf_home):
                os.makedirs(mobsf_home)
            create_user_conf(mobsf_home)
        else:
            mobsf_home = settings.BASE_DIR
        # Logs Directory
        log_dir = os.path.join(mobsf_home, 'logs/')
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        # Certs Directory
        cert_dir = os.path.join(log_dir, 'certs/')
        if not os.path.exists(cert_dir):
            os.makedirs(cert_dir)
        # Download Directory
        dwd_dir = os.path.join(mobsf_home, 'downloads/')
        if not os.path.exists(dwd_dir):
            os.makedirs(dwd_dir)
        # Screenshot Directory
        screen_dir = os.path.join(dwd_dir, 'screen/')
        if not os.path.exists(screen_dir):
            os.makedirs(screen_dir)
        # Upload Directory
        upload_dir = os.path.join(mobsf_home, 'uploads/')
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)
        return mobsf_home
    except Exception:
        logger.exception('Creating MobSF Home Directory')


def make_migrations(base_dir):
    """Create Database Migrations."""
    try:
        manage = os.path.join(base_dir, 'manage.py')
        args = [get_python(), manage, 'makemigrations']
        subprocess.call(args)
        args = [get_python(), manage, 'makemigrations', 'StaticAnalyzer']
        subprocess.call(args)
    except Exception:
        logger.exception('Cannot Make Migrations')


def migrate(base_dir):
    """Migrate Database."""
    try:
        manage = os.path.join(base_dir, 'manage.py')
        args = [get_python(), manage, 'migrate']
        subprocess.call(args)
        args = [get_python(), manage, 'migrate', '--run-syncdb']
        subprocess.call(args)
    except Exception:
        logger.exception('Cannot Migrate')


def kali_fix(base_dir):
    try:
        if platform.system() == 'Linux' and platform.dist()[0] == 'Kali':
            fix_path = os.path.join(base_dir, 'scripts/kali_fix.sh')
            os.chmod(fix_path, 0o744)
            subprocess.call([fix_path], shell=True)
    except Exception:
        logger.exception('Cannot run Kali Fix')


def find_vboxmange_binary(debug=False):
    try:
        vpt = ['C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe',
               'C:\\Program Files (x86)\\Oracle\\VirtualBox\\VBoxManage.exe']
        if settings.ANDROID_DYNAMIC_ANALYZER == 'MobSF_VM':
            if (len(settings.VBOXMANAGE_BINARY) > 0
                    and is_file_exists(settings.VBOXMANAGE_BINARY)):
                return settings.VBOXMANAGE_BINARY
            if platform.system() == 'Windows':
                for path in vpt:
                    if os.path.isfile(path):
                        return path
            else:
                # Path to VBoxManage in Linux/Mac
                vpt = ['/usr/bin/VBoxManage',
                       '/usr/local/bin/VBoxManage']
                for path in vpt:
                    if os.path.isfile(path):
                        return path
            if debug:
                logger.warning('Could not find VirtualBox path')
    except Exception:
        if debug:
            logger.exception('Cannot find VirtualBox path.')


def find_java_binary():
    """Find Java."""
    # Respect user settings
    if platform.system() == 'Windows':
        jbin = 'java.exe'
    else:
        jbin = 'java'
    if is_dir_exists(settings.JAVA_DIRECTORY):
        if settings.JAVA_DIRECTORY.endswith('/'):
            return settings.JAVA_DIRECTORY + jbin
        elif settings.JAVA_DIRECTORY.endswith('\\'):
            return settings.JAVA_DIRECTORY + jbin
        else:
            return settings.JAVA_DIRECTORY + '/' + jbin
    if os.getenv('JAVA_HOME'):
        java = os.path.join(
            os.getenv('JAVA_HOME'),
            'bin',
            jbin)
        if is_file_exists(java):
            return java
    return 'java'


def get_python():
    """Get Python Executable."""
    return sys.executable


def run_process(args):
    try:
        proc = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        dat = ''
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            dat += str(line)
        return dat
    except Exception:
        logger.error('Finding Java path - Cannot Run Process')
        return ''


def print_n_send_error_response(request,
                                msg,
                                api=False,
                                exp='Error Description'):
    """Print and log errors."""
    logger.error(msg)
    if api:
        api_response = {'error': msg}
        return api_response
    else:
        context = {
            'title': 'Error',
            'exp': exp,
            'doc': msg,
        }
        template = 'general/error.html'
        return render(request, template, context, status=500)


def filename_from_path(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)


def get_md5(data):
    return hashlib.md5(data).hexdigest()


def find_between(s, first, last):
    try:
        start = s.index(first) + len(first)
        end = s.index(last, start)
        return s[start:end]
    except ValueError:
        return ''


def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        pass
    try:
        unicodedata.numeric(s)
        return True
    except (TypeError, ValueError):
        pass
    return False


def python_list(value):
    if not value:
        value = []
    if isinstance(value, list):
        return value
    return ast.literal_eval(value)


def python_dict(value):
    if not value:
        value = {}
    if isinstance(value, dict):
        return value
    return ast.literal_eval(value)


def is_base64(b_str):
    return re.match('^[A-Za-z0-9+/]+[=]{0,2}$', b_str)


def is_internet_available():
    try:
        proxies, verify = upstream_proxy('https')
    except Exception:
        logger.exception('Setting upstream proxy')
    try:
        requests.get('https://www.google.com', timeout=5,
                     proxies=proxies, verify=verify)
        return True
    except requests.exceptions.HTTPError:
        try:
            requests.get('https://www.baidu.com/', timeout=5,
                         proxies=proxies, verify=verify)
            return True
        except requests.exceptions.HTTPError:
            return False
    return False


def sha256(file_path):
    blocksize = 65536
    hasher = hashlib.sha256()
    with io.open(file_path, mode='rb') as afile:
        buf = afile.read(blocksize)
        while buf:
            hasher.update(buf)
            buf = afile.read(blocksize)
    return hasher.hexdigest()


def sha256_object(file_obj):
    blocksize = 65536
    hasher = hashlib.sha256()
    buf = file_obj.read(blocksize)
    while buf:
        hasher.update(buf)
        buf = file_obj.read(blocksize)
    return hasher.hexdigest()


def gen_sha256_hash(msg):
    """Generate SHA 256 Hash of the message."""
    hash_object = hashlib.sha256(msg.encode('utf-8'))
    return hash_object.hexdigest()


def is_file_exists(file_path):
    if os.path.isfile(file_path):
        return True
    # This fix situation where a user just typed "adb" or another executable
    # inside settings.py
    if shutil.which(file_path):
        return True
    else:
        return False


def is_dir_exists(dir_path):
    if os.path.isdir(dir_path):
        return True
    else:
        return False


def get_random():
    choice = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)'
    return ''.join([random.SystemRandom().choice(choice) for i in range(50)])


def zipdir(path, zip_file):
    """Zip a directory."""
    try:
        logger.info('Zipping')
        # pylint: disable=unused-variable
        # Needed by os.walk
        for root, _sub_dir, files in os.walk(path):
            for file_name in files:
                zip_file.write(os.path.join(root, file_name))
    except Exception:
        logger.exception('Zipping')


def get_adb():
    """Get ADB binary path."""
    try:
        if (len(settings.ADB_BINARY) > 0
                and is_file_exists(settings.ADB_BINARY)):
            return settings.ADB_BINARY
        else:
            adb = 'adb'
            if platform.system() == 'Darwin':
                adb_dir = os.path.join(settings.TOOLS_DIR, 'adb/mac/')
                os.chmod(adb_dir, 0o744)
                adb = os.path.join(settings.TOOLS_DIR, 'adb/mac/adb')
            elif platform.system() == 'Linux':
                adb_dir = os.path.join(settings.TOOLS_DIR, 'adb/linux/')
                os.chmod(adb_dir, 0o744)
                adb = os.path.join(settings.TOOLS_DIR, 'adb/linux/adb')
            elif platform.system() == 'Windows':
                adb = os.path.join(settings.TOOLS_DIR, 'adb/windows/adb.exe')
            return adb
    except Exception:
        logger.exception('Getting ADB Location')
        return 'adb'


def adb_binary_or32bit_support():
    """Check if 32bit is supported. Also if the binary works."""
    adb_path = get_adb()
    try:
        fnull = open(os.devnull, 'w')
        subprocess.call([adb_path], stdout=fnull, stderr=fnull)
    except Exception:
        msg = ('\nYou don\'t have 32 bit execution support enabled'
               ' or MobSF shipped ADB binary is not compatible with your OS.'
               '\nPlease set the ADB_BINARY path in MobSF/settings.py')
        logger.warning(msg)


def check_basic_env():
    """Check if we have basic env for MobSF to run."""
    logger.info('MobSF Basic Environment Check')
    try:
        import capfuzz  # noqa F401
    except ImportError:
        logger.exception('CapFuzz not installed!')
        os.kill(os.getpid(), signal.SIGTERM)
    try:
        import lxml  # noqa F401
    except ImportError:
        logger.exception('lxml is not installed!')
        os.kill(os.getpid(), signal.SIGTERM)
    if not is_file_exists(settings.JAVA_BINARY):
        logger.error(
            'JDK 8+ is not available. '
            'Set JAVA_HOME environment variable'
            ' or JAVA_DIRECTORY in MobSF/settings.py')
        logger.info('Current Configuration: '
                    'JAVA_DIRECTORY=%s', settings.JAVA_DIRECTORY)
        logger.info('Example Configuration:'
                    '\nJAVA_DIRECTORY = "C:/Program Files/'
                    'Java/jdk1.7.0_17/bin/"'
                    '\nJAVA_DIRECTORY = "/usr/bin/"')
        os.kill(os.getpid(), signal.SIGTERM)


def first_run(secret_file, base_dir, mobsf_home):
    # Based on https://gist.github.com/ndarville/3452907#file-secret-key-gen-py

    if is_file_exists(secret_file):
        secret_key = open(secret_file).read().strip()
    else:
        try:
            secret_key = get_random()
            secret = open(secret_file, 'w')
            secret.write(secret_key)
            secret.close()
        except IOError:
            Exception('Secret file generation failed' % secret_file)
        # Run Once
        make_migrations(base_dir)
        migrate(base_dir)
        kali_fix(base_dir)
        # Windows Setup
        windows_config_local(mobsf_home)
    return secret_key


def update_local_db(db_name, url, local_file):
    """Update Local DBs."""
    update = None
    try:
        proxies, verify = upstream_proxy('http')
    except Exception:
        logger.exception('[ERROR] Setting upstream proxy')
    try:
        response = requests.get(url,
                                timeout=3,
                                proxies=proxies,
                                verify=verify)
        resp = response.content
        inmemoryfile = io.BytesIO(resp)
        # Check1: SHA256 Change
        if sha256_object(inmemoryfile) != sha256(local_file):
            # Hash Changed
            logger.info('%s Database is outdated!', db_name)
            update = resp
        else:
            logger.info('%s Database is up-to-date', db_name)
        return update
    except Exception:
        logger.exception('[ERROR] %s DB Update', db_name)
        return update
    finally:
        if inmemoryfile:
            inmemoryfile.truncate(0)
