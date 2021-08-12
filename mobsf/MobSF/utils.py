"""Common Utils."""
import ast
import hashlib
import io
import logging
import ntpath
import os
import platform
import re
import shutil
import signal
import string
import subprocess
import stat
import sqlite3
import unicodedata
import threading
from distutils.version import StrictVersion

import distro

import psutil

import requests

from django.shortcuts import render

from . import settings

logger = logging.getLogger(__name__)
ADB_PATH = None


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
    dist = distro.linux_distribution(full_distribution_name=False)
    if dist:
        logger.info('Dist: %s', ' '.join(dist))
    find_java_binary()
    check_basic_env()
    thread = threading.Thread(target=check_update, name='check_update')
    thread.start()


def check_update():
    try:
        if not is_internet_available():
            logger.warning('Internet Not Available. Skipping Update check')
            return
        logger.info('Checking for Update.')
        github_url = settings.GITHUB_URL
        try:
            proxies, verify = upstream_proxy('https')
        except Exception:
            logger.exception('Setting upstream proxy')
        response = requests.get(github_url, timeout=5,
                                proxies=proxies, verify=verify)
        html = str(response.text).split('\n')
        local_version = settings.VERSION
        remote_version = None
        for line in html:
            if line.startswith('VERSION'):
                remote_version = line.split('\'')[1]
                break
        if remote_version:
            sem_loc = StrictVersion(local_version)
            sem_rem = StrictVersion(remote_version)
            if sem_loc < sem_rem:
                logger.warning('A new version of MobSF is available, '
                               'Please update to %s from master branch.',
                               remote_version)
            else:
                logger.info('No updates available.')
    except requests.exceptions.HTTPError:
        logger.warning('\nCannot check for updates..'
                       ' No Internet Connection Found.')
        return
    except Exception:
        logger.exception('Cannot Check for updates.')


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
                                exp='Description'):
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
            'version': settings.MOBSF_VER,
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
        requests.get(settings.GOOGLE,
                     timeout=5,
                     proxies=proxies,
                     verify=verify)
        return True
    except Exception:
        try:
            requests.get(settings.BAIDU,
                         timeout=5,
                         proxies=proxies,
                         verify=verify)
            return True
        except Exception:
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
    # inside settings.py/config.py
    if shutil.which(file_path):
        return True
    else:
        return False


def is_dir_exists(dir_path):
    if os.path.isdir(dir_path):
        return True
    else:
        return False


def find_process_by(name):
    """Return a set of process path matching name."""
    proc = set()
    for p in psutil.process_iter(attrs=['name']):
        if (name == p.info['name']):
            proc.add(p.exe())
    return proc


def get_device():
    """Get Device."""
    if os.getenv('ANALYZER_IDENTIFIER'):
        return os.getenv('ANALYZER_IDENTIFIER')
    if settings.ANALYZER_IDENTIFIER:
        return settings.ANALYZER_IDENTIFIER
    else:
        dev_id = ''
        out = subprocess.check_output([get_adb(), 'devices']).splitlines()
        if len(out) > 2:
            dev_id = out[1].decode('utf-8').split('\t')[0]
            return dev_id
    logger.error('Is the Android VM running?\n'
                 'MobSF cannot identify device id.\n'
                 'Please set ''ANALYZER_IDENTIFIER in '
                 '%s', get_config_loc())


def get_adb():
    """Get ADB binary path."""
    try:
        adb_loc = None
        adb_msg = ('Set adb path, ADB_BINARY in'
                   f' {get_config_loc()}'
                   ' with same adb binary used'
                   ' by Genymotion VM/Emulator AVD.')
        global ADB_PATH
        if (len(settings.ADB_BINARY) > 0
                and is_file_exists(settings.ADB_BINARY)):
            ADB_PATH = settings.ADB_BINARY
            return ADB_PATH
        if ADB_PATH:
            return ADB_PATH
        if platform.system() == 'Windows':
            adb_loc = find_process_by('adb.exe')
        else:
            adb_loc = find_process_by('adb')
        if len(adb_loc) > 1:
            logger.warning('Multiple ADB locations found. %s', adb_msg)
            logger.warning(adb_loc)
        if adb_loc:
            ADB_PATH = adb_loc.pop()
            return ADB_PATH
    except Exception:
        if not adb_loc:
            logger.warning('Cannot find adb! %s', adb_msg)
        logger.exception('Getting ADB Location')
    finally:
        if ADB_PATH:
            os.environ['MOBSF_ADB'] = ADB_PATH
        else:
            os.environ['MOBSF_ADB'] = 'adb'
            logger.warning('Dynamic Analysis related '
                           'functions will not work. '
                           '\nMake sure a Genymotion Android VM/'
                           'Android Studio Emulator'
                           ' is running before performing'
                           ' Dynamic Analysis.')
    return 'adb'


def check_basic_env():
    """Check if we have basic env for MobSF to run."""
    logger.info('MobSF Basic Environment Check')
    try:
        import http_tools  # noqa F401
    except ImportError:
        logger.exception('httptools not installed!')
        os.kill(os.getpid(), signal.SIGTERM)
    try:
        import lxml  # noqa F401
    except ImportError:
        logger.exception('lxml is not installed!')
        os.kill(os.getpid(), signal.SIGTERM)
    if not is_file_exists(find_java_binary()):
        logger.error(
            'JDK 8+ is not available. '
            'Set JAVA_HOME environment variable'
            ' or JAVA_DIRECTORY in '
            '%s', get_config_loc())
        logger.info('Current Configuration: '
                    'JAVA_DIRECTORY=%s', settings.JAVA_DIRECTORY)
        logger.info('Example Configuration:'
                    '\nJAVA_DIRECTORY = "C:/Program Files/'
                    'Java/jdk1.7.0_17/bin/"'
                    '\nJAVA_DIRECTORY = "/usr/bin/"')
        os.kill(os.getpid(), signal.SIGTERM)
    get_adb()


def update_local_db(db_name, url, local_file):
    """Update Local DBs."""
    update = None
    inmemoryfile = None
    try:
        proxies, verify = upstream_proxy('https')
    except Exception:
        logger.exception('[ERROR] Setting upstream proxy')
    try:
        response = requests.get(url,
                                timeout=3,
                                proxies=proxies,
                                verify=verify)
        resp = response.content
        inmemoryfile = io.BytesIO(resp)
        # Create on first run
        if not is_file_exists(local_file):
            return resp
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


def read_sqlite(sqlite_file):
    """Sqlite Dump - Readable Text."""
    logger.info('Reading SQLite db')
    table_dict = {}
    try:
        con = sqlite3.connect(sqlite_file)
        cur = con.cursor()
        cur.execute('SELECT name FROM sqlite_master WHERE type=\'table\';')
        tables = cur.fetchall()
        for table in tables:
            table_dict[table[0]] = {'head': [], 'data': []}
            cur.execute('PRAGMA table_info(\'%s\')' % table)
            rows = cur.fetchall()
            for sq_row in rows:
                table_dict[table[0]]['head'].append(sq_row[1])
            cur.execute('SELECT * FROM \'%s\'' % table)
            rows = cur.fetchall()
            for sq_row in rows:
                tmp_row = []
                for each_row in sq_row:
                    tmp_row.append(str(each_row))
                table_dict[table[0]]['data'].append(tmp_row)
    except Exception:
        logger.exception('Reading SQLite db')
    return table_dict


def is_pipe_or_link(path):
    """Check for named pipe."""
    return os.path.islink(path) or stat.S_ISFIFO(os.stat(path).st_mode)


def get_network():
    """Get Network IPs."""
    ips = []
    try:
        for det in psutil.net_if_addrs().values():
            ips.append(det[0].address)
    except Exception:
        logger.exception('Failed to enumerate network interfaces')
    return ips


def get_proxy_ip(identifier):
    """Get Proxy IP."""
    proxy_ip = None
    try:
        if not identifier:
            return proxy_ip
        ips = get_network()
        if ':' not in identifier or not ips:
            return proxy_ip
        device_ip = identifier.split(':', 1)[0]
        ip_range = device_ip.rsplit('.', 1)[0]
        guess_ip = ip_range + '.1'
        if guess_ip in ips:
            return guess_ip
        for ip_addr in ips:
            to_check = ip_addr.rsplit('.', 1)[0]
            if to_check == ip_range:
                return ip_addr
    except Exception:
        logger.error('Error getting Proxy IP')
    return proxy_ip


def is_safe_path(safe_root, check_path):
    """Detect Path Traversal."""
    safe_root = os.path.realpath(os.path.normpath(safe_root))
    check_path = os.path.realpath(os.path.normpath(check_path))
    return os.path.commonprefix([check_path, safe_root]) == safe_root


def file_size(app_path):
    """Return the size of the file."""
    return round(float(os.path.getsize(app_path)) / (1024 * 1024), 2)


def is_md5(user_input):
    """Check if string is valid MD5."""
    stat = re.match(r'^[0-9a-f]{32}$', user_input)
    if not stat:
        logger.error('Invalid scan hash')
    return stat


def get_config_loc():
    """Get config location."""
    if settings.USE_HOME:
        return os.path.join(
            os.path.expanduser('~'),
            '.MobSF',
            'config.py',
        )
    else:
        return 'MobSF/settings.py'


def clean_filename(filename, replace=' '):
    if platform.system() == 'Windows':
        whitelist = f'-_.() {string.ascii_letters}{string.digits}'
        # replace spaces
        for r in replace:
            filename = filename.replace(r, '_')
        # keep only valid ascii chars
        cleaned_filename = unicodedata.normalize(
            'NFKD', filename).encode('ASCII', 'ignore').decode()
        # keep only whitelisted chars
        return ''.join(c for c in cleaned_filename if c in whitelist)
    return filename


def cmd_injection_check(data):
    """OS Cmd Injection from Commix."""
    breakers = [
        ';', '%3B', '&', '%26', '&&',
        '%26%26', '|', '%7C', '||',
        '%7C%7C', '%0a', '%0d%0a',
    ]
    return any(i in data for i in breakers)


def strict_package_check(user_input):
    """Strict package name check."""
    pat = re.compile(r'^\w+\.*[\w\.\$]+$')
    resp = re.match(pat, user_input)
    if not resp:
        logger.error('Invalid package/class name')
    return resp


def is_path_traversal(user_input):
    """Check for path traversal."""
    if (('../' in user_input)
        or ('%2e%2e' in user_input)
        or ('..' in user_input)
            or ('%252e' in user_input)):
        logger.error('Path traversal attack detected')
        return True
    return False


def is_zip_magic(file_obj):
    magic = file_obj.read(4)
    file_obj.seek(0, 0)
    # ZIP magic PK.. no support for spanned and empty arch
    return bool(magic == b'\x50\x4B\x03\x04')
