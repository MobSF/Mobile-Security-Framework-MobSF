"""Initialize on first run."""
import logging
import os
import random
import subprocess
import sys
import shutil
import threading
from pathlib import Path
from importlib import (
    machinery,
    util,
)

from mobsf.MobSF.tools_download import install_jadx
from mobsf.install.windows.setup import windows_config_local

logger = logging.getLogger(__name__)

VERSION = '4.1.5'
BANNER = r"""
  __  __       _    ____  _____       _  _    _ 
 |  \/  | ___ | |__/ ___||  ___|_   _| || |  / |
 | |\/| |/ _ \| '_ \___ \| |_  \ \ / / || |_ | |
 | |  | | (_) | |_) |__) |  _|  \ V /|__   _|| |
 |_|  |_|\___/|_.__/____/|_|     \_/    |_|(_)_|
"""  # noqa: W291
# ASCII Font: Standard


def first_run(secret_file, base_dir, mobsf_home):
    # Based on https://gist.github.com/ndarville/3452907#file-secret-key-gen-py
    base_dir = Path(base_dir)
    mobsf_home = Path(mobsf_home)
    secret_file = Path(secret_file)
    if os.getenv('MOBSF_SECRET_KEY'):
        secret_key = os.environ['MOBSF_SECRET_KEY']
    elif secret_file.exists() and secret_file.is_file():
        secret_key = secret_file.read_text().strip()
    else:
        try:
            secret_key = get_random()
            secret_file.write_text(secret_key)
        except IOError:
            raise Exception('Secret file generation failed' % secret_file)
        # Run Once
        make_migrations(base_dir)
        migrate(base_dir)
        # Install JADX
        thread = threading.Thread(
            target=install_jadx,
            name='install_jadx',
            args=(mobsf_home.as_posix(),))
        thread.start()
        # Windows Setup
        windows_config_local(mobsf_home.as_posix())
    return secret_key


def create_user_conf(mobsf_home, base_dir):
    try:
        config_path = mobsf_home / 'config.py'
        if not config_path.exists():
            sample_conf = base_dir / 'MobSF' / 'settings.py'
            dat = sample_conf.read_text().splitlines()
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
            conf_str = '\n'.join(config)
            config_path.write_text(conf_str)
    except Exception:
        logger.exception('Cannot create config file')


def django_operation(cmds, base_dir):
    """Generic Function for Djano operations."""
    manage = base_dir.parent / 'manage.py'
    if manage.exists() and manage.is_file():
        # Bail out for package
        return
    print(manage)
    args = [sys.executable, manage.as_posix()]
    args.extend(cmds)
    subprocess.call(args)


def make_migrations(base_dir):
    """Create Database Migrations."""
    try:
        django_operation(['makemigrations'], base_dir)
        django_operation(['makemigrations', 'StaticAnalyzer'], base_dir)
    except Exception:
        logger.exception('Cannot Make Migrations')


def migrate(base_dir):
    """Migrate Database."""
    try:
        django_operation(['migrate'], base_dir)
        django_operation(['migrate', '--run-syncdb'], base_dir)
        django_operation(['create_roles'], base_dir)
    except Exception:
        logger.exception('Cannot Migrate')


def get_random():
    choice = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)'
    return ''.join([random.SystemRandom().choice(choice) for i in range(50)])


def get_mobsf_home(use_home, base_dir):
    try:
        base_dir = Path(base_dir)
        mobsf_home = ''
        if use_home:
            mobsf_home = Path.home() / '.MobSF'
            custom_home = os.getenv('MOBSF_HOME_DIR')
            if custom_home:
                p = Path(custom_home)
                if p.exists() and p.is_absolute() and p.is_dir():
                    mobsf_home = p
            # MobSF Home Directory
            if not mobsf_home.exists():
                mobsf_home.mkdir(parents=True, exist_ok=True)
            create_user_conf(mobsf_home, base_dir)
        else:
            mobsf_home = base_dir
        # Download Directory
        dwd_dir = mobsf_home / 'downloads'
        dwd_dir.mkdir(parents=True, exist_ok=True)
        # Screenshot Directory
        screen_dir = mobsf_home / 'screen'
        screen_dir.mkdir(parents=True, exist_ok=True)
        # Upload Directory
        upload_dir = mobsf_home / 'uploads'
        upload_dir.mkdir(parents=True, exist_ok=True)
        # Downloaded tools
        downloaded_tools_dir = mobsf_home / 'tools'
        downloaded_tools_dir.mkdir(parents=True, exist_ok=True)
        # Signatures Directory
        sig_dir = mobsf_home / 'signatures'
        sig_dir.mkdir(parents=True, exist_ok=True)
        if use_home:
            src = Path(base_dir) / 'signatures'
            try:
                shutil.copytree(src, sig_dir, dirs_exist_ok=True)
            except Exception:
                pass
        return mobsf_home.as_posix()
    except Exception:
        logger.exception('Creating MobSF Home Directory')


def get_mobsf_version():
    return BANNER, VERSION, f'v{VERSION}'


def load_source(modname, filename):
    loader = machinery.SourceFileLoader(modname, filename)
    spec = util.spec_from_file_location(modname, filename, loader=loader)
    module = util.module_from_spec(spec)
    loader.exec_module(module)
    return module
