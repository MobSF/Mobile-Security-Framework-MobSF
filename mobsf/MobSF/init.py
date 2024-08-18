"""Initialize on first run."""
import logging
import os
import random
import subprocess
import sys
import shutil

from mobsf.install.windows.setup import windows_config_local

logger = logging.getLogger(__name__)

VERSION = '4.0.7'
BANNER = """
  __  __       _    ____  _____       _  _    ___  
 |  \/  | ___ | |__/ ___||  ___|_   _| || |  / _ \ 
 | |\/| |/ _ \| '_ \___ \| |_  \ \ / / || |_| | | |
 | |  | | (_) | |_) |__) |  _|  \ V /|__   _| |_| |
 |_|  |_|\___/|_.__/____/|_|     \_/    |_|(_)___/ 
"""  # noqa: W291
# ASCII Font: Standard


def first_run(secret_file, base_dir, mobsf_home):
    # Based on https://gist.github.com/ndarville/3452907#file-secret-key-gen-py
    if 'MOBSF_SECRET_KEY' in os.environ:
        secret_key = os.environ['MOBSF_SECRET_KEY']
    elif os.path.isfile(secret_file):
        secret_key = open(secret_file).read().strip()
    else:
        try:
            secret_key = get_random()
            secret = open(secret_file, 'w')
            secret.write(secret_key)
            secret.close()
        except IOError:
            raise Exception('Secret file generation failed' % secret_file)
        # Run Once
        make_migrations(base_dir)
        migrate(base_dir)
        # Windows Setup
        windows_config_local(mobsf_home)
    return secret_key


def create_user_conf(mobsf_home, base_dir):
    try:
        config_path = os.path.join(mobsf_home, 'config.py')
        if not os.path.isfile(config_path):
            sample_conf = os.path.join(base_dir, 'MobSF/settings.py')
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


def django_operation(cmds, base_dir):
    """Generic Function for Djano operations."""
    manage = os.path.join(base_dir, '../manage.py')
    if not os.path.exists(manage):
        # Bail out for package
        return
    args = [sys.executable, manage]
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
        mobsf_home = ''
        if use_home:
            mobsf_home = os.path.join(os.path.expanduser('~'), '.MobSF')
            # MobSF Home Directory
            if not os.path.exists(mobsf_home):
                os.makedirs(mobsf_home)
            create_user_conf(mobsf_home, base_dir)
        else:
            mobsf_home = base_dir
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
        # Signature Directory
        sig_dir = os.path.join(mobsf_home, 'signatures/')
        if use_home:
            src = os.path.join(base_dir, 'signatures/')
            try:
                shutil.copytree(src, sig_dir)
            except Exception:
                pass
        elif not os.path.exists(sig_dir):
            os.makedirs(sig_dir)
        return mobsf_home
    except Exception:
        logger.exception('Creating MobSF Home Directory')


def get_mobsf_version():
    return BANNER, VERSION, f'v{VERSION}'
