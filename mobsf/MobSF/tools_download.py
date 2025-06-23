import logging
import sys
import shutil
import tempfile
import zipfile
import platform
import os
import ssl
from pathlib import Path
from urllib.request import (
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
    getproxies,
)

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(asctime)-15s - %(message)s',
    datefmt='%d/%b/%Y %H:%M:%S')
logger = logging.getLogger(__name__)


def standalone_upstream_proxy():
    """Set upstream Proxy for urllib - standalone."""
    upstream_proxy_enabled = bool(os.getenv('MOBSF_UPSTREAM_PROXY_ENABLED', ''))

    if upstream_proxy_enabled:
        upstream_proxy_username = os.getenv('MOBSF_UPSTREAM_PROXY_USERNAME', '')
        upstream_proxy_password = os.getenv('MOBSF_UPSTREAM_PROXY_PASSWORD', '')
        upstream_proxy_type = os.getenv('MOBSF_UPSTREAM_PROXY_TYPE', 'http')
        upstream_proxy_ip = os.getenv('MOBSF_UPSTREAM_PROXY_IP', '127.0.0.1')
        upstream_proxy_port = int(os.getenv('MOBSF_UPSTREAM_PROXY_PORT', '3128'))

        # Handle Docker proxy IP translation
        if os.getenv('MOBSF_PLATFORM') == 'docker':
            if (upstream_proxy_ip and upstream_proxy_ip.strip() in
                    ('127.0.0.1', 'localhost')):
                upstream_proxy_ip = 'host.docker.internal'

        if not upstream_proxy_username:
            proxy_port = str(upstream_proxy_port)
            proxy_host = f'{upstream_proxy_type}://{upstream_proxy_ip}:{proxy_port}'
        else:
            proxy_port = str(upstream_proxy_port)
            proxy_host = (f'{upstream_proxy_type}://{upstream_proxy_username}:'
                          f'{upstream_proxy_password}@{upstream_proxy_ip}:'
                          f'{proxy_port}')

        # For urllib, we need to set both http and https proxies
        proxies = {
            'http': proxy_host,
            'https': proxy_host,
        }
    else:
        proxies = {}

    upstream_proxy_ssl_verify = os.getenv('MOBSF_UPSTREAM_PROXY_SSL_VERIFY', '1')
    verify = upstream_proxy_ssl_verify in ('1', '"1"')
    return proxies, verify


def download_file(url, file_path):
    req = Request(url)

    # Check for system proxies first (http_proxy, https_proxy env vars)
    system_proxies = getproxies()

    if system_proxies:
        proxies = system_proxies
        verify = True  # Default to verify for system proxies
        logger.info('Using system proxies (SSL verify: %s)', verify)
    else:
        # Check if MobSF upstream proxy is explicitly configured
        upstream_proxy_enabled = bool(os.getenv('MOBSF_UPSTREAM_PROXY_ENABLED', ''))

        if upstream_proxy_enabled:
            proxies, verify = standalone_upstream_proxy()
            logger.info('Using MobSF upstream proxies (SSL verify: %s)', verify)
        else:
            # No proxy configuration - use direct connection
            proxies = {}
            verify = True

    proxy_handler = ProxyHandler(proxies)

    if verify:
        ssl_context = ssl.create_default_context()
    else:
        ssl_context = ssl._create_unverified_context()

    https_handler = HTTPSHandler(context=ssl_context)
    opener = build_opener(proxy_handler, https_handler)

    with opener.open(req) as response:
        if response.status == 200:
            file_size = int(response.headers.get('Content-Length', 0))
            downloaded = 0
            block_size = 8192  # 8KB

            with open(file_path, 'wb') as f:
                while True:
                    buffer = response.read(block_size)
                    if not buffer:
                        break
                    downloaded += len(buffer)
                    f.write(buffer)

                    # Print progress
                    if file_size > 0:
                        done = int(50 * downloaded / file_size)
                        fmt = (f'\r[{"#" * done}{"-" * (50 - done)}] '
                               f'{downloaded * 100 / file_size:.2f}%')
                        sys.stdout.write(fmt)
                        sys.stdout.flush()

            if downloaded != file_size:
                err = (f'Downloaded file size ({downloaded}) '
                       f'does not match expected size ({file_size})')
                raise Exception(err)

            return downloaded
        else:
            raise Exception(f'Failed to download file. Status code: {response.status}')


def install_jadx(mobsf_home, version='1.5.0'):
    """Install JADX dynamically."""
    try:
        url = ('https://github.com/skylot/jadx/releases/download/'
               f'v{version}/jadx-{version}.zip')
        jadx_dir = Path(mobsf_home) / 'tools' / 'jadx'
        extract_dir = jadx_dir / f'jadx-{version}'

        if extract_dir.exists():
            logger.info('JADX is already installed at %s', extract_dir)
            return

        logger.info('Downloading JADX from %s', url)
        shutil.rmtree(jadx_dir, ignore_errors=True)

        with tempfile.NamedTemporaryFile(
                delete=False,
                mode='wb',
                suffix='.zip') as tmp_zip_file:

            downloaded_size = download_file(url, tmp_zip_file.name)
            logger.info('JADX download complete. File size: %d bytes', downloaded_size)

            # Extract the zip file
            logger.info('Extracting JADX to %s', extract_dir)
            extract_dir.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(tmp_zip_file.name, 'r') as zip_ref:
                for member in zip_ref.namelist():
                    zip_ref.extract(member, extract_dir)

        # Set execute permission
        set_rwxr_xr_x_permission_recursively(extract_dir)

        logger.info('JADX installed successfully')
    except Exception:
        logger.exception('Error during JADX installation')
    finally:
        if 'tmp_zip_file' in locals():
            Path(tmp_zip_file.name).unlink()


def set_rwxr_xr_x_permission_recursively(directory_path):
    """Set execute permissions recursively."""
    if platform.system() == 'Windows':
        logger.info('Permission setting is skipped on non-Unix systems.')
        return

    logger.info('Setting execute permission for JADX directory')
    directory_path.chmod(0o755)

    # Recursively set permissions for all files and
    # directories within the root directory
    for path in directory_path.rglob('*'):
        path.chmod(0o755)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    install_jadx(sys.argv[1])
