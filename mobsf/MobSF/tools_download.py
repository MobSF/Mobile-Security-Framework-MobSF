"""Download tools required by MobSF."""
import logging
import sys
import shutil
import tempfile
import zipfile
import platform
from pathlib import Path
from urllib.request import (
    Request,
    urlopen,
)


logger = logging.getLogger(__name__)


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
            # Download JADX zip file
            with urlopen(Request(url)) as response:
                if response.status == 200:
                    tmp_zip_file.write(response.read())
                    logger.info('JADX download complete')
                else:
                    logger.error('Failed to download JADX zip. '
                                 'Status code: %s', response.status)
                    return

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
