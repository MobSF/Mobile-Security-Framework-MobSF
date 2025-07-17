# -*- coding: utf_8 -*-
"""Common Frida Server Update Management for Android and iOS."""

import logging
from pathlib import Path
from lzma import LZMAFile
from shutil import copyfileobj

import requests

from django.conf import settings

from mobsf.MobSF.utils import (
    is_internet_available,
    upstream_proxy,
)

logger = logging.getLogger(__name__)


class FridaServerUpdater:
    """Class for managing Frida server updates and downloads."""
    
    def __init__(self, platform, version):
        """Initialize the FridaServerUpdater.
        
        Args:
            platform (str): The platform ('android' or 'ios')
            version (str): The Frida version to manage
        """
        self.download_dir = Path(settings.DWD_DIR)
        self.platform = platform
        self.version = version
    
    def clean_up_old_binaries(self):
        """Delete old Frida server binaries."""
        if self.platform == 'android':
            file_pattern = 'frida-server*'
        else:
            file_pattern = 'frida_*'
        for f in self.download_dir.glob(file_pattern):
            if f.is_file() and self.version not in f.name:
                try:
                    f.unlink()
                except Exception:
                    pass

    def download_frida_server(self, url, fname, proxies, verify):
        """Download Frida server binary."""

        try:
            logger.info('Downloading Frida server binary: %s', fname)
            dwd_loc = self.download_dir / fname
            
            with requests.get(
                    url,
                    timeout=15,
                    proxies=proxies,
                    verify=verify,
                    stream=True) as r:
                r.raise_for_status()
                
                with open(dwd_loc, 'wb') as f:
                    if fname.endswith('.deb'):
                        copyfileobj(r.raw, f)
                    else:
                        copyfileobj(LZMAFile(r.raw), f)
            
            self.clean_up_old_binaries()
            return True
            
        except Exception:
            logger.exception('[ERROR] Downloading Frida Server Binary')
            # Clean up partial download
            try:
                dwd_loc.unlink()
            except Exception:
                pass
        return False

    def update_frida_server(self, arch):
        """Update/download Frida server for the given architecture."""
        if self.platform == 'android':
            fserver = f'frida-server-{self.version}-{self.platform}-{arch}'
        else:
            fserver = f'frida_{self.version}_{self.platform}-{arch}.deb'
        frida_bin = self.download_dir / fserver
        if frida_bin.is_file():
            return True
        if not is_internet_available():
            return False
        try:
            proxies, verify = upstream_proxy('https')
        except Exception:
            logger.exception('[ERROR] Setting upstream proxy')
            proxies, verify = None, True

        try:
            # Get Frida release asset urls
            response = requests.get(
                f'{settings.FRIDA_SERVER}{self.version}',
                timeout=5,
                proxies=proxies,
                verify=verify
            )
            response.raise_for_status()
            
            # Find the correct binary
            if self.platform == 'android':
                asset = f'{fserver}.xz'
            else:
                asset = fserver
            for item in response.json()['assets']:    
                if item['name'] == asset:
                    return self.download_frida_server(
                        item['browser_download_url'], fserver, proxies, verify
                    )

            logger.error('Frida server binary not found for platform: %s, architecture: %s', 
                        self.platform, arch)
            
        except Exception:
            logger.exception('[ERROR] Fetching Frida Server Release')
        
        return False
