# -*- coding: utf_8 -*-
"""Use aapt2 to extract APK features."""
import re
import logging
import subprocess
from platform import system
from pathlib import Path

from django.conf import settings

from mobsf.MobSF.utils import (
    find_aapt,
)

logger = logging.getLogger(__name__)


class AndroidAAPT:

    def __init__(self, apk_path):
        self.aapt2_path = None
        self.aapt_path = None
        self.apk_path = apk_path
        self.data = {
            'permissions': [],
            'uses_features': {},
            'package': None,
            'application_label': None,
            'application_icon': None,
            'launchable_activity': None,
            'min_sdk_version': None,
            'target_sdk_version': None,
        }

        # Check for custom AAPT2 path in settings
        if (getattr(settings, 'AAPT2_BINARY', '')
                and len(settings.AAPT2_BINARY) > 0
                and Path(settings.AAPT2_BINARY).exists()):
            self.aapt2_path = settings.AAPT2_BINARY
        else:
            aapt2 = 'aapt2.exe' if system() == 'Windows' else 'aapt2'
            self.aapt2_path = find_aapt(aapt2)

        # Check for custom AAPT path in settings
        if (getattr(settings, 'AAPT_BINARY', '')
                and len(settings.AAPT_BINARY) > 0
                and Path(settings.AAPT_BINARY).exists()):
            self.aapt_path = settings.AAPT_BINARY
        else:
            aapt = 'aapt.exe' if system() == 'Windows' else 'aapt'
            self.aapt_path = find_aapt(aapt)

        # Ensure both aapt and aapt2 are found
        if not (self.aapt2_path and self.aapt_path):
            raise FileNotFoundError('aapt and aapt2 found')

    def _execute_command(self, args):
        try:
            out = subprocess.check_output(
                args,
                stderr=subprocess.STDOUT)
            return out.decode('utf-8', errors='ignore')
        except subprocess.CalledProcessError as e:
            logger.warning(e.output)
            return None

    def _get_strings(self, output):
        # Regex to match strings while ignoring paths (strings without slashes)
        pattern = r'String #[\d]+ : ([^\/\n]+)'
        matches = re.findall(pattern, output)
        # Strip whitespace and return the extracted strings
        return [match.strip() for match in matches]

    def _parse_badging(self, output):
        # Match the package information
        package_match = re.search(r'package: name=\'([\w\.]+)\'', output)
        if package_match:
            self.data['package'] = package_match.group(1)

        # Match permissions
        permissions = re.findall(r'uses-permission: name=\'([\w\.]+)\'', output)
        if permissions:
            self.data['permissions'] = permissions

        # Match minSdkVersion
        min_sdk_match = re.search(r'minSdkVersion:\'(\d+)\'', output)
        if min_sdk_match:
            self.data['min_sdk_version'] = min_sdk_match.group(1)

        # Match targetSdkVersion
        target_sdk_match = re.search(r'targetSdkVersion:\'(\d+)\'', output)
        if target_sdk_match:
            self.data['target_sdk_version'] = target_sdk_match.group(1)

        # Match application label
        label_match = re.search(r'application-label(?:-[\w\-]+)?:\'([^\']+)\'', output)
        if label_match:
            self.data['application_label'] = label_match.group(1)

        # Match application icon
        icon_match = re.search(r'application:.*icon=\'([^\']+)\'', output)
        if icon_match:
            self.data['application_icon'] = icon_match.group(1)

        # Match launchable activity
        activity_match = re.search(r'launchable-activity: name=\'([\w\.]+)\'', output)
        if activity_match:
            self.data['launchable_activity'] = activity_match.group(1)

        # Match used features
        features = {}
        feature_matches = re.findall(
            (r'(uses-feature(?:-not-required)?|uses-implied-feature): '
             r'name=\'([\w\.]+)\'(?: reason=\'([^\']+)\')?'),
            output,
        )
        for feature_type, feature_name, reason in feature_matches:
            features[feature_name] = {
                'type': feature_type,
                # e.g., 'uses-feature',
                # 'uses-feature-not-required',
                # 'uses-implied-feature'
                'reason': reason if reason else 'No reason provided',
            }
        self.data['uses_features'] = features

        return self.data

    def get_apk_files(self):
        """List all files in the APK."""
        output = self._execute_command(
            [self.aapt_path, 'list', self.apk_path])
        if output:
            return output.splitlines()
        return []

    def get_apk_strings(self):
        """Extract strings from the APK."""
        output = self._execute_command(
            [self.aapt2_path, 'dump', 'strings', self.apk_path])
        if output:
            return self._get_strings(output)
        return []

    def get_apk_features(self):
        """Extract features from the APK."""
        output = self._execute_command(
            [self.aapt2_path, 'dump', 'badging', self.apk_path])
        if output:
            return self._parse_badging(output)
        return self.data
