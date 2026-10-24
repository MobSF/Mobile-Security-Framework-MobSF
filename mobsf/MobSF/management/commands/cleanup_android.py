"""Clear MobSF Android proxy state when MobSF shuts down."""
import logging

from django.core.management.base import BaseCommand, CommandError

from mobsf.DynamicAnalyzer.views.android.environment import Environment
from mobsf.MobSF.utils import (
    clear_analysis_state,
    get_android_devices,
    is_md5,
    read_analysis_state,
    scan_state_root,
    valid_android_device_identifier,
)

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Clean MobSF-owned proxy and Frida mappings from online devices."""

    help = 'Clear proxy settings on Android devices used by MobSF'  # noqa A003

    @staticmethod
    def _proxy_states():
        states = {}
        for state_file in scan_state_root().glob('*/proxy-state'):
            checksum = state_file.parent.name
            if not is_md5(checksum):
                continue
            state = read_analysis_state(checksum)
            identifier = state.get('identifier')
            if not valid_android_device_identifier(identifier):
                continue
            states.setdefault(identifier, []).append((state_file, state))
        for entries in states.values():
            entries.sort(key=lambda item: item[0].stat().st_mtime)
        return states

    def handle(self, *args, **options):
        states = self._proxy_states()
        failures = 0
        online = [
            device['identifier']
            for device in get_android_devices()
            if device['state'] == 'device'
        ]
        for identifier in online:
            entries = states.get(identifier, [])
            if not entries:
                continue
            env = Environment(identifier)
            env.clear_proxy()
            env.stop_physical_frida_server()
            if not env.remove_frida_forward():
                failures += 1
                logger.error(
                    'Failed to clean up Android device %s', identifier)
            for state_file, _ in entries:
                clear_analysis_state(state_file.parent.name)
            self.stdout.write(f'Cleared proxy on Android device {identifier}')
        if failures:
            raise CommandError(
                f'Failed to clean up {failures} Android device(s)')
