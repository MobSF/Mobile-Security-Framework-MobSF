"""Restore Android network state when MobSF shuts down."""
import json
import logging
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from mobsf.DynamicAnalyzer.views.android.environment import Environment
from mobsf.MobSF.utils import (
    get_android_devices,
    valid_android_device_identifier,
)

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Clean MobSF-owned proxy and Frida mappings from online devices."""

    help = 'Restore network state on Android devices used by MobSF'  # noqa A003

    @staticmethod
    def _proxy_states():
        states = {}
        upload_dir = Path(settings.UPLD_DIR)
        for state_file in upload_dir.glob('*/.mobsf-proxy-state'):
            if not state_file.is_file() or state_file.is_symlink():
                continue
            try:
                with state_file.open(encoding='utf-8') as source:
                    state = json.load(source)
            except (OSError, ValueError, TypeError):
                logger.warning('Ignoring invalid Android proxy state')
                continue
            if not isinstance(state, dict):
                continue
            identifier = state.get('identifier')
            if not valid_android_device_identifier(identifier):
                continue
            states.setdefault(identifier, []).append((state_file, state))
        for entries in states.values():
            entries.sort(key=lambda item: item[0].stat().st_mtime)
        return states

    @staticmethod
    def _remove_frida_forwards(env):
        output = env.adb_command(
            ['forward', '--list'],
            silent=True,
        ) or b''
        for line in output.decode('utf-8', 'ignore').splitlines():
            parts = line.split()
            if (len(parts) >= 3
                    and parts[0] == env.identifier
                    and parts[2] == 'tcp:27042'):
                env.adb_command(
                    ['forward', '--remove', parts[1]],
                    silent=True,
                )

    def handle(self, *args, **options):
        states = self._proxy_states()
        failures = 0
        online = [
            device['identifier']
            for device in get_android_devices()
            if device['state'] == 'device'
        ]
        for identifier in online:
            env = Environment(identifier)
            entries = states.get(identifier, [])
            restored = True
            if entries:
                original_state = entries[0][1]
                previous_proxy = original_state.get('proxy', '')
                if not isinstance(previous_proxy, str):
                    previous_proxy = ''
                restored = env.restore_global_proxy(previous_proxy)
            else:
                current_proxy = env.get_global_proxy()
                try:
                    mobsf_proxy = env.get_mobsf_proxy(
                        env.get_android_version())
                except Exception:
                    mobsf_proxy = ''
                stale_proxies = {
                    mobsf_proxy,
                    f'127.0.0.1:{settings.PROXY_PORT}',
                    f'localhost:{settings.PROXY_PORT}',
                }
                stale_proxies.discard('')
                if current_proxy in stale_proxies:
                    restored = env.restore_global_proxy('')
            env.disable_adb_reverse_tcp()
            self._remove_frida_forwards(env)
            if restored:
                for state_file, _ in entries:
                    state_file.unlink(missing_ok=True)
                    gadget_marker = (
                        state_file.parent / '.mobsf-gadget-mode')
                    gadget_marker.unlink(missing_ok=True)
                self.stdout.write(
                    f'Restored Android device {identifier}')
            else:
                failures += 1
                logger.error(
                    'Failed to restore Android device %s',
                    identifier,
                )
        if failures:
            raise CommandError(
                f'Failed to restore {failures} Android device(s)')
