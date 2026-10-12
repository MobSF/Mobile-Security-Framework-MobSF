"""Diagnose the explicitly configured interception proxy without target traffic."""

import json

from django.core.management.base import BaseCommand, CommandError

from mobsf.DynamicAnalyzer.tools.capture_runner import proxy_preflight


class Command(BaseCommand):
    help = 'Check Burp/Caido listener and CA configuration.'  # noqa: A003

    def handle(self, *args, **kwargs):
        try:
            result = proxy_preflight()
        except (ValueError, OSError) as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(json.dumps(result))
        if not result['ready']:
            raise CommandError(result['error'])
