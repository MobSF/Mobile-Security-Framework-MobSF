"""Read-only Android dynamic runtime diagnostics."""

import json
import re

from django.core.management.base import BaseCommand, CommandError

from mobsf.DynamicAnalyzer.views.android.environment import Environment


class Command(BaseCommand):
    help = 'Read-only diagnostics for an authorized Android.'  # noqa: A003

    def add_arguments(self, parser):
        parser.add_argument('--identifier', required=True)
        parser.add_argument('--json', action='store_true', dest='as_json')

    def handle(self, *args, **options):
        identifier = options['identifier']
        if not re.fullmatch(r'[A-Za-z0-9_.:\[\]-]{1,255}', identifier):
            raise CommandError('Invalid ADB identifier')
        result = Environment(identifier).runtime_preflight()
        if options['as_json']:
            self.stdout.write(json.dumps(result, sort_keys=True))
        else:
            for key, value in result.items():
                self.stdout.write(f'{key}: {value}')
        if not result['ready']:
            raise CommandError('Android runtime is not ready; see diagnostics above')
