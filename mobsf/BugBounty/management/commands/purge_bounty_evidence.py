"""Remove expired evidence according to the configured retention period."""
from django.core.management.base import BaseCommand
from django.utils import timezone

from mobsf.BugBounty.models import Evidence


class Command(BaseCommand):
    def add_arguments(self, parser):
        parser.description = 'Delete expired evidence; preserve review history'

    def handle(self, *args, **options):
        count, _details = Evidence.objects.filter(
            expires_at__lte=timezone.now()).delete()
        self.stdout.write(f'Deleted {count} expired evidence records')
