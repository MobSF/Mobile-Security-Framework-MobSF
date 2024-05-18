"""Command to create Authorization Roles."""
from django.core.management.base import BaseCommand

from mobsf.MobSF.views.authorization import create_authorization_roles


class Command(BaseCommand):
    help = 'Create Authorization Roles.'  # noqa: A003

    def handle(self, *args, **kwargs):
        create_authorization_roles()
        self.stdout.write('Roles Created Successfully!')
