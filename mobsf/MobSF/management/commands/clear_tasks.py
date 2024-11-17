from django.core.management.base import BaseCommand

from django_q.models import (
    OrmQ,
    Task,
)

from mobsf.StaticAnalyzer.models import EnqueuedTask


class Command(BaseCommand):
    help = 'Deletes all tasks in Django Q'  # noqa: A003

    def handle(self, *args, **kwargs):
        Task.objects.all().delete()
        OrmQ.objects.all().delete()
        EnqueuedTask.objects.all().delete()
        self.stdout.write(self.style.SUCCESS('Successfully deleted all Django Q tasks'))
