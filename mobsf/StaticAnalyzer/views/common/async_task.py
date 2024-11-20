"""Views to handle asynchronous tasks."""
import logging
from datetime import (
    timedelta,
)

from django.dispatch import receiver
from django.utils import timezone
from django.shortcuts import render
from django.conf import settings
from django.http import (
    HttpResponseRedirect,
    JsonResponse,
)
from django.views.decorators.http import require_http_methods

from django_q.tasks import async_task
from django_q.signals import post_execute

from mobsf.StaticAnalyzer.models import (
    EnqueuedTask,
    RecentScansDB,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.MobSF.utils import (
    append_scan_status,
    get_scan_logs,
)

logger = logging.getLogger(__name__)


@receiver(post_execute)
def detect_timeout(sender, task, **kwargs):
    """Detect scan task timeout."""
    if 'Task exceeded maximum timeout' in task['result']:
        task_id = task['id']
        EnqueuedTask.objects.filter(task_id=task_id).update(
            app_name='Failed',
            completed_at=timezone.now(),
            status='Scan Timeout',
        )
        logger.error('Task %s exceeded maximum timeout', task_id)


def async_analysis(checksum, app_name, func, *args):
    """Async Analysis Task."""
    # Check if the task is already completed
    recent = RecentScansDB.objects.filter(MD5=checksum)
    scan_completed = recent[0].APP_NAME or recent[0].PACKAGE_NAME
    # Check if the task is updated within the last 60 minutes
    active_recently = recent[0].TIMESTAMP >= timezone.now() - timedelta(minutes=60)
    # Check if the task is already enqueued within the last 60 minutes
    queued_recently = EnqueuedTask.objects.filter(
        checksum=checksum,
        created_at__gte=timezone.now() - timedelta(minutes=60),
    ).exists()

    # Additional checks on recent queue
    if queued_recently:
        if scan_completed:
            # scan already completed recently
            logger.warning('Analysis already completed in the last 60 minutes')
            return HttpResponseRedirect('/tasks?q=completed')
        elif active_recently:
            # scan not completed but active recently
            logger.warning('Analysis already enqueued in the last 60 minutes')
            return HttpResponseRedirect('/tasks?q=queued')

    # Clear old tasks
    queue_size = settings.QUEUE_MAX_SIZE
    task_count = EnqueuedTask.objects.count()
    if task_count > queue_size:
        logger.info('Deleting oldest enqueued tasks')
        # Get IDs of tasks to delete (keep the latest queue_size)
        oldest_task_ids = list(
            EnqueuedTask.objects.order_by('created_at')
            .values_list('id', flat=True)[:task_count - queue_size])
        # Delete tasks by IDs
        EnqueuedTask.objects.filter(id__in=oldest_task_ids).delete()
    # Enqueue the task
    task_id = async_task(
        func,
        *args,
        queue=True,
        save=False)
    EnqueuedTask.objects.create(
        task_id=task_id,
        checksum=checksum,
        file_name=app_name[:254])
    msg = f'Scan Queued with ID: {task_id}'
    logger.info(msg)
    append_scan_status(checksum, msg)
    return HttpResponseRedirect('/tasks')


def update_enqueued_task(checksum, app_name, status):
    """Update the Enqueued Task and others that matches the checksum."""
    EnqueuedTask.objects.filter(checksum=checksum).update(
        app_name=app_name[:254],
        completed_at=timezone.now(),
        status=status[:254],
    )
    return True


def get_live_status(enq):
    """Get Live Status of the Task."""
    if enq.status == 'Success' or enq.app_name == 'Failed':
        return enq.status
    logs = get_scan_logs(enq.checksum)
    if logs:
        return logs[-1]
    return enq.status


@login_required
@require_http_methods(['POST', 'GET'])
def list_tasks(request):
    if request.method == 'POST':
        enqueued = EnqueuedTask.objects.all().order_by('-created_at')
        task_data = []
        for enq in enqueued:
            # Enqueued task is not in the completed tasks
            task_data.append({
                'task_id': enq.task_id,
                'file_name': enq.file_name,
                'app_name': enq.app_name,
                'checksum': enq.checksum,
                'created_at': enq.created_at,
                'completed_at': enq.completed_at,
                'status': get_live_status(enq),
            })
        return JsonResponse(task_data, safe=False)
    context = {
        'title': 'Scan Tasks',
        'version': settings.MOBSF_VER,
    }
    return render(request, 'general/tasks.html', context)
