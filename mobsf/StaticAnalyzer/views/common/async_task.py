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
    result = task.get('result')
    if isinstance(result, str) and 'Task exceeded maximum timeout' in result:
        task_id = task['id']
        EnqueuedTask.objects.filter(task_id=task_id).update(
            app_name='Failed',
            completed_at=timezone.now(),
            status='Scan Timeout',
        )
        logger.error('Task %s exceeded maximum timeout', task_id)


def async_analysis(checksum, api, file_name, func, *args, **kwargs):
    """Async Analysis Task."""
    # Check if the scan is already completed and successful
    scan_completed = False
    recent = RecentScansDB.objects.filter(MD5=checksum)
    if recent.exists() and (recent[0].APP_NAME or recent[0].PACKAGE_NAME):
        # Successful scan will have APP_NAME or PACKAGE_NAME
        scan_completed = True
    # Check if task is already completed within the last 60 minutes
    # Can be success or failed
    completed_at_recently = EnqueuedTask.objects.filter(
        checksum=checksum,
        completed_at__gte=timezone.now() - timedelta(
            minutes=settings.ASYNC_ANALYSIS_TIMEOUT),
    ).exists()

    # Check if the task is already enqueued within the last 60 minutes
    queued_recently = EnqueuedTask.objects.filter(
        checksum=checksum,
        created_at__gte=timezone.now() - timedelta(
            minutes=settings.ASYNC_ANALYSIS_TIMEOUT),
    ).exists()
    # Check if the task is already started within the last 60 minutes
    started_at_recently = EnqueuedTask.objects.filter(
        checksum=checksum,
        started_at__gte=timezone.now() - timedelta(
            minutes=settings.ASYNC_ANALYSIS_TIMEOUT),
    ).exists()

    # Prevent duplicate scans in the last 60 minutes
    if scan_completed and completed_at_recently:
        # scan task already completed with success/failure recently
        msg = ('Analysis already completed/failed in the '
               f'last {settings.ASYNC_ANALYSIS_TIMEOUT} minutes. '
               'Please try again later.')
        logger.warning(msg)
        if api:
            return {'task_id': None, 'message': msg}
        return HttpResponseRedirect('/tasks?q=completed')
    elif queued_recently or started_at_recently:
        # scan not completed but queued or started recently
        msg = ('Analysis already enqueued in the '
               f'last {settings.ASYNC_ANALYSIS_TIMEOUT} minutes. '
               'Please wait for the current scan to complete.')
        logger.warning(msg)
        if api:
            return {'task_id': None, 'message': msg}
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
        file_name=file_name[:254])
    msg = f'Scan Queued with ID: {task_id}'
    logger.info(msg)
    append_scan_status(checksum, msg)
    if api:
        return {'task_id': task_id, 'message': msg}
    return HttpResponseRedirect('/tasks')


def mark_task_started(checksum):
    """Register the enqued task and others that matches the checksum as started."""
    EnqueuedTask.objects.filter(checksum=checksum).update(
        started_at=timezone.now(),
    )


def mark_task_completed(checksum, app_name, status):
    """Update the enqueued task and others that matches the checksum as completed."""
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
        return logs[-1].get('status', '')
    return enq.status


@login_required
@require_http_methods(['POST', 'GET'])
def list_tasks(request, api=False):
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
                'started_at': enq.started_at,
                'completed_at': enq.completed_at,
                'status': get_live_status(enq),
            })
        if api:
            return task_data
        return JsonResponse(task_data, safe=False)
    context = {
        'title': 'Scan Tasks',
        'version': settings.MOBSF_VER,
    }
    return render(request, 'general/tasks.html', context)
