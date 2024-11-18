"""Views to handle asynchronous tasks."""
import logging
from datetime import timedelta

from django.utils import timezone
from django.shortcuts import render
from django.conf import settings
from django.http import (
    HttpResponseRedirect,
    JsonResponse,
)
from django.views.decorators.http import require_http_methods

from django_q.tasks import async_task

from mobsf.StaticAnalyzer.models import EnqueuedTask
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.MobSF.utils import (
    append_scan_status,
    get_scan_logs,
)

logger = logging.getLogger(__name__)


def async_analysis(checksum, app_name, func, *args):
    # Check if there is any task with the same checksum
    # created within the last 60 minute
    recent_task_exists = EnqueuedTask.objects.filter(
        checksum=checksum,
        created_at__gte=timezone.now() - timedelta(minutes=60),
    ).exists()
    if recent_task_exists:
        logger.info('Analysis already in progress')
        return HttpResponseRedirect('/tasks')
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
        app_name=app_name,
        completed_at=timezone.now(),
        status=status,
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
