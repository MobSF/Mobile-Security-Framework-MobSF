# -*- coding: utf_8 -*-
"""Stream Android dynamic analysis status while setup is running."""
import json
import logging
import queue
import re
import threading
from contextvars import ContextVar

_CONTROL = re.compile(r'[\x00-\x1f\x7f]')
_MAX_CHARS = 180
_SINK = ContextVar('mobsf_android_dyn_sink', default=None)
_LAST = ContextVar('mobsf_android_dyn_last', default='')


def push_progress_sink(sink):
    """Send subsequent Dynamic Analyzer logs to sink. Returns a token."""
    _ensure_handler()
    return (_SINK.set(sink), _LAST.set(''))


def pop_progress_sink(token):
    """Stop the sink started by push_progress_sink."""
    if not token:
        return
    sink_token, last_token = token
    _SINK.reset(sink_token)
    _LAST.reset(last_token)


def iter_progress_events(work):
    """Run work on a thread and yield its INFO logs, then its result."""
    from django.db import close_old_connections

    updates = queue.Queue()
    box = {}

    def sink(message):
        updates.put(message)

    def runner():
        close_old_connections()
        token = push_progress_sink(sink)
        try:
            box['value'] = work()
        except Exception:
            logging.getLogger('mobsf.MobSF').exception(
                'Android dynamic analysis progress failed')
            box['error'] = 'Dynamic Analysis Failed.'
        finally:
            pop_progress_sink(token)
            close_old_connections()
            updates.put(None)

    threading.Thread(target=runner, daemon=True).start()
    # Encourage proxies and WSGI servers to flush the first chunk.
    yield ':' + (' ' * 2048) + '\n'
    while True:
        item = updates.get()
        if item is None:
            break
        yield json.dumps({'log': item}) + '\n'
    if box.get('error'):
        yield json.dumps({'error': box['error']}) + '\n'
        return
    yield json.dumps({'done': box.get('value')}) + '\n'


def progress_response(work):
    """Stream work's logs as newline-delimited JSON."""
    from django.http import StreamingHttpResponse

    response = StreamingHttpResponse(
        iter_progress_events(work),
        content_type='application/x-ndjson; charset=utf-8',
    )
    response['Cache-Control'] = 'no-cache'
    response['X-Accel-Buffering'] = 'no'
    return response


def _clean(message):
    text = _CONTROL.sub(' ', str(message))
    text = ' '.join(text.split())
    if len(text) > _MAX_CHARS:
        text = text[:_MAX_CHARS - 1] + '…'
    return text


class _ProgressHandler(logging.Handler):
    """Forward INFO+ Dynamic Analyzer records to the active sink."""

    def emit(self, record):
        sink = _SINK.get()
        if sink is None or record.levelno < logging.INFO:
            return
        try:
            message = _clean(record.getMessage())
        except Exception:
            return
        if not message or message == _LAST.get():
            return
        _LAST.set(message)
        try:
            sink(message)
        except Exception:
            return


def _ensure_handler():
    logger = logging.getLogger('mobsf.DynamicAnalyzer')
    if any(getattr(handler, 'mobsf_android_progress', False)
           for handler in logger.handlers):
        return
    handler = _ProgressHandler()
    handler.mobsf_android_progress = True
    handler.setLevel(logging.INFO)
    logger.addHandler(handler)
