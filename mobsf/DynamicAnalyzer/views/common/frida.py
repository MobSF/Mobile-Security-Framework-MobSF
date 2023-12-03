"""Shared Frida Views."""
import glob
import os
from pathlib import Path

from django.conf import settings
from django.views.decorators.http import require_http_methods

from mobsf.DynamicAnalyzer.views.common.shared import (
    send_response,
)
from mobsf.MobSF.utils import (
    is_file_exists,
    is_safe_path,
)
# AJAX


@require_http_methods(['POST'])
def list_frida_scripts(request, api=False):
    """List frida scripts from others."""
    scripts = []
    device = request.POST.get('device', 'android')
    if device != 'android':
        device = 'ios'
    others = os.path.join(settings.TOOLS_DIR,
                          'frida_scripts',
                          device,
                          'others')
    files = glob.glob(others + '**/*.js', recursive=True)
    for item in files:
        scripts.append(Path(item).stem)
    scripts.sort()
    return send_response(
        {'status': 'ok',
         'files': scripts},
        api)
# AJAX


@require_http_methods(['POST'])
def get_script(request, api=False):
    """Get frida scripts from others."""
    data = {'status': 'ok', 'content': ''}
    try:
        device = request.POST.get('device', 'android')
        if device != 'android':
            device = 'ios'
        scripts = request.POST.getlist('scripts[]')
        others = os.path.join(settings.TOOLS_DIR,
                              'frida_scripts',
                              device,
                              'others')
        script_ct = []
        for script in scripts:
            script_file = os.path.join(others, script + '.js')
            if not is_safe_path(others, script_file):
                data = {
                    'status': 'failed',
                    'message': 'Path traversal detected.'}
                return send_response(data, api)
            if is_file_exists(script_file):
                script_ct.append(Path(script_file).read_text())
        data['content'] = '\n'.join(script_ct)
    except Exception:
        pass
    return send_response(data, api)
