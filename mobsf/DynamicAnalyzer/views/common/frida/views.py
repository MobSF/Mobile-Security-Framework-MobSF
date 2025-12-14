"""Shared Frida Views."""
import logging
from pathlib import Path

from django.conf import settings
from django.shortcuts import render
from django.views.decorators.http import require_http_methods

from mobsf.DynamicAnalyzer.views.common.shared import (
    send_response,
)
from mobsf.MobSF.utils import (
    is_md5,
    is_safe_path,
    print_n_send_error_response,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)


logger = logging.getLogger(__name__)


# AJAX


@login_required
@require_http_methods(['POST'])
def list_frida_scripts(request, api=False):
    """List frida scripts from others."""
    scripts = []
    device = request.POST.get('device', 'android')
    if device != 'android':
        device = 'ios'
    others = Path(settings.TOOLS_DIR) / 'frida_scripts' / device / 'others'
    files = list(others.rglob('*.js'))
    for item in files:
        scripts.append(Path(item).stem)
    scripts.sort()
    return send_response(
        {'status': 'ok',
         'files': scripts},
        api)
# AJAX


@login_required
@require_http_methods(['POST'])
def get_script_content(request, api=False):
    """Get frida scripts from others."""
    data = {'status': 'ok', 'content': ''}
    try:
        device = request.POST.get('device', 'android')
        if device != 'android':
            device = 'ios'
        scripts = request.POST.getlist('scripts[]')
        others = Path(settings.TOOLS_DIR) / 'frida_scripts' / device / 'others'
        script_ct = []
        for script in scripts:
            script_file = others / f'{script}.js'
            if not is_safe_path(str(others), str(script_file), script):
                data = {
                    'status': 'failed',
                    'message': 'Path traversal detected.'}
                return send_response(data, api)
            if script_file.exists():
                script_ct.append(script_file.read_text())
        data['content'] = '\n'.join(script_ct)
    except Exception:
        pass
    return send_response(data, api)
# AJAX + HTML


@login_required
def frida_logs(request, api=False):
    try:
        data = {
            'status': 'failed',
            'message': 'Data does not exist.'}
        if api:
            apphash = request.POST['hash']
            stream = True
        else:
            apphash = request.GET.get('hash', '')
            stream = request.GET.get('stream', '')
        if not is_md5(apphash):
            data['message'] = 'Invalid hash'
            return send_response(data, api)
        if stream:
            apk_dir = Path(settings.UPLD_DIR) / apphash
            frida_logs = apk_dir / 'mobsf_frida_out.txt'
            if not frida_logs.exists():
                return send_response(data, api)
            data = {
                'status': 'ok',
                'message': frida_logs.read_text(encoding='utf8', errors='ignore'),
            }
            return send_response(data, api)
        logger.info('Frida Logs live streaming')
        template = 'dynamic_analysis/android/frida_logs.html'
        return render(request,
                      template,
                      {'hash': apphash,
                       'package': request.GET.get('package', ''),
                       'version': settings.MOBSF_VER,
                       'title': 'Live Frida logs'})
    except Exception:
        logger.exception('Frida log streaming')
        err = 'Error in Frida log streaming'
        return print_n_send_error_response(request, err, api)
