"""Exercise the actual native Windows executable, scan and persistent workspace."""

import argparse
import hashlib
import json
import os
import re
import secrets
import signal
import subprocess
import time
from pathlib import Path

import requests

BASE = 'http://127.0.0.1:8000'
ROOT = Path(__file__).resolve().parent.parent


def diagnostic(text):
    """Expose bounded CI errors without printing credentials or environment dumps."""
    lines = text.splitlines()[-35:]
    lines = [line for line in lines if not re.search(
        r'password|api.?key|authorization|bearer|secret', line, re.I)]
    return re.sub(r'[a-fA-F0-9]{32,}', '[REDACTED]', '\n'.join(lines))[-2500:]


def checked(command, env):
    """Keep subprocess error details reviewable in public CI annotations."""
    result = subprocess.run(command, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True,
                            encoding='utf-8', errors='replace')
    if result.returncode:
        raise RuntimeError('Native ' + command[-1] + ' failed:\n'
                           + diagnostic(result.stdout))
    print('Native command passed:', command[-1], flush=True)


def run_smoke(executable, runtime_command=None):
    """Use only synthetic owned data in an isolated application profile."""
    profile = Path(os.environ['APPDATA']) / 'MobSF-BugBounty'
    command = [str(executable)]
    env = dict(os.environ, MOBSF_DESKTOP_NO_BROWSER='1')
    if runtime_command:
        command = [runtime_command, str(ROOT / 'scripts/native_runtime.py')]
    else:
        checked(command + ['install'], env)
        checked(command + ['doctor'], env)
    config = dict(
        line.split('=', 1)
        for line in (profile / 'desktop.env').read_text().splitlines()
        if line
    )
    secret = (profile / 'data/secret').read_bytes().strip()
    api_headers = {'Authorization': hashlib.sha256(secret).hexdigest()}
    name = 'native-smoke-' + secrets.token_hex(8)
    original_secret = secret
    program_id = None
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
    for attempt in range(2):
        action = 'serve' if runtime_command else 'start'
        with (profile / f'smoke-server-{attempt}.log').open('w') as log:
            server = subprocess.Popen(
                command + [action],
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                creationflags=flags,
            )
            try:
                session = requests.Session()
                session.trust_env = False
                for _ in range(180):
                    if server.poll() is not None:
                        raise RuntimeError(
                            'Native server exited:\n' + diagnostic(
                                (profile / f'smoke-server-{attempt}.log').read_text(
                                    encoding='utf-8', errors='replace')),
                        )
                    try:
                        response = session.get(BASE + '/login/', timeout=3)
                        health = session.get(
                            BASE + '/__mobsf_desktop_health__',
                            timeout=3,
                        )
                        if (
                            response.status_code == 200
                            and 'csrfmiddlewaretoken' in response.text
                            and health.status_code == 200
                            and len(health.text) == 64
                        ):
                            break
                    except requests.RequestException:
                        pass
                    time.sleep(1)
                else:
                    raise RuntimeError('Native startup readiness timed out')
                csrf = session.cookies['csrftoken']
                response = session.post(
                    BASE + '/login/',
                    data={
                        'username': 'mobsf',
                        'password': config['MOBSF_ADMIN_PASSWORD'],
                        'csrfmiddlewaretoken': csrf,
                    },
                    timeout=30,
                )
                response.raise_for_status()
                assert 'sessionid' in session.cookies, 'Native login failed'
                response = session.get(BASE + '/bounty/', timeout=30)
                response.raise_for_status()
                assert 'csrfmiddlewaretoken' in response.text
                csrf_headers = {'X-CSRFToken': session.cookies['csrftoken']}
                if attempt == 0:
                    response = session.post(
                        BASE + '/bounty/api/programs/',
                        json={'name': name, 'rules': {}},
                        headers=csrf_headers,
                        timeout=30,
                    )
                    assert response.status_code == 201, response.text
                    program_id = response.json()['id']
                    fixture = (
                        ROOT / 'mobsf/DynamicAnalyzer/fixtures' / 'android17-static.apk'
                    )
                    with fixture.open('rb') as apk:
                        response = session.post(
                            BASE + '/api/v1/upload',
                            files={
                                'file': (
                                    fixture.name,
                                    apk,
                                    'application/vnd.android.package-archive',
                                ),
                            },
                            headers=api_headers,
                            timeout=60,
                        )
                    response.raise_for_status()
                    upload = response.json()
                    assert upload.get('hash'), upload
                    response = session.post(
                        BASE + '/api/v1/scan',
                        data=upload,
                        headers=api_headers,
                        timeout=600,
                    )
                    response.raise_for_status()
                    response = session.post(
                        BASE + '/api/v1/report_json',
                        data={'hash': upload['hash']},
                        headers=api_headers,
                        timeout=60,
                    )
                    response.raise_for_status()
                    report = response.json()
                    assert report['package_name'] == 'test.mobsf.android17'
                    assert str(report['min_sdk']) == '37', report.get('min_sdk')
                    assert str(report['target_sdk']) == '37', report.get('target_sdk')
                    response = session.post(
                        BASE + f'/bounty/api/programs/{program_id}/import/',
                        json={'checksum': upload['hash']},
                        headers=csrf_headers,
                        timeout=60,
                    )
                    assert response.status_code == 200, response.text
                else:
                    response = session.get(
                        BASE + f'/bounty/api/programs/{program_id}/',
                        timeout=30,
                    )
                    response.raise_for_status()
                    assert response.json()['name'] == name
                assert (profile / 'data/secret').read_bytes().strip() == original_secret
            finally:
                session.close()
                if os.name == 'nt':
                    # Signal only our own console process group.
                    if server.poll() is None:
                        server.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    server.terminate()
                try:
                    server.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    if os.name == 'nt':
                        subprocess.run(
                            ['taskkill', '/PID', str(server.pid), '/T', '/F'],
                            check=True,
                            stdout=subprocess.DEVNULL,
                        )
                    else:
                        server.kill()
                    server.wait(timeout=10)
        if not runtime_command:
            # Reinstallation must preserve the database, secret and password.
            checked(command + ['install'], env)
    print(
        json.dumps(
            {
                'native_login': 'passed',
                'android_17_scan': 'passed',
                'workspace_import': 'passed',
                'restart_persistence': 'passed',
            },
        ),
    )


def main():
    """Run a Windows executable or the same native server on the cloud host."""
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime-python')
    args = parser.parse_args()
    try:
        run_smoke(ROOT / 'windows/MobSF-BugBounty.exe', args.runtime_python)
    except Exception as exc:
        if os.getenv('GITHUB_ACTIONS') == 'true':
            detail = diagnostic(str(exc)).replace('%', '%25')
            detail = detail.replace('\r', '%0D').replace('\n', '%0A')
            print('::error title=Native Windows diagnostic::' + detail, flush=True)
        raise


if __name__ == '__main__':
    main()
