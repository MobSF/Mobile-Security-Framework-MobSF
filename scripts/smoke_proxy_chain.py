"""Verify local capture forwarding and HTTPS CA trust using owned fixtures."""

import argparse
from datetime import datetime, timedelta, timezone
import os
import secrets
import select
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import requests

ROOT = Path(__file__).resolve().parent.parent


class FixtureHandler(BaseHTTPRequestHandler):
    """A fake interceptor that handles only the synthetic fixture domain."""

    def log_message(self, *args):
        pass

    def do_GET(self):  # noqa: N802 - HTTP handler contract
        self.send_response(200)
        self.send_header('Content-Length', str(len(b'owned-proxy-fixture!!')))
        self.end_headers()
        self.wfile.write(b'owned-proxy-fixture!!')

    def do_CONNECT(self):  # noqa: N802 - HTTP handler contract
        if self.path != 'fixture.test:443':
            self.send_error(403)
            return
        upstream = socket.create_connection(('127.0.0.1', self.server.tls_port))
        try:
            self.send_response(200, 'Connection established')
            self.end_headers()
            peers = (self.connection, upstream)
            while True:
                ready, _, _ = select.select(peers, [], [], 10)
                if not ready:
                    return
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    destination = (
                        upstream if source is self.connection else self.connection
                    )
                    destination.sendall(data)
        except OSError:
            pass
        finally:
            upstream.close()


def fixture_certificate(root):
    """Make a temporary CA and fixture-only HTTPS certificate."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Owned fixture CA')])
    now = datetime.now(timezone.utc)
    ca = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'fixture.test')])
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName('fixture.test')]), critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    ca_file = root / 'fixture-ca.pem'
    leaf_file = root / 'fixture-leaf.pem'
    key_file = root / 'fixture-key.pem'
    ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    leaf_file.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    return ca_file, leaf_file, key_file


def available_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def run_smoke(python):
    """Send fixture requests only through a loopback proxy, with no target DNS."""
    with tempfile.TemporaryDirectory(prefix='mobsf-proxy-lab-') as temporary:
        root = Path(temporary)
        ca_file, leaf_file, key_file = fixture_certificate(root)
        backend = ThreadingHTTPServer(('127.0.0.1', 0), FixtureHandler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(leaf_file, key_file)
        backend.socket = context.wrap_socket(backend.socket, server_side=True)
        upstream = ThreadingHTTPServer(('127.0.0.1', 0), FixtureHandler)
        upstream.tls_port = backend.server_port
        for server in (backend, upstream):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            for provider, trusted in (('burp', False), ('burp', True), ('caido', True)):
                home = root / (provider + str(trusted))
                home.mkdir()
                (home / 'secret').write_text(secrets.token_urlsafe(50))
                port = available_port()
                env = dict(
                    os.environ,
                    MOBSF_HOME_DIR=str(home),
                    MOBSF_CAPTURE_PROXY_PROVIDER=provider,
                    MOBSF_CAPTURE_PROXY_URL=f'http://127.0.0.1:{upstream.server_port}',
                    MOBSF_CAPTURE_PROXY_CA_FILE=str(ca_file) if trusted else '',
                    MOBSF_PROXY_IP='127.0.0.1',
                    MOBSF_PROXY_PORT=str(port),
                )
                with (home / 'capture.log').open('w') as log:
                    process = subprocess.Popen(
                        [
                            python,
                            '-m',
                            'mobsf.DynamicAnalyzer.tools.capture_runner',
                            '--port',
                            str(port),
                            '--project',
                            'owned.fixture',
                        ],
                        cwd=ROOT,
                        env=env,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                    )
                    try:
                        client = requests.Session()
                        client.trust_env = False
                        client.proxies = {
                            'http': f'http://127.0.0.1:{port}',
                            'https': f'http://127.0.0.1:{port}',
                        }
                        mitm_ca = home / 'mitmproxy/mitmproxy-ca-cert.pem'
                        for _ in range(60):
                            if process.poll() is not None:
                                raise RuntimeError(
                                    'Capture runner exited: '
                                    + (home / 'capture.log').read_text()[-3000:],
                                )
                            try:
                                response = client.get(
                                    'http://fixture.test/owned', timeout=2,
                                )
                                if response.status_code == 200 and mitm_ca.is_file():
                                    break
                            except requests.RequestException:
                                pass
                            time.sleep(0.5)
                        else:
                            raise RuntimeError('Capture runner did not forward HTTP')
                        assert response.content == b'owned-proxy-fixture!!'
                        response = client.get(
                            'https://fixture.test/owned',
                            verify=str(mitm_ca),
                            timeout=10,
                        )
                        if trusted:
                            assert response.status_code == 200, response.status_code
                            assert response.content == b'owned-proxy-fixture!!'
                        else:
                            assert response.status_code == 502, response.status_code
                        print(
                            provider,
                            'HTTP forwarding passed; HTTPS',
                            'trusted CA passed' if trusted else 'untrusted CA rejected',
                        )
                    finally:
                        process.terminate()
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
        finally:
            for server in (upstream, backend):
                server.shutdown()
                server.server_close()


def main():
    """Run this smoke test using the installed native dependency interpreter."""
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime-python', required=True)
    args = parser.parse_args()
    run_smoke(args.runtime_python)


if __name__ == '__main__':
    main()
