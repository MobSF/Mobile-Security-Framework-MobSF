"""mitmproxy capture and upstream replay addons for MobSF Dynamic Analysis."""
from pathlib import Path

from mitmproxy import (
    ctx,
    http,
)
from mitmproxy.connection import Server
from mitmproxy.net.server_spec import ServerSpec


class HTTPDump:
    """Write human-readable HTTP traffic alongside mitmproxy's .flow stream."""

    def __init__(self):
        self.http_f = None
        self.replay_host = ''
        self.replay_port = 0
        self.replay_scheme = 'http'
        self.skip_port = 1337

    def load(self, loader):
        loader.add_option(
            name='mobsf_replay_host',
            typespec=str,
            default='',
            help='Upstream fuzzer proxy host for client replay',
        )
        loader.add_option(
            name='mobsf_replay_port',
            typespec=int,
            default=0,
            help='Upstream fuzzer proxy port for client replay',
        )
        loader.add_option(
            name='mobsf_replay_scheme',
            typespec=str,
            default='http',
            help='Upstream fuzzer proxy scheme for client replay',
        )
        loader.add_option(
            name='mobsf_skip_port',
            typespec=int,
            default=1337,
            help='Local MobSF proxy port to skip during replay',
        )

    def running(self):
        self.replay_host = getattr(ctx.options, 'mobsf_replay_host', '') or ''
        self.replay_port = int(getattr(ctx.options, 'mobsf_replay_port', 0) or 0)
        self.replay_scheme = (
            getattr(ctx.options, 'mobsf_replay_scheme', 'http') or 'http'
        )
        self.skip_port = int(getattr(ctx.options, 'mobsf_skip_port', 1337) or 1337)
        stream_file = getattr(ctx.options, 'save_stream_file', None)
        if stream_file and not self.replay_host:
            dump_path = Path(f'{stream_file}.txt')
            dump_path.parent.mkdir(parents=True, exist_ok=True)
            self.http_f = dump_path.open('w', encoding='utf-8', errors='replace')

    def request(self, flow: http.HTTPFlow) -> None:
        """Route replayed client flows through the configured fuzzer proxy."""
        if not self.replay_host or not self.replay_port:
            return
        if (flow.request.host in ('127.0.0.1', 'localhost', '::1')
                and flow.request.port == self.skip_port):
            flow.kill()
            return
        address = (self.replay_host, self.replay_port)
        if flow.server_conn.timestamp_start:
            flow.server_conn = Server(address=flow.server_conn.address)
        flow.server_conn.via = ServerSpec((self.replay_scheme, address))

    def save_http(self, httpflow: http.HTTPFlow) -> None:
        """Dump HTTP Request and Response."""
        if not self.http_f:
            return
        req = httpflow.request
        res = httpflow.response
        self.http_f.write('========\nREQUEST\n========\n')
        self.http_f.write(f'{req.method} {req.url} {req.http_version}\n')
        for key, val in req.headers.items():
            self.http_f.write(f'{key}: {val}\n')
        if req.content:
            self.http_f.write(f'\n\n{req.content}\n')
        if res:
            self.http_f.write('=========\nRESPONSE\n=========\n')
            self.http_f.write(
                f'{res.http_version} {res.status_code} {res.reason}\n')
            for key, val in res.headers.items():
                self.http_f.write(f'{key}: {val}\n')
            if res.content:
                self.http_f.write(f'\n\n{res.content}\n')
        self.http_f.flush()

    def done(self):
        if self.http_f:
            self.http_f.close()
            self.http_f = None

    def response(self, flow: http.HTTPFlow) -> None:
        self.save_http(flow)


addons = [HTTPDump()]
