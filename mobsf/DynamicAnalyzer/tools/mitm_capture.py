"""mitmproxy capture addon for MobSF Dynamic Analysis."""
from pathlib import Path

from mitmproxy import (
    ctx,
    http,
)


class HTTPDump:
    """Write human-readable HTTP traffic alongside mitmproxy's .flow stream."""

    def __init__(self):
        self.http_f = None

    def running(self):
        stream_file = getattr(ctx.options, 'save_stream_file', None)
        if stream_file:
            dump_path = Path(f'{stream_file}.txt')
            dump_path.parent.mkdir(parents=True, exist_ok=True)
            self.http_f = dump_path.open('w', encoding='utf-8', errors='replace')

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
