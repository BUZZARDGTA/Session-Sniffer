"""Serve `website/` locally over HTTP/1.1 with Cloudflare Pages Pretty URLs and custom `404.html`."""

from __future__ import annotations

import argparse
import posixpath
import sys
from functools import partial
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Final, override
from urllib.parse import urlsplit, urlunsplit

if TYPE_CHECKING:
    from io import BytesIO
    from typing import BinaryIO

REPO_ROOT: Final = Path(__file__).resolve().parent.parent
WEBSITE_DIR: Final = REPO_ROOT / 'website'
DEFAULT_HOST: Final = '127.0.0.1'
DEFAULT_PORT: Final = 8080


class _CloudflarePagesHandler(SimpleHTTPRequestHandler):
    """HTTP/1.1 static request handler mirroring Cloudflare Pages Pretty URLs and `404.html`."""

    protocol_version = 'HTTP/1.1'

    def _send_redirect(self, target: str) -> None:
        """Send a 308 Permanent Redirect to *target* with zero-length body."""
        self.send_response(HTTPStatus.PERMANENT_REDIRECT)
        self.send_header('Location', target)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def _resolve_redirect(self) -> str | None:
        """Return a 308 redirect target when the request path should canonicalize to a Pretty URL."""
        parsed = urlsplit(self.path)
        raw_path = parsed.path or '/'
        normalized = posixpath.normpath(raw_path)
        if raw_path.endswith('/') and not normalized.endswith('/'):
            normalized += '/'
        if not normalized.startswith('/'):
            normalized = '/' + normalized

        # Redirect `/index.html` -> `/` and `/<page>.html` -> `/<page>`.
        if normalized == '/index.html':
            return urlunsplit(('', '', '/', parsed.query, ''))
        if normalized.endswith('.html') and normalized != '/404.html':
            candidate = WEBSITE_DIR / normalized.lstrip('/')
            if candidate.is_file():
                clean_path = normalized.removesuffix('.html')
                return urlunsplit(('', '', clean_path, parsed.query, ''))

        # Redirect trailing slash on extensionless HTML page (`/demo/` -> `/demo`).
        if normalized != '/' and normalized.endswith('/'):
            stem = normalized.strip('/')
            if (WEBSITE_DIR / f'{stem}.html').is_file():
                return urlunsplit(('', '', f'/{stem}', parsed.query, ''))

        return None

    @override
    def translate_path(self, path: str) -> str:
        """Resolve extensionless Pretty URLs (e.g. `/demo` -> `demo.html`)."""
        resolved = super().translate_path(path)
        candidate = Path(resolved)
        if not candidate.exists():
            html_candidate = Path(f'{resolved}.html')
            if html_candidate.is_file():
                return str(html_candidate)
        return resolved

    @override
    def send_head(self) -> BytesIO | BinaryIO | None:
        """Apply Pretty URL redirects before delegating static file serving."""
        redirect_target = self._resolve_redirect()
        if redirect_target is not None:
            self._send_redirect(redirect_target)
            return None
        return super().send_head()

    @override
    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        """Serve `website/404.html` with HTTP 404 status on missing paths."""
        if code == HTTPStatus.NOT_FOUND:
            not_found_path = WEBSITE_DIR / '404.html'
            if not_found_path.is_file():
                payload = not_found_path.read_bytes()
                self.send_response(HTTPStatus.NOT_FOUND)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                if self.command != 'HEAD':
                    self.wfile.write(payload)
                return
        super().send_error(code, message, explain)


def _parse_args() -> argparse.Namespace:
    """Parse CLI arguments for host and port binding."""
    parser = argparse.ArgumentParser(description='Preview website/ locally with Cloudflare Pages routing.')
    parser.add_argument('--host', default=DEFAULT_HOST, help=f'Bind address (default: {DEFAULT_HOST}).')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help=f'TCP port (default: {DEFAULT_PORT}).')
    return parser.parse_args()


def main() -> int:
    """Start the local HTTP/1.1 preview server until interrupted."""
    args = _parse_args()
    handler = partial(_CloudflarePagesHandler, directory=str(WEBSITE_DIR))
    with ThreadingHTTPServer((args.host, args.port), handler) as server:
        sys.stdout.write(f'Serving {WEBSITE_DIR} at http://{args.host}:{args.port}/ (HTTP/1.1, Pretty URLs + 404.html)\n')
        sys.stdout.flush()
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            return 0
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
