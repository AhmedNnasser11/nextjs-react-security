#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, os, re, socket, ssl, urllib.parse, urllib.request
from datetime import datetime, timezone

DEFAULT_ALLOWED = {
    'api.github.com', 'github.com', 'raw.githubusercontent.com',
    'api.osv.dev', 'osv.dev',
    'nextjs.org', 'vercel.com',
    'react.dev', 'nodejs.org', 'npmjs.com', 'www.npmjs.com',
    'owasp.org', 'portswigger.net', 'cve.org', 'nvd.nist.gov',
    'socket.dev', 'api.socket.dev', 'api.exa.ai'
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def host_allowed(host: str, allowed: set[str]) -> bool:
    host = host.lower().rstrip('.')
    return host in allowed or any(host.endswith('.' + d) for d in allowed)


def resolve_and_validate(url: str, allowed: set[str]) -> tuple[urllib.parse.ParseResult, list[str]]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {'https'}:
        raise ValueError('Only https:// URLs are allowed')
    if not parsed.hostname or not host_allowed(parsed.hostname, allowed):
        raise ValueError(f'Host not in allowlist: {parsed.hostname}')
    try:
        infos = socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
    except OSError as e:
        raise ValueError(f'DNS resolution failed: {e}')
    ips = sorted({i[4][0] for i in infos})
    # Fail closed for literal/private/loopback/link-local targets.
    import ipaddress
    for ip in ips:
        obj = ipaddress.ip_address(ip)
        if obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_reserved:
            raise ValueError(f'Resolves to restricted address: {ip}')
    return parsed, ips


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed: set[str]):
        super().__init__()
        self.allowed = allowed

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed, ips = resolve_and_validate(newurl, self.allowed)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def main() -> None:
    ap = argparse.ArgumentParser(description='Open a trusted HTTPS URL with provenance-safe logging.')
    ap.add_argument('url')
    ap.add_argument('--max-bytes', type=int, default=2_000_000)
    ap.add_argument('--allow', action='append', default=[])
    args = ap.parse_args()
    allowed = DEFAULT_ALLOWED | set(args.allow)
    parsed, ips = resolve_and_validate(args.url, allowed)
    req = urllib.request.Request(args.url, headers={
        'User-Agent': 'nextjs-react-security/1.0 (security-research)',
        'Accept': 'text/html,application/json,text/plain;q=0.9,*/*;q=0.1',
    })
    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(SafeRedirectHandler(allowed))
    with opener.open(req, timeout=20, context=ctx) as r:
        body = r.read(args.max_bytes + 1)
        truncated = len(body) > args.max_bytes
        body = body[:args.max_bytes]
        result = {
            'url': args.url,
            'final_url': r.geturl(),
            'status': getattr(r, 'status', 200),
            'content_type': r.headers.get('Content-Type'),
            'retrieved_at': now(),
            'resolved_ips': ips,
            'truncated': truncated,
            'bytes': len(body),
            'content': body.decode('utf-8', errors='replace'),
        }
    print(json.dumps(result, ensure_ascii=False))

if __name__ == '__main__':
    main()
