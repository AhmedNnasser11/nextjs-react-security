#!/usr/bin/env python3
"""Run an approved external search provider and open authoritative results.

This is intentionally provider-neutral. Set SEARCH_PROVIDER_COMMAND to a command
that implements the documented stdin/stdout JSON contract, or set EXA_SEARCH_URL /
EXA_API_KEY when the deployment has verified the current provider API contract.
The Skill never treats snippets as final evidence.
"""
from __future__ import annotations
import argparse, json, os, shlex, subprocess, sys, urllib.request
from datetime import datetime, timezone
from pathlib import Path


def now():
    return datetime.now(timezone.utc).isoformat()


def run_provider(payload: dict) -> dict:
    cmd = os.getenv('SEARCH_PROVIDER_COMMAND')
    if cmd:
        proc = subprocess.run(shlex.split(cmd), input=json.dumps(payload), text=True,
                              shell=False, capture_output=True, timeout=60)
        if proc.returncode != 0:
            return {'provider': 'external-command', 'query': payload['query'],
                    'retrieved_at': now(), 'results': [], 'failure': proc.stderr[:1000]}
        return json.loads(proc.stdout)

    # Deployment-controlled endpoint. The endpoint/request schema MUST be verified
    # against the provider's current official docs before use.
    url = os.getenv('EXA_SEARCH_URL')
    key = os.getenv('EXA_API_KEY')
    if not url or not key:
        return {'provider': 'unconfigured', 'query': payload['query'],
                'retrieved_at': now(), 'results': [],
                'failure': 'no_verified_search_provider_configured'}
    body = json.dumps({
        'query': payload['query'],
        'numResults': payload.get('num_results', 5),
        'includeDomains': payload.get('domains') or [],
    }).encode()
    req = urllib.request.Request(url, data=body, method='POST', headers={
        'Content-Type': 'application/json', 'x-api-key': key,
        'Accept': 'application/json',
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode())
        return {'provider': 'exa', 'query': payload['query'], 'retrieved_at': now(),
                'results': data.get('results', []), 'failure': None}
    except Exception as e:
        return {'provider': 'exa', 'query': payload['query'], 'retrieved_at': now(),
                'results': [], 'failure': str(e)}


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('query')
    ap.add_argument('--domains', nargs='*', default=[])
    ap.add_argument('--num-results', type=int, default=5)
    ap.add_argument('--output', default='-')
    args=ap.parse_args()
    result=run_provider({'query':args.query,'domains':args.domains,'num_results':args.num_results})
    text=json.dumps(result, ensure_ascii=False, indent=2)
    if args.output == '-': print(text)
    else: Path(args.output).write_text(text,encoding='utf-8')

if __name__ == '__main__':
    main()
