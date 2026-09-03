from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

@dataclass(frozen=True)
class QueryTask:
    query_id: str
    family: str
    query: str
    generated_from: str
    rationale: str
    package: str | None = None
    version: str | None = None
    ecosystem: str | None = None
    freshness_required: bool = True
    priority: int = 0
    source: str = 'exa_web'
    requires_open: bool = True
    preferred_domains: tuple[str, ...] = ()


def plan_queries(project: dict, *, year: int | None = None) -> list[QueryTask]:
    year = year or datetime.now(timezone.utc).year
    out: list[QueryTask] = []
    seen = set()
    deps = project.get('dependencies', [])
    fw = project.get('framework', {}) or {}
    fn = fw.get('name', '')
    fv = fw.get('version', '')
    attack = ' '.join(str(v).lower() for e in project.get('entry_points', []) for v in e.values())

    def add(family, query, generated_from, rationale, package=None, version=None,
            priority=50, source='exa_web', domains=()):
        key = (family, query, source)
        if key in seen:
            return
        seen.add(key)
        out.append(QueryTask(
            query_id=f'q-{len(out)+1:04d}-{family}', family=family, query=query,
            generated_from=generated_from, rationale=rationale, package=package,
            version=version, ecosystem='npm' if package else None,
            freshness_required=True, priority=priority, source=source,
            requires_open=(source == 'exa_web'), preferred_domains=tuple(domains)
        ))

    if fn.lower() == 'next.js':
        add('framework', f'Next.js security advisories {fv} CVE GHSA {year}',
            'framework.version', 'Exact framework security discovery', 'next', fv, 100, 'exa_web',
            ('nextjs.org','vercel.com','github.com'))
        add('framework', f'Next.js {fv} security vulnerability affected patched {year}',
            'framework.version', 'Version applicability and remediation discovery', 'next', fv, 98, 'exa_web',
            ('nextjs.org','vercel.com','github.com'))
        if 'server action' in attack:
            add('server-actions', f'Next.js Server Actions security CVE GHSA {year}',
                'attack_surface.server_actions', 'Server Actions boundary', 'next', fv, 95, 'exa_web',
                ('nextjs.org','vercel.com','github.com','owasp.org'))
        if 'middleware' in attack or 'proxy' in attack:
            add('middleware', f'Next.js middleware proxy security bypass CVE GHSA {year}',
                'attack_surface.middleware_proxy', 'Middleware/proxy boundary', 'next', fv, 94, 'exa_web',
                ('nextjs.org','vercel.com','github.com'))
        if 'rsc' in attack or 'server component' in attack:
            add('rsc', f'Next.js React Server Components RSC security CVE GHSA {year}',
                'attack_surface.rsc', 'RSC security behavior', 'next', fv, 96, 'exa_web',
                ('nextjs.org','react.dev','github.com'))
        if 'fetch' in attack or 'ssrf' in attack:
            add('ssrf', f'Next.js SSRF CVE GHSA {year}', 'attack_surface.ssrf',
                'Server request sink', 'next', fv, 93, 'exa_web',
                ('nextjs.org','vercel.com','portswigger.net','owasp.org'))
        if 'cache' in attack:
            add('cache', f'Next.js cache poisoning security CVE GHSA {year}',
                'attack_surface.caching', 'Shared cache boundary', 'next', fv, 90, 'exa_web',
                ('nextjs.org','vercel.com','portswigger.net','owasp.org'))

    important = {'next','react','react-dom','react-server-dom-webpack','react-server-dom-turbopack',
                 'react-server-dom-parcel','swiper','sharp','jsonwebtoken','jose'}
    for d in deps:
        n, v = d.get('name'), d.get('version')
        if not n or not v or not (n in important or d.get('security_sensitive') or d.get('runtime_relevant')):
            continue
        add('exact-vulnerability', f'{n} {v} CVE GHSA vulnerability {year}',
            f'dependency:{n}', 'Exact dependency/version discovery', n, v, 92)
        add('exact-vulnerability', f'{n} {v} affected patched security advisory',
            f'dependency:{n}', 'Affected/fixed corroboration', n, v, 88)
        add('supply-chain', f'{n} {v} malicious compromised typosquatting supply chain',
            f'dependency:{n}', 'Supply-chain intelligence', n, v, 70, 'exa_web', ('socket.dev','github.com','npmjs.com','openssf.org'))
        if n == 'swiper':
            add('prototype-pollution', f'swiper {v} prototype pollution CVE GHSA',
                'dependency:swiper', 'Package-specific prototype-pollution research', n, v, 91,
                'exa_web', ('github.com','cve.org','nvd.nist.gov'))

    if any(d.get('name','').startswith('react') for d in deps):
        add('react-rsc', f'React Server Components RSC security advisories {year}',
            'dependency:react-rsc', 'Upstream RSC discovery', priority=97, source='exa_web',
            domains=('react.dev','github.com'))
        add('react-rsc', f'React RSC CVE GHSA Server Components {year}',
            'dependency:react-rsc', 'Alias and advisory discovery', priority=95, source='exa_web',
            domains=('react.dev','github.com','cve.org'))

    rv = (project.get('runtime', {}) or {}).get('version')
    if rv:
        add('runtime', f'Node.js {rv} security vulnerabilities CVE {year}',
            'runtime.version', 'Runtime discovery', priority=80, source='exa_web', domains=('nodejs.org','github.com','cve.org'))
    if 'edge' in attack:
        add('runtime', f'Next.js Edge runtime Node.js API compatibility security {year}',
            'attack_surface.edge_runtime', 'Validate runtime constraints; compatibility is not automatically a vulnerability', priority=65,
            source='exa_web', domains=('nextjs.org','vercel.com'))

    techniques = [('xss','XSS',85),('ssrf','SSRF',90),('prototype','prototype pollution',82),
                  ('command','command injection',88),('path','path traversal',86),('csrf','CSRF',80),
                  ('authorization','authorization IDOR BOLA',92)]
    for token, label, pri in techniques:
        if token in attack:
            add('technique', f'{label} Next.js React web security research {year}',
                f'attack_surface:{token}', 'Technique-specific corroboration', priority=pri,
                source='exa_web', domains=('owasp.org','portswigger.net','nextjs.org'))
    return sorted(out, key=lambda x: (-x.priority, x.query_id))

if __name__ == '__main__':
    import json, sys
    project = json.load(open(sys.argv[1], encoding='utf-8'))
    print(json.dumps([asdict(x) for x in plan_queries(project)], indent=2))
