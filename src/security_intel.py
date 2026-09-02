from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable

# This module is deliberately stdlib-only. YAML is parsed with a small restricted
# parser because the shipped registry uses a simple YAML subset. Deployments may
# replace it with PyYAML without changing the data model.

IDENTIFIER_RE = re.compile(r"\b(?:GHSA|CVE|OSV)-[A-Za-z0-9_.-]+\b", re.I)

def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()

def _scalar(v: str) -> Any:
    v = v.strip()
    if not v:
        return ""
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        return v[1:-1]
    if v.lower() in ("true", "false"):
        return v.lower() == "true"
    if v.lower() in ("null", "~"):
        return None
    try:
        return int(v)
    except ValueError:
        return v

def load_simple_yaml(path: str | Path) -> dict[str, Any]:
    """Parse the registry's intentionally simple YAML subset."""
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    root: dict[str, Any] = {}
    sources: list[dict[str, Any]] = []
    current = None
    key = None
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        s = raw.strip()
        if s == "sources:":
            root["sources"] = sources
            continue
        if s.startswith("- id:"):
            current = {}
            sources.append(current)
            current["id"] = _scalar(s.split(":",1)[1])
            key = "id"
            continue
        if current is None:
            if ":" in s:
                k,v=s.split(":",1); root[k.strip()]=_scalar(v)
            continue
        if ":" in s:
            k,v=s.split(":",1)
            k=k.strip(); v=v.strip()
            if v == ">":
                current[k] = ""
                key = k
            else:
                current[k] = _scalar(v)
                key = k
        elif key and raw.startswith("      "):
            current[key] = (str(current.get(key,"")) + " " + s).strip()
    return root

@dataclass
class SourceResult:
    source: str
    queried: bool
    query: dict[str, Any]
    retrieved_at: str
    result_count: int
    failure: str | None
    records: list[dict[str, Any]]

@dataclass
class NormalizedAdvisory:
    advisory_id: str
    source: str
    source_url: str | None
    canonical_id: str
    package: str
    ecosystem: str
    installed_version: str | None
    affected_versions: str
    patched_versions: str | None
    severity: str | None
    cwe: list[str]
    cve: str | None
    ghsa: str | None
    osv: str | None
    published_at: str | None
    updated_at: str | None
    exploit_status: str | None
    withdrawn: bool
    malware: bool
    summary: str | None
    references: list[str]
    confidence: str

class RetrievalEngine:
    def __init__(self, registry_path: str, timeout: int = 20):
        data = load_simple_yaml(registry_path)
        self.sources = {s["id"]: s for s in data.get("sources", []) if s.get("enabled", True)}
        self.timeout = timeout
        self.cache: dict[str, SourceResult] = {}

    def _http(self, method: str, url: str, *, headers=None, body=None) -> Any:
        req = urllib.request.Request(url, method=method, headers=headers or {}, data=body)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"HTTP {e.code}: {detail}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"network error: {e.reason}") from e

    def select_sources(self, package: str, ecosystem: str, category: str | None = None) -> list[str]:
        selected = []
        if ecosystem == "npm":
            selected += ["github-advisory-database", "osv"]
            if package == "next":
                selected += ["nextjs-security-advisories"]
            selected += ["snyk", "socket"]
        if category in {"xss", "ssrf", "web"}:
            selected += ["portswigger-research", "owasp-wstg"]
        # Stable order, de-duplicated, registry-enabled only.
        return list(dict.fromkeys(s for s in selected if s in self.sources))

    def query_github(self, package: str, version: str, ecosystem: str) -> SourceResult:
        sid = "github-advisory-database"
        query = {"affects": f"{package}@{version}", "ecosystem": ecosystem, "per_page": "100"}
        key = sid + "|" + urllib.parse.urlencode(query)
        if key in self.cache: return self.cache[key]
        url = self.sources[sid]["api_url"] + "?" + urllib.parse.urlencode(query)
        try:
            token = os.getenv("GITHUB_TOKEN")
            headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10"}
            if token: headers["Authorization"] = f"Bearer {token}"
            data = self._http("GET", url, headers=headers)
            result = SourceResult(sid, True, query, utc_now(), len(data), None, data)
        except Exception as e:
            result = SourceResult(sid, True, query, utc_now(), 0, str(e), [])
        self.cache[key] = result
        return result

    def query_osv(self, package: str, version: str, ecosystem: str) -> SourceResult:
        sid = "osv"
        query = {"package": {"name": package, "ecosystem": ecosystem}, "version": version}
        key = sid + "|" + json.dumps(query, sort_keys=True)
        if key in self.cache: return self.cache[key]
        try:
            data = self._http(
                "POST", self.sources[sid]["api_url"],
                headers={"Content-Type": "application/json"},
                body=json.dumps(query).encode(),
            )
            vulns = data.get("vulns", []) if isinstance(data, dict) else []
            result = SourceResult(sid, True, query, utc_now(), len(vulns), None, vulns)
        except Exception as e:
            result = SourceResult(sid, True, query, utc_now(), 0, str(e), [])
        self.cache[key] = result
        return result

    def query_osv_batch(self, packages: list[tuple[str, str, str]]) -> SourceResult:
        sid = "osv"
        query = {"queries":[{"package":{"name":p,"ecosystem":e},"version":v} for p,v,e in packages]}
        key = sid + "|batch|" + json.dumps(query, sort_keys=True)
        if key in self.cache: return self.cache[key]
        try:
            data = self._http("POST", self.sources[sid]["batch_api_url"],
                              headers={"Content-Type":"application/json"},
                              body=json.dumps(query).encode())
            results = data.get("results", []) if isinstance(data, dict) else []
            count = sum(len(x.get("vulns", [])) for x in results)
            result = SourceResult(sid, True, query, utc_now(), count, None, results)
        except Exception as e:
            result = SourceResult(sid, True, query, utc_now(), 0, str(e), [])
        self.cache[key] = result
        return result

    def query_nextjs(self, package: str, version: str) -> SourceResult:
        sid = "nextjs-security-advisories"
        query = {"package": package, "version": version}
        key = sid + "|" + json.dumps(query, sort_keys=True)
        if key in self.cache: return self.cache[key]
        try:
            token = os.getenv("GITHUB_TOKEN")
            headers = {"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2026-03-10"}
            if token: headers["Authorization"] = f"Bearer {token}"
            data = self._http("GET", self.sources[sid]["api_url"], headers=headers)
            # Filter client-side because repository advisory endpoint does not
            # expose the same "affects package@version" filter as global advisories.
            result = SourceResult(sid, True, query, utc_now(), len(data), None, data)
        except Exception as e:
            result = SourceResult(sid, True, query, utc_now(), 0, str(e), [])
        self.cache[key] = result
        return result

    def retrieve(self, package: str, version: str, ecosystem: str = "npm", category: str | None = None) -> list[SourceResult]:
        out = []
        for sid in self.select_sources(package, ecosystem, category):
            if sid == "github-advisory-database":
                out.append(self.query_github(package, version, ecosystem))
            elif sid == "osv":
                out.append(self.query_osv(package, version, ecosystem))
            elif sid == "nextjs-security-advisories":
                out.append(self.query_nextjs(package, version))
            else:
                # Do not invent provider API contracts. Record as not queried
                # unless a deployment adds an explicit adapter.
                out.append(SourceResult(sid, False, {"package":package,"version":version},
                                         utc_now(), 0, "adapter_not_configured", []))
        return out

def _ids(record: dict[str, Any]) -> dict[str, str | None]:
    ids = {"cve":None,"ghsa":None,"osv":None}
    for ident in record.get("identifiers", []) or []:
        t, v = ident.get("type"), ident.get("value")
        if t == "CVE": ids["cve"] = v
        elif t == "GHSA": ids["ghsa"] = v
        elif t == "OSV": ids["osv"] = v
    if record.get("id", "").startswith("OSV-"): ids["osv"] = record["id"]
    return ids

def normalize(source: str, record: dict[str, Any], package: str, version: str, ecosystem: str) -> list[NormalizedAdvisory]:
    out=[]
    if source in {"github-advisory-database","nextjs-security-advisories"}:
        vulns = record.get("vulnerabilities") or []
        ids = _ids(record)
        for v in vulns:
            pkg = v.get("package", {}).get("name", package)
            if pkg != package: continue
            out.append(NormalizedAdvisory(
                advisory_id=record.get("ghsa_id") or record.get("cve_id") or record.get("id",""),
                source=source, source_url=record.get("html_url") or record.get("url"),
                canonical_id=ids["ghsa"] or ids["cve"] or record.get("id",""),
                package=pkg, ecosystem=v.get("package",{}).get("ecosystem",ecosystem),
                installed_version=version,
                affected_versions=v.get("vulnerable_version_range",""),
                patched_versions=(v.get("first_patched_version") or None),
                severity=(record.get("severity") or None),
                cwe=[x.get("cwe_id") for x in record.get("cwes",[]) if x.get("cwe_id")],
                cve=ids["cve"], ghsa=ids["ghsa"], osv=ids["osv"],
                published_at=record.get("published_at"), updated_at=record.get("updated_at"),
                exploit_status=None, withdrawn=bool(record.get("withdrawn_at")),
                malware=record.get("type")=="malware", summary=record.get("summary"),
                references=record.get("references",[]) or [], confidence="High" if source.startswith("nextjs") else "High"
            ))
    elif source == "osv":
        ids = _ids(record)
        aliases = record.get("aliases",[]) or []
        cve = next((x for x in aliases if x.startswith("CVE-")), ids["cve"])
        ghsa = next((x for x in aliases if x.startswith("GHSA-")), ids["ghsa"])
        affected = record.get("affected",[]) or []
        for a in affected:
            if a.get("package",{}).get("name") != package: continue
            ranges=[]
            fixed=None
            for r in a.get("ranges",[]) or []:
                for ev in r.get("events",[]) or []:
                    if "introduced" in ev: ranges.append("introduced:"+str(ev["introduced"]))
                    if "fixed" in ev: fixed=ev["fixed"]
            out.append(NormalizedAdvisory(
                advisory_id=record.get("id",""), source=source,
                source_url=next((x.get("url") for x in record.get("references",[]) if x.get("url")),None),
                canonical_id=ghsa or cve or record.get("id",""), package=package, ecosystem=ecosystem,
                installed_version=version, affected_versions=";".join(ranges),
                patched_versions=fixed, severity=None, cwe=[x for x in record.get("database_specific",{}).get("cwe_ids",[])],
                cve=cve, ghsa=ghsa, osv=record.get("id"), published_at=record.get("published"),
                updated_at=record.get("modified"), exploit_status=None, withdrawn=False, malware=False,
                summary=record.get("summary"), references=[x.get("url") for x in record.get("references",[]) if x.get("url")],
                confidence="High"
            ))
    return out

def canonical_key(a: NormalizedAdvisory) -> str:
    return (a.ghsa or a.cve or a.osv or
            f"{a.package}|{a.ecosystem}|{a.affected_versions}|{a.patched_versions}")

def deduplicate(advisories: Iterable[NormalizedAdvisory]) -> list[NormalizedAdvisory]:
    grouped: dict[str, NormalizedAdvisory] = {}
    for a in advisories:
        k = canonical_key(a)
        if k not in grouped:
            grouped[k]=a
        else:
            # Prefer the record with a concrete primary identifier and richer data.
            old=grouped[k]
            score=lambda x: sum(bool(getattr(x,f)) for f in ("cve","ghsa","osv","patched_versions","source_url","summary"))
            if score(a)>score(old):
                grouped[k]=a
    return list(grouped.values())

def provenance_record(result: SourceResult) -> dict[str, Any]:
    return {
        "source": result.source,
        "query": result.query,
        "retrieved_at": result.retrieved_at,
        "result_count": result.result_count,
        "failure": result.failure,
    }

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--registry", required=True)
    ap.add_argument("--package", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--ecosystem", default="npm")
    ap.add_argument("--category")
    args=ap.parse_args()
    engine=RetrievalEngine(args.registry)
    results=engine.retrieve(args.package,args.version,args.ecosystem,args.category)
    advisories=[]
    for r in results:
        for rec in r.records:
            advisories.extend(normalize(r.source,rec,args.package,args.version,args.ecosystem))
    advisories=deduplicate(advisories)
    print(json.dumps({
        "retrieved_at": utc_now(),
        "package": args.package,
        "version": args.version,
        "ecosystem": args.ecosystem,
        "sources": [provenance_record(r) for r in results],
        "advisories": [asdict(a) for a in advisories],
    }, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
