import json
import tempfile
import unittest
from pathlib import Path

from src.security_intel import (
    NormalizedAdvisory, canonical_key, deduplicate, load_simple_yaml, normalize
)

class TestSecurityIntel(unittest.TestCase):
    def test_registry_loads(self):
        p = Path(__file__).parents[1] / "references" / "source-registry.yaml"
        data = load_simple_yaml(p)
        self.assertGreaterEqual(len(data["sources"]), 9)
        for s in data["sources"]:
            self.assertTrue(s["description"])
            self.assertTrue(s["retrieval_hint"])

    def test_deduplicates_cross_source_identifiers(self):
        common = dict(
            advisory_id="GHSA-x", canonical_id="GHSA-x", package="next", ecosystem="npm",
            installed_version="16.0.0", affected_versions="<16.2.11",
            patched_versions="16.2.11", severity="high", cwe=["CWE-918"],
            cve="CVE-0000-0000", ghsa="GHSA-x", osv=None, published_at=None,
            updated_at=None, exploit_status=None, withdrawn=False, malware=False,
            summary="example", references=[], confidence="High"
        )
        a = NormalizedAdvisory(source="github-advisory-database", source_url="a", **common)
        b = NormalizedAdvisory(source="osv", source_url="b", **common)
        self.assertEqual(len(deduplicate([a,b])), 1)

    def test_osv_null_database_specific_is_safe(self):
        records = normalize('osv', {
            'id': 'OSV-TEST', 'aliases': [], 'affected': [{
                'package': {'name': 'zod'}, 'ranges': []
            }], 'database_specific': None, 'references': []
        }, 'zod', '4.1.3', 'npm')
        self.assertEqual(len(records), 1)

if __name__ == "__main__":
    unittest.main()
