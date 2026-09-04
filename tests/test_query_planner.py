import unittest
import json
from pathlib import Path
from src.query_planner import plan_queries

class TestQueryPlanner(unittest.TestCase):
    def setUp(self):
        fixture = Path(__file__).parents[1] / 'fixtures' / 'query-planner-nextjs.json'
        self.project = json.loads(fixture.read_text(encoding='utf-8'))

    def test_dynamic_queries_are_not_three_hardcoded_searches(self):
        tasks=plan_queries(self.project,year=2026)
        queries=[t.query for t in tasks]
        self.assertGreater(len(tasks), 3)
        self.assertTrue(any('Next.js security advisories 16.0.10' in q for q in queries))
        self.assertTrue(any('Server Actions' in q for q in queries))
        self.assertTrue(any('swiper 12.0.3 prototype pollution' in q for q in queries))
        self.assertTrue(any('React Server Components' in q for q in queries))

    def test_validation_library_uses_context7_without_opening_web_results(self):
        self.project['dependencies'].append({'name': 'zod', 'version': '4.1.3'})
        task = next(x for x in plan_queries(self.project) if x.family == 'library_documentation')
        self.assertEqual(task.source, 'context7-docs')
        self.assertFalse(task.requires_open)

    def test_trusted_domain_routing_and_open_requirement(self):
        tasks=plan_queries(self.project,year=2026)
        t=next(x for x in tasks if x.family=='middleware')
        self.assertEqual(t.source,'exa_web')
        self.assertTrue(t.requires_open)
        self.assertIn('nextjs.org', t.preferred_domains)

    def test_irrelevant_dependency_is_not_searched(self):
        tasks=plan_queries(self.project,year=2026)
        self.assertFalse(any('left-pad' in x.query for x in tasks))

if __name__=='__main__': unittest.main()
