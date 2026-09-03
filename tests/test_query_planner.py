import unittest
from src.query_planner import plan_queries

class TestQueryPlanner(unittest.TestCase):
    def setUp(self):
        self.project = {
            'framework': {'name':'Next.js','version':'16.0.10'},
            'runtime': {'name':'Node.js','version':'22'},
            'dependencies': [
                {'name':'next','version':'16.0.10','security_sensitive':True},
                {'name':'swiper','version':'12.0.3','security_sensitive':True},
                {'name':'react','version':'19.2.0','security_sensitive':True},
                {'name':'left-pad','version':'1.3.0'},
            ],
            'entry_points':[{'kind':'Server Action','notes':'RSC; middleware; authorization; fetch; Edge runtime'}]
        }

    def test_dynamic_queries_are_not_three_hardcoded_searches(self):
        tasks=plan_queries(self.project,year=2026)
        queries=[t.query for t in tasks]
        self.assertGreater(len(tasks), 3)
        self.assertTrue(any('Next.js security advisories 16.0.10' in q for q in queries))
        self.assertTrue(any('Server Actions' in q for q in queries))
        self.assertTrue(any('swiper 12.0.3 prototype pollution' in q for q in queries))
        self.assertTrue(any('React Server Components' in q for q in queries))

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
