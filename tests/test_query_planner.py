import unittest
from src.query_planner import plan_queries
class TestPlanner(unittest.TestCase):
 def test_dynamic(self):
  p={'framework':{'name':'Next.js','version':'16.0.10'},'runtime':{'version':'22'},'dependencies':[{'name':'next','version':'16.0.10','security_sensitive':True},{'name':'swiper','version':'12.0.3','security_sensitive':True},{'name':'react','version':'19.2.0','security_sensitive':True}],'entry_points':[{'x':'Server Action RSC middleware fetch Edge authorization'}]}
  q=[x.query for x in plan_queries(p,2026)]
  self.assertTrue(any('Server Actions' in x for x in q)); self.assertTrue(any('swiper 12.0.3 prototype pollution' in x for x in q)); self.assertTrue(any('React Server Components' in x for x in q))
if __name__=='__main__':unittest.main()
