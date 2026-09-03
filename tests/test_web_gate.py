import unittest
from scripts.open_url import host_allowed

class TestWebGate(unittest.TestCase):
    def test_allowlist(self):
        allow={'github.com'}
        self.assertTrue(host_allowed('github.com', allow))
        self.assertTrue(host_allowed('api.github.com', allow))
        self.assertFalse(host_allowed('evilgithub.com', allow))

if __name__=='__main__': unittest.main()
