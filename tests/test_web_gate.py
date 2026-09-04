import unittest
from unittest.mock import patch
from scripts.open_url import host_allowed, resolve_and_validate

class TestWebGate(unittest.TestCase):
    def test_allowlist(self):
        allow={'github.com'}
        self.assertTrue(host_allowed('github.com', allow))
        self.assertTrue(host_allowed('api.github.com', allow))
        self.assertFalse(host_allowed('evilgithub.com', allow))

    def test_rejects_non_https_and_private_resolution(self):
        with self.assertRaises(ValueError):
            resolve_and_validate('http://github.com/advisories', {'github.com'})
        with patch('scripts.open_url.socket.getaddrinfo', return_value=[(None, None, None, None, ('127.0.0.1', 443))]):
            with self.assertRaises(ValueError):
                resolve_and_validate('https://github.com/advisories', {'github.com'})

if __name__=='__main__': unittest.main()
