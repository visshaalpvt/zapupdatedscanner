import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from scripts.orchestrate import ServerPool


class TestServerPool(unittest.TestCase):
    def test_acquire_uses_least_busy_server(self):
        pool = ServerPool([
            {"name": "zap1", "api_url": "http://10.93.15.18:8080", "api_key": "k", "max_concurrent": 2},
            {"name": "zap2", "api_url": "http://10.53.15.9:8080", "api_key": "k", "max_concurrent": 2},
        ])

        s1 = pool.acquire()
        s2 = pool.acquire()

        self.assertEqual(s1.name, "zap1")
        self.assertEqual(s2.name, "zap2")

        pool.release(s1)
        s3 = pool.acquire()
        self.assertEqual(s3.name, "zap1")

    def test_server_capacity_is_respected(self):
        pool = ServerPool([
            {"name": "zap1", "api_url": "http://10.93.15.18:8080", "api_key": "k", "max_concurrent": 1},
            {"name": "zap2", "api_url": "http://10.53.15.9:8080", "api_key": "k", "max_concurrent": 1},
        ])

        first = pool.acquire()
        second = pool.acquire()
        self.assertNotEqual(first.name, second.name)

        pool.release(first)
    def test_invalid_preferred_server_raises_value_error(self):
        pool = ServerPool([
            {"name": "zap1", "api_url": "http://10.93.15.18:8080", "api_key": "k", "max_concurrent": 1},
        ])

        with self.assertRaises(ValueError) as ctx:
            pool.acquire(preferred_server="zap_nonexistent")
        self.assertIn("Requested server 'zap_nonexistent' not found", str(ctx.exception))

    def test_total_capacity_calculation(self):
        pool = ServerPool([
            {"name": "zap1", "api_url": "http://1.1.1.1:8080", "max_concurrent": 3},
            {"name": "zap2", "api_url": "http://2.2.2.2:8080", "max_concurrent": 2},
        ])
        self.assertEqual(pool.total_capacity, 5)


if __name__ == "__main__":
    unittest.main()
