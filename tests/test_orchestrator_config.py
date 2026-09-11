import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import scripts.new_project as new_project_mod


class TestProjectConfig(unittest.TestCase):
    def test_browser_auth_block_is_built(self):
        cfg = new_project_mod.build_project_config(
            project_name="abc",
            url="http://10.53.56.20:8080/browser",
            auth={
                "auth_method": "browser",
                "username": "admin",
                "password": "xyz",
                "logged_in_indicator": "Dashboard",
            },
        )

        self.assertEqual(cfg["project_name"], "abc")
        self.assertEqual(cfg["target"]["url"], "http://10.53.56.20:8080/browser")
        self.assertEqual(cfg["auth"]["method"], "browser")
        self.assertEqual(cfg["auth"]["username"], "admin")
        self.assertEqual(cfg["auth"]["password"], "xyz")
        self.assertEqual(cfg["auth"]["logged_in_indicator"], "Dashboard")

    def test_no_credentials_returns_unauthenticated(self):
        cfg = new_project_mod.build_project_config(
            project_name="pqr",
            url="http://10.53.15.9:5080/",
            auth={
                "auth_method": "none",
                "username": "",
                "password": "",
            },
        )

        self.assertIsNone(cfg["auth"])


if __name__ == "__main__":
    unittest.main()
