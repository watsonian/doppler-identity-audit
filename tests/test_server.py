import json
import os
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"

import mock_api  # noqa: E402
import server  # noqa: E402


class WebApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mock = mock_api.start()
        cls.state = server.State(f"http://127.0.0.1:{cls.mock.server_port}", "https://dashboard.doppler.com")
        handler = server.make_handler(cls.state, {"localhost", "127.0.0.1"})
        cls.web = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=cls.web.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.web.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.web.shutdown()
        cls.mock.shutdown()

    def call(self, path, body=None, headers=None):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.base + path, data=data, headers=headers or {})
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, json.load(error)

    def test_flow_and_guards(self):
        write = {"X-Identity-Audit": "1"}
        self.assertEqual(self.call("/api/tokens", {"text": "dp.sa.acme"})[0], 403)  # missing CSRF header
        self.assertEqual(self.call("/api/state", headers={"Host": "attacker.example"})[0], 403)

        status, body = self.call("/api/tokens", {"text": "dp.sa.acme\na dp.sa.globex\ndp.sa.acme\ndp.sa.acmedupe\ndp.sa.revoked"}, write)
        self.assertEqual((status, body), (200, {"added": 4, "skipped": 1}))

        # Each token is checked against /v3/me as soon as it's added, before any audit.
        state = self.wait(lambda s: not s["busy"])
        self.assertIsNone(state["report_version"])
        self.assertEqual(self.call("/api/report")[0], 404)
        tokens = {t["preview"]: t for t in state["tokens"]}
        self.assertEqual((tokens["…acme"]["name"], tokens["…acme"]["status"], tokens["…acme"]["label"]), ("Acme Production", "ready", None))
        self.assertEqual((tokens["…obex"]["name"], tokens["…obex"]["label"]), ("Globex", "a"))
        self.assertEqual(tokens["…dupe"]["status"], "duplicate")
        self.assertEqual(tokens["…oked"]["status"], "invalid")
        self.assertIn("401", tokens["…oked"]["error"])

        self.assertEqual(self.call("/api/audit", {}, write)[0], 202)
        state = self.wait(lambda s: s["run"]["finished_at"])
        self.assertIsNotNone(state["report_version"])
        report = self.call("/api/report")[1]
        self.assertEqual(report["summary"]["identities"], 6)
        self.assertEqual([r["id"] for r in report["rules"]][:2], ["any-value", "leading-wildcard"])

        # Settings are checked, then applied to the current results without another audit.
        self.assertEqual(self.call("/api/settings", {"max_ttl_seconds": 5}, write)[0], 400)
        self.assertEqual(self.call("/api/settings", {"concurrency": "lots"}, write)[0], 400)
        self.assertEqual(self.call("/api/settings", {"stale_days": 1}, {})[0], 403)  # missing CSRF header
        version = state["report_version"]
        self.assertEqual(self.call("/api/settings", {"stale_days": 1, "max_ttl_seconds": 300}, write)[0], 200)
        after = self.call("/api/state")[1]
        self.assertEqual(after["report_version"], version + 1)
        self.assertEqual((after["settings"]["stale_days"], after["settings"]["max_ttl_seconds"], after["settings"]["concurrency"]), (1, 300, 4))
        rechecked = self.call("/api/report")[1]
        self.assertEqual(rechecked["options"], {"stale_days": 1, "max_ttl_seconds": 300})
        self.assertGreater(rechecked["summary"]["findings"]["low"], report["summary"]["findings"]["low"])
        self.assertIn("last 1 day.", next(r for r in rechecked["rules"] if r["id"] == "stale")["when"])
        statuses = {t["preview"]: t["status"] for t in state["tokens"]}
        self.assertEqual(statuses, {"…acme": "audited", "…obex": "audited", "…dupe": "failed", "…oked": "failed"})
        self.assertNotIn("dp.sa.", json.dumps(state))  # tokens never reach the browser

    def wait(self, done):
        for _ in range(100):
            state = self.call("/api/state")[1]
            if done(state):
                return state
            time.sleep(0.05)
        self.fail("timed out")


if __name__ == "__main__":
    unittest.main()
