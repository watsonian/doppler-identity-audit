import io
import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"

import identity_audit as audit  # noqa: E402
import mock_api  # noqa: E402


class ParseTokens(unittest.TestCase):
    def test_accepted_forms(self):
        text = "\n".join([
            "# comment",
            "",
            "dp.sa.aaa",
            "prod dp.sa.bbb",
            "STAGING=dp.pt.ccc",
            'export QA="dp.sa.ddd"',
        ])
        self.assertEqual(
            audit.parse_tokens(text, "t"),
            [(None, "dp.sa.aaa"), ("prod", "dp.sa.bbb"), ("STAGING", "dp.pt.ccc"), ("QA", "dp.sa.ddd")],
        )

    def test_env_tokens_are_labelled_by_name(self):
        os.environ["TEST_TOKEN_ACME_PROD"] = "dp.sa.aaa"
        try:
            self.assertEqual(audit.tokens_from_env("TEST_TOKEN_"), [("ACME_PROD", "dp.sa.aaa")])
            os.environ["TEST_TOKEN_BAD"] = "label dp.sa.bbb"
            with self.assertRaises(ValueError):
                audit.tokens_from_env("TEST_TOKEN_")
        finally:
            os.environ.pop("TEST_TOKEN_ACME_PROD", None)
            os.environ.pop("TEST_TOKEN_BAD", None)

    def test_bad_line_does_not_echo_content(self):
        with self.assertRaises(ValueError) as ctx:
            audit.parse_tokens("dp.sa.ok\nsupersecret value here", "t")
        self.assertIn("line 2", str(ctx.exception))
        self.assertNotIn("supersecret", str(ctx.exception))


class Checks(unittest.TestCase):
    now = datetime(2026, 10, 29, tzinfo=timezone.utc)
    options = {"stale_days": 90, "max_ttl_seconds": 3600}

    def findings(self, identity, role="collaborator"):
        config = identity["config"]
        row = {
            "method": identity["method"], "claims_type": config["claims_type"], "claims": config["claims"],
            "ttl_seconds": identity["ttl_seconds"], "created_at": identity["created_at"], "last_seen_at": identity["last_seen_at"],
            "service_account_role_identifier": role, "service_account_role": role.title(),
        }
        return audit.check_row(row, self.now, self.options)

    def severities(self, identity, role="collaborator"):
        return sorted(f["severity"] for f in self.findings(identity, role))

    def test_clean_identity_has_no_findings(self):
        self.assertEqual(self.findings(mock_api.IDENTITIES["20000000-0000-4000-8000-000000000001"][0]), [])

    def test_wide_open_identity(self):
        wide_open = mock_api.IDENTITIES["00000000-0000-4000-8000-000000000001"][2]
        # aud "*", sub "*", 12h TTL, never used
        self.assertEqual(self.severities(wide_open), ["high", "high", "low", "low"])

    def test_wildcards_only_matter_for_wildcard_type(self):
        exact = mock_api.identity("x", "x", {"aud": ["*"], "sub": ["*"]}, claims_type="exact")
        self.assertEqual(self.findings(exact), [])

    def test_findings_name_their_rule_and_field(self):
        wide_open = mock_api.IDENTITIES["00000000-0000-4000-8000-000000000001"][2]
        found = {(f["rule"], f["field"]) for f in self.findings(wide_open)}
        self.assertEqual(found, {("any-value", "claims.aud"), ("any-value", "claims.sub"), ("long-ttl", "ttl"), ("never-used", "last_seen")})
        self.assertEqual(self.findings(wide_open)[0]["title"], "Claim accepts any value")

    def test_rules_describe_the_thresholds_in_use(self):
        rules = {r["id"]: r for r in audit.finding_rules({"stale_days": 30, "max_ttl_seconds": 1800})}
        self.assertIn("30 days", rules["stale"]["when"])
        self.assertIn("30m", rules["long-ttl"]["when"])
        self.assertEqual(set(rules), set(audit.RULES))

    def test_admin_role_and_leading_wildcard(self):
        tf = mock_api.IDENTITIES["00000000-0000-4000-8000-000000000002"][0]
        # leading wildcard on sub, admin role, unused since January
        self.assertEqual(self.severities(tf, "admin"), ["low", "medium", "medium"])


class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = mock_api.start()
        cls.host = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_report(self):
        tokens = [("acme", "dp.sa.acme"), ("globex", "dp.sa.globex"), ("noperm", "dp.sa.noperm"),
                  ("revoked", "dp.sa.nope"), ("acme-again", "dp.sa.acmedupe")]
        report = audit.build_report(tokens, self.host)
        summary = report["summary"]
        self.assertEqual(summary["workplaces"], 5)
        self.assertEqual(summary["workplaces_failed"], 3)  # 403, 401, duplicate
        self.assertEqual(summary["identities"], 6)
        names = {row["identity_name"] for row in report["identities"]}
        self.assertTrue(any("sneaky" in n for n in names), "identity on page 2 of service accounts was missed")

        errors = {w["token_label"]: w["error"] for w in report["workplaces"]}
        self.assertIn("403", errors["noperm"])
        self.assertIn("401", errors["revoked"])
        self.assertIn("duplicate", errors["acme-again"])

    def test_identify_token(self):
        self.assertEqual(audit.identify_token("dp.sa.globex", self.host), ({"slug": "globex456", "name": "Globex"}, None))
        workplace, error = audit.identify_token("dp.sa.revoked", self.host)
        self.assertIsNone(workplace)
        self.assertIn("401", error)

    def test_unlabelled_token_is_named_by_its_last_characters(self):
        report = audit.build_report([(None, "dp.sa.globex"), (None, "dp.sa.nope")], self.host)
        self.assertEqual([w["token_label"] for w in report["workplaces"]], [None, None])
        self.assertEqual(report["identities"][0]["token_label"], "…obex")
        self.assertIn("token: …nope", audit.format_text(report))

    def test_apply_checks_reuses_fetched_data(self):
        report = audit.build_report([("acme", "dp.sa.acme")], self.host)
        self.assertEqual(report["summary"]["findings"]["low"], 4)
        stricter = audit.apply_checks(report, {"stale_days": 1, "max_ttl_seconds": 300})
        self.assertGreater(stricter["summary"]["findings"]["low"], 4)
        self.assertEqual(stricter["options"], {"stale_days": 1, "max_ttl_seconds": 300})
        self.assertEqual(report["summary"]["findings"]["low"], 4)  # the original is left alone

    def test_outputs_are_safe(self):
        report = audit.build_report([("acme", "dp.sa.acme")], self.host)
        text = audit.format_text(report)
        self.assertNotIn("\x1b", text)
        self.assertIn("wide open", text)
        csv_text = audit.format_csv(report)
        self.assertIn("'=HYPERLINK", csv_text)

    def test_cli_exit_codes(self):
        path = os.path.join(os.path.dirname(__file__), "tokens.txt")
        self.assertEqual(audit.main(["--api-host", self.host, "-f", "json", "-o", os.devnull, "-t", path]), 1)
        os.environ["DOPPLER_AUDIT_TOKEN_GLOBEX"] = "dp.sa.globex"
        try:
            self.assertEqual(audit.main(["--api-host", self.host, "-o", os.devnull]), 0)
            os.environ["DOPPLER_AUDIT_TOKEN_ACME"] = "dp.sa.acme"
            self.assertEqual(audit.main(["--api-host", self.host, "-o", os.devnull, "--fail-on", "high"]), 3)
        finally:
            os.environ.pop("DOPPLER_AUDIT_TOKEN_GLOBEX", None)
            os.environ.pop("DOPPLER_AUDIT_TOKEN_ACME", None)

    def test_review_records_and_resumes(self):
        import builtins
        import contextlib
        import csv
        import tempfile

        report = audit.build_report([("acme", "dp.sa.acme"), ("globex", "dp.sa.globex")], self.host)
        path = os.path.join(tempfile.mkdtemp(), "review.csv")

        def review(answers):
            replies = iter(answers)
            original = builtins.input
            builtins.input = lambda prompt="": next(replies)
            try:
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    audit.run_review(report, path, color=False)
            finally:
                builtins.input = original
            with open(path, newline="") as handle:
                return {r["identity_name"]: r for r in csv.DictReader(handle)}, out.getvalue()

        # Highest severity first: "wide open" (high), then "tf cloud" (medium).
        rows, out = review(["f", "=accepts anything", "a", "q"])
        self.assertIn("Identity 1 of 6", out)
        self.assertEqual((rows["wide open"]["decision"], rows["wide open"]["note"]), ("flagged", "'=accepts anything"))
        self.assertEqual(rows["tf cloud"]["decision"], "approved")
        self.assertEqual(rows["release pipeline"]["decision"], "not reviewed")
        self.assertEqual(len(rows), 6)

        # Running again picks up at the first identity without a decision, and keeps earlier notes intact.
        rows, out = review(["n", "checked with platform team", "q"])
        self.assertIn("Identity 3 of 6", out)
        self.assertEqual(rows["any acme repo"]["note"], "checked with platform team")
        self.assertEqual(rows["wide open"]["note"], "'=accepts anything")

        # Changing an identity's configuration clears its decision.
        report["identities"][0]["ttl_seconds"] = 1800
        rows, _ = review(["q"])
        self.assertEqual(rows[report["identities"][0]["identity_name"]]["decision"], "not reviewed")

    def test_waits_out_rate_limits(self):
        report = audit.build_report([("rl", "dp.sa.ratelimited")], self.host)
        self.assertIsNone(report["workplaces"][0]["error"])
        self.assertEqual(report["summary"]["identities"], 1)

    def test_rejects_plain_http_remote_host(self):
        with self.assertRaises(ValueError):
            audit.check_api_host("http://api.example.com")


if __name__ == "__main__":
    unittest.main()
