import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from waflens.analyze import summarize
from waflens.cli import main
from waflens.parser import iter_events, parse_record

SAMPLE = Path(__file__).resolve().parent.parent / "examples" / "sample-audit.log"


def tx(ip, uri, status, *rules, ts="Sun Oct 18 09:00:00 2026"):
    return {
        "transaction": {
            "client_ip": ip,
            "time_stamp": ts,
            "unique_id": "x",
            "request": {"method": "GET", "uri": uri},
            "response": {"http_code": status},
            "messages": [
                {"message": f"rule {r}", "details": {"ruleId": r, "tags": tags}}
                for r, tags in rules
            ],
        }
    }


class ParserTests(unittest.TestCase):
    def test_parse_record_fields(self):
        ev = parse_record(tx("1.2.3.4", "/a?b=1", 403, ("942100", ["attack-sqli", "OWASP_CRS"])))
        self.assertEqual(ev.client_ip, "1.2.3.4")
        self.assertEqual(ev.path, "/a")
        self.assertTrue(ev.blocked)
        self.assertEqual(ev.hits[0].attack_types, ["sqli"])
        self.assertEqual(ev.timestamp.hour, 9)

    def test_missing_fields_do_not_crash(self):
        ev = parse_record({"transaction": {"response": {"http_code": "oops"}}})
        self.assertEqual(ev.status, 0)
        self.assertEqual(ev.path, "/")
        self.assertIsNone(ev.timestamp)

    def test_malformed_lines_are_counted(self):
        stream = io.StringIO(json.dumps(tx("1.1.1.1", "/", 200)) + "\nnot json\n[1,2]\n\n")
        errors = []
        events = list(iter_events(stream, errors))
        self.assertEqual(len(events), 1)
        self.assertEqual(errors, [2, 3])


class AnalyzeTests(unittest.TestCase):
    def test_summary_rules_are_excluded_by_default(self):
        events = [parse_record(tx("1.1.1.1", "/", 403, ("942100", []), ("949110", [])))]
        self.assertNotIn("949110", summarize(events).rules)
        self.assertIn("949110", summarize(events, include_summary_rules=True).rules)

    def test_attack_type_counted_once_per_event(self):
        events = [parse_record(tx("1.1.1.1", "/", 403, ("942100", ["attack-sqli"]), ("942430", ["attack-sqli"])))]
        self.assertEqual(summarize(events).attack_types["sqli"], 1)

    def test_false_positive_needs_many_clients(self):
        noisy = [parse_record(tx(f"10.0.0.{i}", "/search?q=a", 200, ("942430", []))) for i in range(6)]
        scanner = [parse_record(tx("6.6.6.6", "/login", 403, ("942100", []))) for _ in range(50)]
        s = summarize(noisy + scanner, fp_min_ips=5)
        self.assertEqual([(c.rule_id, c.path, c.distinct_ips) for c in s.fp_candidates], [("942430", "/search", 6)])
        self.assertAlmostEqual(s.block_rate, 50 / 56)


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_sample_log_json_report(self):
        code, out, err = self.run_cli(str(SAMPLE), "--format", "json")
        self.assertEqual(code, 0)
        report = json.loads(out)
        self.assertGreater(report["total_events"], 200)
        self.assertEqual(report["false_positive_candidates"][0]["rule_id"], "942430")
        self.assertIn("skipped 1 malformed", err)

    def test_text_and_markdown_render(self):
        for fmt, marker in (("text", "Top rules"), ("markdown", "# WAF log report")):
            code, out, _ = self.run_cli(str(SAMPLE), "-f", fmt)
            self.assertEqual(code, 0)
            self.assertIn(marker, out)

    def test_missing_file_exits_2(self):
        code, _, err = self.run_cli("/nonexistent/audit.log")
        self.assertEqual(code, 2)
        self.assertIn("waflens:", err)


if __name__ == "__main__":
    unittest.main()
