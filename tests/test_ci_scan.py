import contextlib
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agent import ci_scan


class CiScanTests(unittest.TestCase):
    def setUp(self):
        self.sources = {
            "target_app/app.py": [
                "value = request.args.get('q', '')",
                "query = 'SELECT * FROM users WHERE name = ' + value",
                "cursor.execute(query)",
            ]
        }
        self.finding = {
            "file": "target_app/app.py",
            "line": 2,
            "description": "Request input is concatenated into executed SQL.",
        }

    def test_reads_only_python_sources_under_target_app(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "target_app" / "nested").mkdir(parents=True)
            (root / "target_app" / "app.py").write_text("first\nsecond\n")
            (root / "target_app" / "nested" / "query.py").write_text("nested\n")
            (root / "target_app" / "notes.txt").write_text("not source")
            (root / "outside.py").write_text("not scanned")
            self.assertEqual(
                ci_scan.read_sources(root),
                {
                    "target_app/app.py": ["first", "second"],
                    "target_app/nested/query.py": ["nested"],
                },
            )

    def test_rejects_source_symlink_outside_target_app(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "target_app").mkdir()
            outside = root / "outside.py"
            outside.write_text("must not be sent")
            try:
                (root / "target_app" / "link.py").symlink_to(outside)
            except OSError:
                self.skipTest("Symlinks are unavailable")
            with self.assertRaises(ValueError):
                ci_scan.read_sources(root)

    def test_rejects_target_app_directory_symlink(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            try:
                (root / "target_app").symlink_to(root, target_is_directory=True)
            except OSError:
                self.skipTest("Symlinks are unavailable")
            with self.assertRaises(ValueError):
                ci_scan.read_sources(root)

    def test_renders_finding_once_with_exact_location(self):
        report = ci_scan.render_report(
            {"findings": [self.finding, self.finding]}, self.sources
        )
        self.assertEqual(
            report,
            "## AI Security Scan\n\n- `target_app/app.py:2` \u2014 "
            "Request input is concatenated into executed SQL.",
        )

    def test_renders_clean_scan(self):
        self.assertEqual(
            ci_scan.render_report({"findings": []}, self.sources),
            "## AI Security Scan\n\nNo vulnerabilities found.",
        )

    def test_rejects_invalid_model_findings(self):
        invalid_results = [
            [],
            {},
            {"findings": "none"},
            {"findings": [None]},
            {"findings": [dict(self.finding, file="../secret.py")]},
            {"findings": [dict(self.finding, line=0)]},
            {"findings": [dict(self.finding, line=4)]},
            {"findings": [dict(self.finding, line=True)]},
            {"findings": [dict(self.finding, description=" ")]},
        ]
        for result in invalid_results:
            with self.subTest(result=result), self.assertRaises(ValueError):
                ci_scan.render_report(result, self.sources)

    def test_escapes_untrusted_description(self):
        result = {"findings": [dict(
            self.finding,
            description="<img> @everyone [click](https://example.com)\nSQL",
        )]}
        report = ci_scan.render_report(result, self.sources)
        self.assertNotIn("<img>", report)
        self.assertNotIn("@everyone", report)
        self.assertIn(r"\[click\]", report)
        self.assertEqual(len(report.splitlines()), 3)

    @patch.dict("os.environ", {
        "LLM_API_KEY": "test-key",
        "LLM_BASE_URL": "https://example.invalid/v1/",
        "LLM_MODEL": "test-model",
    }, clear=True)
    @patch("agent.ci_scan.OpenAI")
    def test_uses_environment_and_numbered_sources(self, client_class):
        client = client_class.return_value
        client.chat.completions.create.return_value = SimpleNamespace(choices=[
            SimpleNamespace(
                finish_reason="stop",
                message=SimpleNamespace(content='{"findings": []}'),
            )
        ])
        self.assertEqual(ci_scan.scan(self.sources), {"findings": []})
        client_class.assert_called_once_with(
            api_key="test-key", base_url="https://example.invalid/v1/",
            timeout=90, max_retries=0,
        )
        request = client.chat.completions.create.call_args.kwargs
        self.assertEqual(request["model"], "test-model")
        self.assertEqual(request["messages"][0]["content"], ci_scan.SYSTEM_PROMPT)
        source_data = json.loads(request["messages"][1]["content"])
        self.assertIn("2: query =", source_data["files"][0]["source"])
        client.chat.completions.create.return_value.choices[0].finish_reason = "length"
        with self.assertRaises(ValueError):
            ci_scan.scan(self.sources)

    @patch.dict("os.environ", {}, clear=True)
    @patch("agent.ci_scan.OpenAI")
    def test_missing_key_does_not_call_provider(self, client_class):
        with self.assertRaises(ValueError):
            ci_scan.scan(self.sources)
        client_class.assert_not_called()

    def test_main_prints_failure_report_without_sensitive_error_body(self):
        rate_limit_error = type("RateLimitError", (Exception,), {})
        for error in [
            RuntimeError("secret"),
            ValueError("invalid JSON"),
            rate_limit_error("rate limit reached"),
        ]:
            with self.subTest(error=type(error).__name__):
                stdout, stderr = io.StringIO(), io.StringIO()
                with (
                    patch("agent.ci_scan.read_sources", return_value=self.sources),
                    patch("agent.ci_scan.scan", side_effect=error),
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    self.assertEqual(ci_scan.main(), 1)
                self.assertIn("Scan couldn't complete.", stdout.getvalue())
                self.assertNotIn("No vulnerabilities found.", stdout.getvalue())
                self.assertNotIn(str(error), stderr.getvalue())

    def test_main_prints_only_markdown_on_success(self):
        stdout = io.StringIO()
        with (
            patch("agent.ci_scan.read_sources", return_value=self.sources),
            patch("agent.ci_scan.scan", return_value={"findings": [self.finding]}),
            contextlib.redirect_stdout(stdout),
        ):
            self.assertEqual(ci_scan.main(), 0)
        self.assertTrue(stdout.getvalue().startswith("## AI Security Scan\n\n"))
        self.assertIn("target_app/app.py:2", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
