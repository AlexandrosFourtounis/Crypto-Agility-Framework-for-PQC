"""Regression checks for the documented local scanning and remediation workflow."""

from io import BytesIO
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from crypto_agility import remediation, scanner, web
from crypto_agility.report import build_report


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.rules = scanner.load_rules()

    def scan(self, name, source):
        path = self.root / name
        path.write_text(source, encoding="utf-8")
        return scanner.scan_file(path, self.rules)

    def test_detection_across_languages(self):
        samples = [
            ("sample.py", "hashlib.md5(data)", "detect-md5"),
            ("Sample.java", 'MessageDigest.getInstance("MD5")', "detect-md5-java"),
            ("sample.c", "SHA1(input, size, output);", "detect-sha1-c"),
        ]
        for name, source, expected in samples:
            with self.subTest(language=name):
                self.assertIn(expected, {f["check_id"] for f in self.scan(name, source)})

    def test_language_filters_avoid_cross_language_findings(self):
        self.assertEqual(self.scan("Sample.java", 'String text = "hashlib.md5(data)";'), [])

    def test_rsa_key_size_boundary(self):
        for size, expected in [(1024, True), (2048, False), (4096, False)]:
            with self.subTest(size=size):
                findings = self.scan("sample.py", f"key = RSA.generate({size})")
                self.assertEqual(any(f["check_id"] == "detect-small-rsa" for f in findings), expected)

    def test_hardcoded_key_location_excludes_preceding_blank_line(self):
        findings = self.scan("sample.py", '\nkey = b"example-key"\n')
        finding = next(f for f in findings if f["check_id"] == "detect-hardcoded-keys")
        self.assertEqual(finding["start"], {"line": 2, "col": 1})

    def test_static_iv_configuration_is_reported(self):
        findings = self.scan("sample.py", 'iv = b"1234567890123456"\n')
        self.assertIn("detect-static-iv", {finding["check_id"] for finding in findings})

    def test_only_supported_sources_are_collected(self):
        (self.root / "sample.py").write_text("pass\n")
        (self.root / "notes.txt").write_text("hashlib.md5(data)")
        (self.root / ".venv").mkdir()
        (self.root / ".venv/dependency.py").write_text("hashlib.md5(data)")
        self.assertEqual(scanner.gather_all_files(self.root), [str(self.root / "sample.py")])


class CaseWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.database = self.root / "findings.db"
        for module in (web, remediation):
            patcher = patch.object(module, "DATABASE", self.database)
            patcher.start()
            self.addCleanup(patcher.stop)
        config = patch.dict(web.app.config, {"TESTING": True, "UPLOAD_FOLDER": str(self.root / "cases")})
        config.start()
        self.addCleanup(config.stop)
        scanner.create_database(self.database)
        self.client = web.app.test_client()

    def upload(self, source, name="demo", filename="project/sample.py"):
        return self.client.post("/scan_new_directory", data={
            "new_case_name": name,
            "new_target_path": (BytesIO(source.encode()), filename),
        }, content_type="multipart/form-data", follow_redirects=True)

    def rule_ids(self, case="demo"):
        with sqlite3.connect(self.database) as conn:
            return {row[0] for row in conn.execute(
                "SELECT check_id FROM semgrep_results WHERE scan_name=? AND check_id IS NOT NULL", (case,))}

    def test_empty_case_is_idempotent_and_has_no_findings(self):
        for _ in range(2):
            self.client.post("/create_case", data={"case_name": "empty"})
        rows, stats, _ = web.get_case_results("empty")
        self.assertEqual(rows, [])
        self.assertEqual(stats["total"], 0)
        self.assertEqual(web.list_cases()[0]["total"], 0)
        self.assertEqual(self.client.get("/load_case/empty").status_code, 200)
        self.client.post("/delete_case", data={"case_name": "empty"})
        self.assertEqual(web.list_cases(), [])

    def test_upload_fix_and_rescan_refresh_current_findings(self):
        response = self.upload("import hashlib\nvalue = hashlib.md5(data).hexdigest()\n")
        self.assertEqual(response.status_code, 200)
        self.assertIn("detect-md5", self.rule_ids())
        rows, _, _ = web.get_case_results("demo")
        response = self.client.post("/fix_vulnerability", data={"case_name": "demo", "vuln_id": rows[0][0]},
                                    follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        source = (self.root / "cases/demo/project/sample.py").read_text()
        self.assertIn("hashlib.sha256(data).hexdigest()", source)
        self.assertNotIn("detect-md5", self.rule_ids())
        self.assertIn("detect-sha2", self.rule_ids())

    def test_batch_fix_preserves_locations_on_the_same_line(self):
        self.upload("a = hashlib.md5(data); b = hashlib.sha1(other)\n")
        response = self.client.post("/fix_all_vulnerabilities", data={"case_name": "demo"}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        source = (self.root / "cases/demo/project/sample.py").read_text()
        self.assertEqual(source, "a = hashlib.sha256(data); b = hashlib.sha256(other)\n")
        self.assertFalse({"detect-md5", "detect-sha1"} & self.rule_ids())

    def test_assisted_template_does_not_insert_placeholder_functions(self):
        source = 'key = b"example-key"\n'
        self.upload(source)
        self.client.post("/fix_all_vulnerabilities", data={"case_name": "demo"})
        self.assertEqual((self.root / "cases/demo/project/sample.py").read_text(), source)
        self.assertIn("detect-hardcoded-keys", self.rule_ids())

    def test_java_hash_and_python_rsa_replacements(self):
        samples = [
            ("java-md5", "Sample.java", 'MessageDigest.getInstance("MD5");\n',
             'MessageDigest.getInstance("SHA-256");\n'),
            ("java-sha1", "Sample.java", 'MessageDigest.getInstance("SHA-1");\n',
             'MessageDigest.getInstance("SHA-256");\n'),
            ("python-rsa", "sample.py", "key = RSA.generate(1024)\n", "key = RSA.generate(2048)\n"),
        ]
        for name, filename, source, expected in samples:
            with self.subTest(case=name):
                self.upload(source, name, filename)
                response = self.client.post("/fix_all_vulnerabilities", data={"case_name": name},
                                            follow_redirects=True)
                self.assertEqual(response.status_code, 200)
                self.assertEqual((self.root / "cases" / name / filename).read_text(), expected)

    def test_zero_finding_rescan_retains_case_directory(self):
        self.upload("hashlib.md5(data)\n")
        directory = web.get_scan_directory("demo")
        (Path(directory) / "project/sample.py").write_text("value = 42\n")
        self.client.post("/rescan_case", data={"case_name": "demo"})
        self.assertEqual(self.rule_ids(), set())
        self.assertEqual(web.get_scan_directory("demo"), directory)
        self.assertEqual(web.list_cases()[0]["total"], 0)

    def test_upload_paths_cannot_escape_case_storage(self):
        for name, filename in [("../escape", "sample.py"), ("demo", "../../escape.py"),
                               ("demo", str(self.root / "absolute.py"))]:
            with self.subTest(name=name, filename=filename):
                response = self.upload("hashlib.md5(data)", name, filename)
                self.assertEqual(response.status_code, 200)
        self.assertFalse((self.root / "escape.py").exists())
        self.assertFalse((self.root / "absolute.py").exists())
        self.assertEqual(web.list_cases(), [])

    def test_delete_case_keeps_original_cli_source(self):
        source = self.root / "original"
        source.mkdir()
        (source / "sample.py").write_text("hashlib.md5(data)\n")
        web.scan_case("cli", source)
        web.delete_case("cli")
        self.assertTrue((source / "sample.py").exists())
        self.assertEqual(web.list_cases(), [])

    def test_report_counts_suggestions_without_claiming_completed_fixes(self):
        self.upload('hashlib.md5(data)\nkey = b"example-key"\n')
        report = build_report(self.database, "demo")
        self.assertEqual(report["summary"]["findings"], 2)
        self.assertEqual(report["summary"]["files_with_findings"], 1)
        self.assertEqual(report["summary"]["with_suggested_replacement"], 1)
        self.assertNotIn("fixed_files", report["summary"])
        response = self.client.get("/report/demo")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["summary"], report["summary"])
        self.assertIn("detect-md5", self.rule_ids())

    def test_invalid_database_import_preserves_existing_cases(self):
        web.create_case("keep")
        response = self.client.post("/import_db", data={"dbfile": (BytesIO(b"invalid"), "bad.db")},
                                    content_type="multipart/form-data", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(web.list_cases()[0]["scan_name"], "keep")

    def test_exported_database_can_be_reimported(self):
        web.create_case("saved")
        exported = self.client.get("/export_db").data
        web.clear_database()
        response = self.client.post("/import_db", data={"dbfile": (BytesIO(exported), "findings.db")},
                                    content_type="multipart/form-data", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(web.list_cases()[0]["scan_name"], "saved")


if __name__ == "__main__":
    unittest.main()
