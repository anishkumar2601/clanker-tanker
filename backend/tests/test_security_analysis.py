import tempfile
import unittest
from pathlib import Path

from backend.app.inventory import build_inventory
from backend.app.ai_analyst import _valid_references
from backend.app.security_analysis import normalize_findings, scan_secrets


class SecurityAnalysisTests(unittest.TestCase):
    def test_secret_scanner_redacts_credential_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = "AKIA1234567890ABCDEF"
            (root / "config.py").write_text(f'AWS_ACCESS_KEY_ID = "{secret}"\n', encoding="utf-8")
            findings = scan_secrets(root)
            self.assertEqual(len(findings), 1)
            self.assertNotIn(secret, findings[0]["snippet"])
            self.assertIn("*", findings[0]["snippet"])

    def test_overlapping_secret_findings_are_correlated(self):
        findings = normalize_findings(
            [
                {"id": "a", "type": "hardcoded_secret", "title": "Credential", "severity": "High", "confidence": 0.8, "source": "pattern-scanner", "file": "config.py", "line": 4, "snippet": 'TOKEN = "secret-value"', "evidence": "TOKEN", "attack_path": ["Source repository", "Credential in source"]},
                {"id": "b", "type": "secret_exposure", "title": "Secret", "severity": "High", "confidence": 0.95, "source": "secret-scanner", "file": "config.py", "line": 4, "snippet": 'TOKEN = "secret-value"', "evidence": "TOKEN", "attack_path": ["Source repository", "Credential in source"]},
            ],
            {"api_routes": []},
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "secret_exposure")
        self.assertEqual(set(findings[0]["sources"]), {"pattern-scanner", "secret-scanner"})
        self.assertTrue(findings[0]["secret_redacted"])

    def test_inventory_maps_routes_and_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "routes.py").write_text('@app.get("/users")\ndef users():\n    return []\n', encoding="utf-8")
            (root / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
            inventory = build_inventory(root)
            self.assertEqual(inventory["api_routes"][0]["path"], "/users")
            self.assertEqual(inventory["dependencies"][0]["name"], "requests")

    def test_ai_reference_validation_rejects_nonexistent_line(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("print('safe')\n", encoding="utf-8")
            finding = {"file": "app.py"}
            self.assertFalse(_valid_references({"evidence_refs": [{"file": "app.py", "line": 99}]}, finding, root))
            self.assertTrue(_valid_references({"evidence_refs": [{"file": "app.py", "line": 1}]}, finding, root))


if __name__ == "__main__":
    unittest.main()
