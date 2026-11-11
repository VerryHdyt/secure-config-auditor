import tempfile
import unittest
from pathlib import Path

from secure_config_auditor.checks import scan_world_writable


class FilesystemChecksTest(unittest.TestCase):
    def test_detects_world_writable_file(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "unsafe.conf"
            target.write_text("example")
            target.chmod(0o666)
            findings = scan_world_writable([Path(temp)])
            self.assertTrue(any(item.path == str(target) and item.check_id == "FS-001"
                                for item in findings))

    def test_ignores_safe_file(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "safe.conf"
            target.write_text("example")
            target.chmod(0o600)
            findings = scan_world_writable([Path(temp)])
            self.assertFalse(any(item.path == str(target) for item in findings))


if __name__ == "__main__":
    unittest.main()
