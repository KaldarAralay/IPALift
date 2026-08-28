from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from ipalift.cli import main


class CLITests(unittest.TestCase):
    def test_missing_input_has_concise_error_and_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                exit_code = main(["analyze", str(root / "missing.ipa"), "--output", str(root / "out")])
            self.assertEqual(2, exit_code)
            self.assertIn("ipalift: error: Cannot access source IPA", stderr.getvalue())
            self.assertFalse((root / "out").exists())


if __name__ == "__main__":
    unittest.main()
