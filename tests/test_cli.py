from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ipalift.cli import main
from ipalift.ghidra import GhidraError


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
    def test_ghidra_and_timeout_failures_are_concise(self) -> None:
        ghidra_stderr = io.StringIO()
        with patch(
            "ipalift.cli.decompile_workspace",
            side_effect=GhidraError(
                "Ghidra was not found. Pass --ghidra-home <directory>, set GHIDRA_HOME, "
                "or install an official release under tools/ghidra/."
            ),
        ):
            with contextlib.redirect_stderr(ghidra_stderr):
                exit_code = main(["decompile", "workspace"])
        self.assertEqual(2, exit_code)
        self.assertIn("ipalift: error: Ghidra was not found", ghidra_stderr.getvalue())
        self.assertNotIn("Traceback", ghidra_stderr.getvalue())

        timeout_stderr = io.StringIO()
        with contextlib.redirect_stderr(timeout_stderr):
            exit_code = main([
                "decompile",
                "missing-workspace",
                "--function-timeout",
                "0",
            ])
        self.assertEqual(2, exit_code)
        self.assertIn(
            "ipalift: error: --function-timeout must be between 1 and 600 seconds",
            timeout_stderr.getvalue(),
        )
        self.assertNotIn("Traceback", timeout_stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
