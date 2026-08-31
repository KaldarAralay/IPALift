from __future__ import annotations

import contextlib
import io
import unittest
from pathlib import Path
from unittest.mock import patch

from ipalift.cli import main
from ipalift.full_run import FULL_RUN_STAGES, FullRunResult


class RunAllCLITests(unittest.TestCase):
    def test_run_all_forwards_options_and_reports_progress(self) -> None:
        workspace = Path("workspace")
        report = workspace / "reports" / "reconstruction-handoff-report.md"
        result = FullRunResult(workspace, FULL_RUN_STAGES, report)
        stdout = io.StringIO()

        def invoke(*args: object, **kwargs: object) -> FullRunResult:
            on_stage = kwargs["on_stage"]
            for index, stage in enumerate(FULL_RUN_STAGES, 1):
                on_stage(index, len(FULL_RUN_STAGES), stage)
            return result

        with patch("ipalift.cli.run_full_pipeline", side_effect=invoke) as run:
            with contextlib.redirect_stdout(stdout):
                exit_code = main([
                    "run-all",
                    "fixture.ipa",
                    "--output",
                    "workspace",
                    "--ghidra-home",
                    "ghidra",
                    "--function-timeout",
                    "45",
                    "--analysis-timeout",
                    "7200",
                ])

        self.assertEqual(0, exit_code)
        run.assert_called_once()
        args, kwargs = run.call_args
        self.assertEqual((Path("fixture.ipa"), Path("workspace")), args)
        self.assertEqual(Path("ghidra"), kwargs["ghidra_home"])
        self.assertEqual(45, kwargs["function_timeout"])
        self.assertEqual(7200, kwargs["analysis_timeout"])
        output = stdout.getvalue()
        self.assertIn("[1/13] analyze", output)
        self.assertIn("[13/13] build-handoff", output)
        self.assertIn("Completed full IPALift pipeline", output)
        self.assertIn(str(report), output)


if __name__ == "__main__":
    unittest.main()
