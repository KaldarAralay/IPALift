from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


class ReleaseContractTests(unittest.TestCase):
    def test_visual_studio_ci_uses_explicit_instance_discovery(self) -> None:
        root = Path(__file__).parents[1]
        presets = json.loads(
            (root / "reconstruction-core" / "CMakePresets.json").read_text(encoding="utf-8")
        )
        windows_preset = next(
            item for item in presets["configurePresets"] if item["name"] == "windows-x64"
        )
        self.assertEqual("Visual Studio 17 2022", windows_preset["generator"])

        workflow = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        job_match = re.search(
            r"(?ms)^  reconstruction-core:\n(?P<body>.*?)(?=^  [a-z][a-z0-9-]+:|\Z)",
            workflow,
        )
        self.assertIsNotNone(job_match)
        self.assertRegex(job_match.group("body"), r"(?m)^    runs-on: windows-2022$")

        build_script = (
            root / "reconstruction-core" / "scripts" / "build-and-test.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("Microsoft.VisualStudio.Component.VC.Tools.x86.x64", build_script)
        self.assertIn("-DCMAKE_GENERATOR_INSTANCE=$visualStudioInstance", build_script)


if __name__ == "__main__":
    unittest.main()
