from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ipalift.pipeline import analyze_ipa

from helpers import create_test_ipa


EXPECTED_REPORTS = {
    "application.json",
    "architectures.json",
    "frameworks.json",
    "classes.json",
    "assets.json",
    "unresolved.json",
}


class PipelineTests(unittest.TestCase):
    def test_end_to_end_outputs_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ipa = create_test_ipa(root / "fixture.ipa")
            first = analyze_ipa(ipa, root / "first")
            second = analyze_ipa(ipa, root / "second")
            self.assertEqual(EXPECTED_REPORTS, {item.name for item in first.paths.analysis_root.iterdir()})
            for name in EXPECTED_REPORTS:
                first_bytes = (first.paths.analysis_root / name).read_bytes()
                second_bytes = (second.paths.analysis_root / name).read_bytes()
                self.assertEqual(first_bytes, second_bytes, name)
                document = json.loads(first_bytes)
                self.assertEqual(1, document["schema_version"])
                self.assertEqual(name.removesuffix(".json"), document["artifact"])
                self.assertIsInstance(document["facts"], dict)
                self.assertIsInstance(document["hypotheses"], list)
                self.assertIsInstance(document["errors"], list)
            self.assertEqual(first.paths.report_path.read_bytes(), second.paths.report_path.read_bytes())

    def test_schema_artifacts_match_report_names(self) -> None:
        schema_root = Path(__file__).parents[1] / "schemas"
        for name in EXPECTED_REPORTS:
            schema = json.loads((schema_root / name.replace(".json", ".schema.json")).read_text(encoding="utf-8"))
            artifact = schema["allOf"][1]["properties"]["artifact"]["const"]
            self.assertEqual(name.removesuffix(".json"), artifact)


if __name__ == "__main__":
    unittest.main()
