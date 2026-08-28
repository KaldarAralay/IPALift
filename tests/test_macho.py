from __future__ import annotations

import unittest

from ipalift.errors import MachOError
from ipalift.macho import parse_macho_bytes

from helpers import minimal_macho


class MachOTests(unittest.TestCase):
    def test_parses_core_thin_macho_facts(self) -> None:
        analysis = parse_macho_bytes(minimal_macho())
        self.assertEqual("thin", analysis.container)
        self.assertEqual(1, len(analysis.slices))
        item = analysis.slices[0]
        self.assertEqual("arm6", item.architecture_name)
        self.assertEqual(32, item.bits)
        self.assertEqual("executable", item.as_facts()["file_type_name"])
        self.assertFalse(item.encryption["is_encrypted"])
        self.assertEqual("2.1.0", item.deployment_target["minimum_version"])
        self.assertEqual("UIKit", item.linked_libraries[0]["name"])

    def test_rejects_non_macho(self) -> None:
        with self.assertRaisesRegex(MachOError, "not a supported Mach-O"):
            parse_macho_bytes(b"NOPE" + b"\0" * 32)

    def test_rejects_truncated_macho_header(self) -> None:
        with self.assertRaisesRegex(MachOError, "header is truncated"):
            parse_macho_bytes(b"\xce\xfa\xed\xfe" + b"\0" * 8)


if __name__ == "__main__":
    unittest.main()
