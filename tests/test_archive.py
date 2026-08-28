from __future__ import annotations

import tempfile
import unittest
import stat
import zipfile
from pathlib import Path

from ipalift.archive import extract_and_inventory
from ipalift.errors import InvalidIPAError
from ipalift.util import sha256_file

from helpers import create_test_ipa


class ArchiveTests(unittest.TestCase):
    @staticmethod
    def _add_link(archive: zipfile.ZipFile, name: str, target: str) -> None:
        info = zipfile.ZipInfo(name)
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o755) << 16
        archive.writestr(info, target.encode("utf-8"))

    def test_extracts_valid_ipa_and_preserves_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ipa = create_test_ipa(root / "fixture.ipa")
            before = sha256_file(ipa)
            result = extract_and_inventory(ipa, root / "out")
            self.assertEqual("Fixture", result.bundle.executable_name)
            self.assertEqual("test.ipalift.fixture", result.bundle.plist["CFBundleIdentifier"])
            self.assertEqual(4, len(result.files))
            self.assertEqual(2, len(result.assets))
            self.assertEqual(before, sha256_file(ipa))
            self.assertTrue((result.evidence_root / "Payload" / "Fixture.app" / "Fixture").is_file())

    def test_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ipa = root / "unsafe.ipa"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("../escape.txt", "unsafe")
            with self.assertRaisesRegex(InvalidIPAError, "unsafe archive path"):
                extract_and_inventory(ipa, root / "out")
            self.assertFalse((root / "escape.txt").exists())

    def test_refuses_to_overwrite_conflicting_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ipa = create_test_ipa(root / "fixture.ipa")
            output = root / "out"
            first = extract_and_inventory(ipa, output)
            target = first.evidence_root / "Payload" / "Fixture.app" / "image.png"
            target.write_bytes(b"conflict")
            with self.assertRaisesRegex(InvalidIPAError, "conflicting extracted evidence"):
                extract_and_inventory(ipa, output)
            self.assertEqual(b"conflict", target.read_bytes())

    def test_materializes_safe_internal_symbolic_link_as_regular_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ipa = create_test_ipa(root / "fixture.ipa")
            with zipfile.ZipFile(ipa, "a") as archive:
                archive.writestr("Payload/Fixture.app/_CodeSignature/CodeResources", b"signed-content")
                self._add_link(
                    archive,
                    "Payload/Fixture.app/CodeResources",
                    "_CodeSignature/CodeResources",
                )
            result = extract_and_inventory(ipa, root / "out")
            materialized = result.evidence_root / "Payload" / "Fixture.app" / "CodeResources"
            self.assertTrue(materialized.is_file())
            self.assertFalse(materialized.is_symlink())
            self.assertEqual(b"signed-content", materialized.read_bytes())
            record = next(item for item in result.files if item["path"].endswith("/CodeResources"))
            self.assertEqual("symbolic_link", record["archive_entry_type"])
            self.assertEqual("_CodeSignature/CodeResources", record["link_target"])
            self.assertEqual(
                "Payload/Fixture.app/_CodeSignature/CodeResources",
                record["resolved_archive_path"],
            )
            self.assertEqual("materialized", record["link_status"])
            self.assertEqual(len(b"signed-content"), record["size"])

    def test_preserves_missing_internal_symbolic_link_as_unresolved_inert_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ipa = create_test_ipa(root / "fixture.ipa")
            with zipfile.ZipFile(ipa, "a") as archive:
                self._add_link(
                    archive,
                    "Payload/Fixture.app/CodeResources",
                    "_CodeSignature/CodeResources",
                )
            result = extract_and_inventory(ipa, root / "out")
            materialized = result.evidence_root / "Payload" / "Fixture.app" / "CodeResources"
            self.assertFalse(materialized.is_symlink())
            self.assertEqual(b"_CodeSignature/CodeResources", materialized.read_bytes())
            record = next(item for item in result.files if item["path"].endswith("/CodeResources"))
            self.assertEqual("target_missing", record["link_status"])
            self.assertEqual(
                "Payload/Fixture.app/_CodeSignature/CodeResources",
                record["resolved_archive_path"],
            )
            self.assertEqual(
                ["archive_symbolic_link_target_missing"],
                [item["code"] for item in result.issues],
            )

    def test_rejects_unsafe_directory_and_cyclic_symbolic_links(self) -> None:
        cases = {
            "absolute": ("/outside", "unsafe target"),
            "escape": ("../../../outside", "escapes the archive root"),
        }
        for label, (target, message) in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                ipa = create_test_ipa(root / "fixture.ipa")
                with zipfile.ZipFile(ipa, "a") as archive:
                    self._add_link(archive, "Payload/Fixture.app/UnsafeLink", target)
                with self.assertRaisesRegex(InvalidIPAError, message):
                    extract_and_inventory(ipa, root / "out")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ipa = create_test_ipa(root / "directory.ipa")
            with zipfile.ZipFile(ipa, "a") as archive:
                archive.writestr("Payload/Fixture.app/Directory/", b"")
                self._add_link(archive, "Payload/Fixture.app/DirectoryLink", "Directory")
            with self.assertRaisesRegex(InvalidIPAError, "targets a directory"):
                extract_and_inventory(ipa, root / "out")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ipa = create_test_ipa(root / "cyclic.ipa")
            with zipfile.ZipFile(ipa, "a") as archive:
                self._add_link(archive, "Payload/Fixture.app/LinkA", "LinkB")
                self._add_link(archive, "Payload/Fixture.app/LinkB", "LinkA")
            with self.assertRaisesRegex(InvalidIPAError, "cyclic symbolic link"):
                extract_and_inventory(ipa, root / "out")


if __name__ == "__main__":
    unittest.main()
