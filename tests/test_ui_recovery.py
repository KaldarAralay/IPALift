from __future__ import annotations

import hashlib
import json
import plistlib
import struct
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from ipalift.cli import build_parser
from ipalift.nibarchive import NIBArchiveError, decode_nibarchive
from ipalift.ui_recovery import UIRecoveryError, recover_ui
from ipalift.util import report_envelope, write_json_atomic


def _file_record(workspace: Path, archive_path: str, data: bytes, category: str | None) -> dict:
    path = workspace / "evidence" / "extracted" / Path(*archive_path.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    bundle_root = "Payload/Fixture.app/"
    return {
        "path": archive_path,
        "bundle_relative_path": archive_path[len(bundle_root):] if archive_path.startswith(bundle_root) else None,
        "size": len(data),
        "compressed_size": len(data),
        "crc32": "00000000",
        "sha256": hashlib.sha256(data).hexdigest(),
        "extension": Path(archive_path).suffix.lower(),
        "asset_category": category,
    }


def _keyed_nib() -> bytes:
    uid = plistlib.UID
    objects: list[object] = [
        "$null",
        {
            "$class": uid(7),
            "UIView": uid(2),
            "UIStoryboardIdentifier": "ArchivedScreen",
        },
        {
            "$class": uid(8),
            "UIFrame": "{{0, 0}, {200, 100}}",
            "UISubviews": uid(3),
        },
        {"$class": uid(9), "NS.objects": [uid(4)]},
        {
            "$class": uid(10),
            "UILabelText": "Archived text",
            "UIFrame": "{{10, 12}, {180, 24}}",
        },
        {
            "$class": uid(11),
            "UISource": uid(1),
            "UIDestination": uid(4),
            "UILabel": "archivedLabel",
        },
        {
            "$class": uid(12),
            "UIFirstItem": uid(4),
            "UIFirstAttribute": "width",
            "UIRelation": "equal",
            "UIConstant": 180,
            "UIPriority": 1000,
        },
        {"$classes": ["ArchiveController", "UIViewController", "NSObject"], "$classname": "ArchiveController"},
        {"$classes": ["UIView", "UIResponder", "NSObject"], "$classname": "UIView"},
        {"$classes": ["NSArray", "NSObject"], "$classname": "NSArray"},
        {"$classes": ["UILabel", "UIView", "NSObject"], "$classname": "UILabel"},
        {"$classes": ["UIRuntimeOutletConnection", "NSObject"], "$classname": "UIRuntimeOutletConnection"},
        {"$classes": ["NSLayoutConstraint", "NSObject"], "$classname": "NSLayoutConstraint"},
        {"$class": uid(9), "NS.objects": [uid(1)]},
    ]
    return plistlib.dumps(
        {
            "$archiver": "NSKeyedArchiver",
            "$version": 100000,
            "$objects": objects,
            "$top": {"UINibTopLevelObjectsKey": uid(13)},
        },
        fmt=plistlib.FMT_BINARY,
        sort_keys=True,
    )


def _vint32(value: int) -> bytes:
    result = bytearray()
    while True:
        digit = value & 0x7F
        value >>= 7
        result.append(digit | (0x80 if value == 0 else 0))
        if value == 0:
            return bytes(result)


def _compiled_nibarchive() -> bytes:
    objects: list[tuple[str, list[tuple[str, int, object]]]] = [
        ("NSArray", [("NSInlinedValue", 5, True), ("UINibEncoderEmptyKey", 10, 1)]),
        ("UIClassSwapper", [("UIClassName", 10, 6), ("UIOriginalClassName", 10, 7), ("UIView", 10, 2)]),
        ("UIView", [("UISubviews", 10, 3), ("UIFrame", 8, struct.pack("<4f", 0, 0, 240, 160))]),
        ("NSArray", [("NSInlinedValue", 5, True), ("UINibEncoderEmptyKey", 10, 4)]),
        ("UILabel", [("UILabelText", 10, 8), ("UIFrame", 8, struct.pack("<4f", 12, 14, 200, 30))]),
        ("UIRuntimeOutletConnection", [("UISource", 10, 1), ("UIDestination", 10, 4), ("UILabel", 10, 9)]),
        ("NSString", [("NS.bytes", 8, b"BinaryController")]),
        ("NSString", [("NS.bytes", 8, b"UIViewController")]),
        ("NSString", [("NS.bytes", 8, b"Binary text")]),
        ("NSString", [("NS.bytes", 8, b"binaryLabel")]),
        ("NSLayoutConstraint", [("UIFirstItem", 10, 4), ("UIFirstAttribute", 10, 11), ("UIConstant", 6, 200.0), ("UIPriority", 2, 1000)]),
        ("NSString", [("NS.bytes", 8, b"width")]),
    ]
    keys = list(dict.fromkeys(key for _, fields in objects for key, _, _ in fields))
    classes = list(dict.fromkeys(class_name for class_name, _ in objects))
    key_index = {name: index for index, name in enumerate(keys)}
    class_index = {name: index for index, name in enumerate(classes)}

    object_bytes = bytearray()
    value_bytes = bytearray()
    value_count = 0
    for class_name, fields in objects:
        object_bytes.extend(_vint32(class_index[class_name]))
        object_bytes.extend(_vint32(value_count))
        object_bytes.extend(_vint32(len(fields)))
        value_count += len(fields)
        for key, value_type, value in fields:
            value_bytes.extend(_vint32(key_index[key]))
            value_bytes.append(value_type)
            if value_type == 2:
                value_bytes.extend(int(value).to_bytes(4, "little", signed=True))
            elif value_type == 5:
                pass
            elif value_type == 6:
                value_bytes.extend(struct.pack("<f", float(value)))
            elif value_type == 8:
                raw = bytes(value)
                value_bytes.extend(_vint32(len(raw)))
                value_bytes.extend(raw)
            elif value_type == 10:
                value_bytes.extend(int(value).to_bytes(4, "little"))
            else:
                raise AssertionError(value_type)

    key_bytes = bytearray()
    for key in keys:
        raw = key.encode("utf-8")
        key_bytes.extend(_vint32(len(raw)))
        key_bytes.extend(raw)
    class_bytes = bytearray()
    for class_name in classes:
        raw = class_name.encode("utf-8") + b"\x00"
        class_bytes.extend(_vint32(len(raw)))
        class_bytes.extend(_vint32(0))
        class_bytes.extend(raw)

    object_offset = 50
    key_offset = object_offset + len(object_bytes)
    value_offset = key_offset + len(key_bytes)
    class_offset = value_offset + len(value_bytes)
    header = b"NIBArchive" + struct.pack(
        "<10I",
        1,
        10,
        len(objects),
        object_offset,
        len(keys),
        key_offset,
        value_count,
        value_offset,
        len(classes),
        class_offset,
    )
    return header + object_bytes + key_bytes + value_bytes + class_bytes + b"\x00\x00"


def _storyboard() -> bytes:
    return b"""<?xml version="1.0" encoding="UTF-8"?>
<document type="com.apple.InterfaceBuilder3.CocoaTouch.Storyboard.XIB" initialViewController="vc-main">
  <scenes>
    <scene sceneID="scene-main">
      <objects>
        <viewController id="vc-main" customClass="ExampleController" storyboardIdentifier="MainScreen">
          <view key="view" id="root-view">
            <rect key="frame" x="0" y="0" width="320" height="480"/>
            <subviews>
              <label id="title-label" text="WELCOME_KEY">
                <rect key="frame" x="20" y="30" width="280" height="40"/>
                <fontDescription key="fontDescription" type="system" pointSize="18"/>
                <color key="textColor" red="1" green="1" blue="1" alpha="1"/>
              </label>
              <imageView id="logo-view" image="logo.png">
                <rect key="frame" x="128" y="90" width="64" height="32"/>
              </imageView>
              <button id="continue-button" buttonType="roundedRect">
                <state key="normal" title="Continue"/>
                <connections>
                  <action selector="didTap:" destination="vc-main" eventType="touchUpInside" id="action-1"/>
                </connections>
              </button>
            </subviews>
            <constraints>
              <constraint firstItem="title-label" firstAttribute="top" secondItem="root-view" secondAttribute="top" constant="30" id="constraint-1"/>
            </constraints>
          </view>
          <connections>
            <outlet property="titleLabel" destination="title-label" id="outlet-1"/>
            <segue destination="vc-detail" kind="show" identifier="ShowDetail" id="segue-1"/>
          </connections>
        </viewController>
      </objects>
    </scene>
    <scene sceneID="scene-detail">
      <objects>
        <viewController id="vc-detail" customClass="DetailController" storyboardIdentifier="DetailScreen">
          <view key="view" id="detail-root">
            <rect key="frame" x="0" y="0" width="320" height="480"/>
          </view>
        </viewController>
      </objects>
    </scene>
  </scenes>
</document>
"""


def build_ui_workspace(root: Path, *, malformed: bool = False) -> Path:
    workspace = root / "workspace"
    analysis = workspace / "analysis"
    analysis.mkdir(parents=True)

    info = plistlib.dumps(
        {
            "CFBundleIdentifier": "test.ipalift.ui",
            "CFBundleExecutable": "Fixture",
            "UIMainStoryboardFile": "Main",
        },
        fmt=plistlib.FMT_BINARY,
        sort_keys=True,
    )
    records = [
        _file_record(workspace, "Payload/Fixture.app/Info.plist", info, None),
        _file_record(workspace, "Payload/Fixture.app/Main.storyboard", _storyboard(), "interface"),
        _file_record(workspace, "Payload/Fixture.app/Archive.nib", _keyed_nib(), "interface"),
        _file_record(workspace, "Payload/Fixture.app/Binary.nib", _compiled_nibarchive(), "interface"),
        _file_record(
            workspace,
            "Payload/Fixture.app/en.lproj/Main.strings",
            b'"WELCOME_KEY" = "Welcome";\n"title-label.text" = "Localized welcome";\n',
            "localization",
        ),
        _file_record(
            workspace,
            "Payload/Fixture.app/logo@2x.png",
            b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + struct_pack_dimensions(128, 64),
            "image",
        ),
    ]
    if malformed:
        records.append(
            _file_record(workspace, "Payload/Fixture.app/Broken.nib", b"not-an-interface", "interface")
        )
    assets = [item for item in records if item["asset_category"] is not None]
    write_json_atomic(
        analysis / "application.json",
        report_envelope(
            "application",
            {
                "bundle": {
                    "archive_root": "Payload/Fixture.app",
                    "bundle_identifier": "test.ipalift.ui",
                }
            },
        ),
    )
    write_json_atomic(
        analysis / "assets.json",
        report_envelope(
            "assets",
            {
                "file_count": len(records),
                "asset_count": len(assets),
                "total_uncompressed_bytes": sum(item["size"] for item in records),
                "category_counts": {},
                "files": records,
                "assets": assets,
            },
        ),
    )

    methods = [
        {
            "id": "method:did-tap",
            "class_name": "ExampleController",
            "selector": "didTap:",
            "function_id": "0x00001000",
        }
    ]
    classes = [
        {
            "name": "ExampleController",
            "superclass": {"name": "UIViewController"},
            "properties": [{"name": "titleLabel"}],
            "ivars": [],
        },
        {
            "name": "DetailController",
            "superclass": {"name": "UIViewController"},
            "properties": [],
            "ivars": [],
        },
        {
            "name": "ArchiveController",
            "superclass": {"name": "UIViewController"},
            "properties": [{"name": "archivedLabel"}],
            "ivars": [],
        },
        {
            "name": "CodeOnlyController",
            "superclass": {"name": "UIViewController"},
            "properties": [],
            "ivars": [],
        },
    ]
    recovered_functions = [
        {
            "function_id": "0x00001000",
            "method_ids": ["method:did-tap"],
            "referenced_assets": [{"path": "Payload/Fixture.app/logo@2x.png"}],
            "referenced_strings": [{"value": "Runtime title"}],
            "decompilation": {"status": "success", "output_path": None, "sha256": None, "message": None},
        }
    ]
    write_json_atomic(
        analysis / "functions.json",
        report_envelope("functions", {"discovered_function_count": 1, "functions": [{"id": "0x00001000"}]}),
    )
    write_json_atomic(
        analysis / "recovered-code-index.json",
        report_envelope(
            "recovered-code-index",
            {
                "objective_c_method_count": len(methods),
                "function_count": len(recovered_functions),
                "methods": methods,
                "classes": classes,
                "functions": recovered_functions,
            },
        ),
    )
    write_json_atomic(analysis / "objc-dispatch.json", report_envelope("objc-dispatch", {}))
    write_json_atomic(analysis / "objc-type-flow.json", report_envelope("objc-type-flow", {}))
    write_json_atomic(
        analysis / "platform-api-map.json",
        report_envelope(
            "platform-api-map",
            {
                "message_callsites": [{
                    "id": "platform-message:set-text",
                    "call_site": "0x00001020",
                    "caller_function_id": "0x00001000",
                    "selector": "setText:",
                    "classification": "exact",
                    "frameworks": ["UIKit"],
                    "categories": ["ui"],
                    "external_class_candidates": ["UILabel"],
                    "affected_method_ids": ["method:did-tap"],
                    "affected_class_names": ["ExampleController"],
                }]
            },
        ),
    )
    write_json_atomic(analysis / "native-type-flow.json", report_envelope("native-type-flow", {}))
    return workspace


def struct_pack_dimensions(width: int, height: int) -> bytes:
    return width.to_bytes(4, "big") + height.to_bytes(4, "big")


class UIRecoveryTests(unittest.TestCase):
    def test_recovers_xml_keyed_archive_resources_code_and_navigation_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = build_ui_workspace(Path(temporary))
            preserved = {
                path: path.read_bytes()
                for path in (workspace / "analysis").glob("*.json")
            }
            first = recover_ui(workspace)
            first_model = first.ui_model_path.read_bytes()
            first_report = first.report_path.read_bytes()
            second = recover_ui(workspace)

            self.assertEqual(first_model, second.ui_model_path.read_bytes())
            self.assertEqual(first_report, second.report_path.read_bytes())
            for path, contents in preserved.items():
                self.assertEqual(contents, path.read_bytes(), path)

            facts = second.ui_model["facts"]
            self.assertEqual(3, facts["summary"]["interface_artifact_count"])
            self.assertEqual(5, facts["summary"]["screen_count"])
            self.assertGreaterEqual(facts["summary"]["element_count"], 9)
            self.assertEqual(0, facts["summary"]["error_count"])
            formats = {item["format"] for item in facts["interface_artifacts"]}
            self.assertEqual({"interface_builder_xml", "nskeyedarchiver", "nibarchive"}, formats)

            screens = {item["controller_class_name"]: item for item in facts["screens"]}
            self.assertEqual("main", screens["ExampleController"]["entry_point_kind"])
            self.assertEqual("candidate_set", screens["CodeOnlyController"]["classification"])
            self.assertIn("controller_class_does_not_prove_a_runtime_screen_instance", screens["CodeOnlyController"]["failure_reasons"])
            self.assertEqual("exact", screens["BinaryController"]["classification"])
            binary_label = next(item for item in facts["elements"] if item["class_name"] == "UILabel" and item["frame"] and item["frame"]["width"] == 200.0)
            self.assertEqual("Binary text", binary_label["attributes"]["UILabelText"])
            self.assertEqual([], next(item for item in facts["interface_artifacts"] if item["format"] == "nibarchive")["issue_codes"])

            title = next(item for item in facts["elements"] if item["source_object_id"] == "title-label")
            self.assertEqual({"x": 20.0, "y": 30.0, "width": 280.0, "height": 40.0}, {key: title["frame"][key] for key in ("x", "y", "width", "height")})
            title_references = [
                item for item in facts["resource_references"]
                if item["element_id"] == title["id"] and item["kind"] == "text"
            ]
            self.assertTrue(any(item["localization_entry_ids"] for item in title_references))

            image_reference = next(
                item for item in facts["resource_references"]
                if item["kind"] == "image" and item["requested_value"] == "logo.png"
            )
            self.assertEqual("exact", image_reference["classification"])
            image = next(item for item in facts["assets"] if item["id"] in image_reference["asset_candidate_ids"])
            self.assertEqual({"width": 128, "height": 64}, image["pixel_size"])
            self.assertEqual({"width": 64.0, "height": 32.0}, image["logical_size"])

            action = next(item for item in facts["connections"] if item["selector"] == "didTap:")
            self.assertEqual("exact", action["code_matches"][0]["classification"])
            outlet = next(item for item in facts["connections"] if item["label"] == "titleLabel")
            self.assertEqual("exact", outlet["code_matches"][0]["classification"])
            archived_outlet = next(item for item in facts["connections"] if item["label"] == "archivedLabel")
            self.assertEqual("exact", archived_outlet["code_matches"][0]["classification"])
            navigation = facts["navigation_edges"][0]
            self.assertEqual("exact", navigation["classification"])
            self.assertEqual(screens["DetailController"]["id"], navigation["destination_screen_id"])
            self.assertEqual("exact", facts["code_operations"][0]["classification"])
            self.assertEqual([screens["ExampleController"]["id"]], facts["code_operations"][0]["screen_candidate_ids"])
            self.assertFalse(facts["evidence_boundary"]["application_specific_rules_used"])

            schema_root = Path(__file__).parents[1] / "schemas"
            registry = Registry()
            for schema_path in schema_root.glob("*.schema.json"):
                contents = json.loads(schema_path.read_text(encoding="utf-8"))
                resource = Resource.from_contents(contents)
                registry = registry.with_resource(contents["$id"], resource)
                registry = registry.with_resource(schema_path.name, resource)
            schema = json.loads((schema_root / "ui-model.schema.json").read_text(encoding="utf-8"))
            Draft202012Validator(schema, registry=registry).validate(second.ui_model)

    def test_compiled_nibarchive_rejects_invalid_table_offsets(self) -> None:
        malformed = bytearray(_compiled_nibarchive())
        struct.pack_into("<I", malformed, 22, 51)
        with self.assertRaisesRegex(NIBArchiveError, "object table begins"):
            decode_nibarchive(bytes(malformed))

    def test_malformed_interface_is_reported_without_discarding_decoded_screens(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = build_ui_workspace(Path(temporary), malformed=True)
            result = recover_ui(workspace)
            self.assertEqual(1, result.ui_model["facts"]["summary"]["error_count"])
            self.assertEqual("interface_decode_failed", result.ui_model["errors"][0]["code"])
            self.assertTrue(result.ui_model["facts"]["screens"])

    def test_rejects_extracted_evidence_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = build_ui_workspace(Path(temporary))
            path = workspace / "analysis" / "assets.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            interface = next(item for item in document["facts"]["files"] if item["extension"] == ".storyboard")
            interface["path"] = "../outside.storyboard"
            write_json_atomic(path, document)
            with self.assertRaisesRegex(UIRecoveryError, "escapes the analysis workspace"):
                recover_ui(workspace)

    def test_rejects_missing_prerequisite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(UIRecoveryError, "missing analysis/application.json"):
                recover_ui(Path(temporary))

    def test_cli_exposes_recover_ui(self) -> None:
        args = build_parser().parse_args(["recover-ui", "workspace"])
        self.assertEqual("recover-ui", args.command)
        self.assertEqual(Path("workspace"), args.workspace)


if __name__ == "__main__":
    unittest.main()
