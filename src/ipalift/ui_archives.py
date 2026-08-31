"""Safe, deterministic decoders for Interface Builder XML and compiled NIB archives."""

from __future__ import annotations

import math
import plistlib
import re
import struct
import xml.etree.ElementTree as ET
from pathlib import PurePosixPath
from typing import Any, Iterable

from .nibarchive import NIBArchiveError, decode_nibarchive


MAX_INTERFACE_BYTES = 64 * 1024 * 1024
MAX_XML_ELEMENTS = 100_000
MAX_ARCHIVE_OBJECTS = 200_000
MAX_ARCHIVE_DEPTH = 64
_NUMBER = re.compile(r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?")
_CONTROLLER_TAGS = {
    "collectionViewController",
    "navigationController",
    "pageViewController",
    "splitViewController",
    "tabBarController",
    "tableViewController",
    "viewController",
}
_CONNECTION_TAGS = {"action", "outlet", "outletCollection", "segue"}
_PROPERTY_TAGS = {"color", "fontDescription", "inset", "point", "rect", "size", "state"}
_ARCHIVE_CHILD_KEYS = {
    "NS.objects",
    "UIChildViewControllers",
    "UIItems",
    "UINavigationItems",
    "UISubviews",
    "UIView",
    "UIViewControllers",
}


class InterfaceDecodeError(ValueError):
    """An interface artifact cannot be decoded safely or consistently."""


def _local_name(value: str) -> str:
    return value.rsplit("}", 1)[-1]


def _stable_scalar(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return {"byte_count": len(value), "encoding": "opaque"}
    if isinstance(value, plistlib.UID):
        return {"archive_reference": value.data}
    if isinstance(value, (list, tuple)):
        return [_stable_scalar(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _stable_scalar(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    return str(value)


def _geometry(value: Any) -> dict[str, Any] | None:
    raw = value
    values: list[float] = []
    if isinstance(value, str):
        values = [float(item) for item in _NUMBER.findall(value)]
    elif isinstance(value, (list, tuple)):
        try:
            values = [float(item) for item in value]
        except (TypeError, ValueError):
            values = []
    elif isinstance(value, dict):
        lowered = {str(key).lower(): item for key, item in value.items()}
        keys = ("x", "y", "width", "height")
        if all(key in lowered for key in keys):
            try:
                values = [float(lowered[key]) for key in keys]
            except (TypeError, ValueError):
                values = []
        else:
            for key in ("ns.rectval", "uirect", "value"):
                if key in lowered:
                    return _geometry(lowered[key])
    elif isinstance(value, bytes):
        formats = {16: "<4f", 32: "<4d"}
        if len(value) in formats:
            values = list(struct.unpack(formats[len(value)], value))
    if len(values) < 4:
        return None
    x, y, width, height = values[-4:]
    if not all(math.isfinite(item) and abs(item) <= 1_000_000_000 for item in (x, y, width, height)):
        return None
    return {
        "x": x,
        "y": y,
        "width": width,
        "height": height,
        "raw": _stable_scalar(raw),
    }


def _xml_property(element: ET.Element) -> dict[str, Any]:
    tag = _local_name(element.tag)
    value: dict[str, Any] = {"kind": tag}
    value.update({key: item for key, item in sorted(element.attrib.items())})
    if element.text and element.text.strip():
        value["value"] = element.text.strip()
    return value


def _decode_xml(relative_path: str, data: bytes, element_tags: dict[str, str]) -> dict[str, Any]:
    prefix = data[:4096].upper()
    if b"<!DOCTYPE" in prefix or b"<!ENTITY" in prefix:
        raise InterfaceDecodeError("Interface XML contains a forbidden DTD or entity declaration")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise InterfaceDecodeError(f"Malformed Interface Builder XML: {exc}") from exc
    elements = list(root.iter())
    if len(elements) > MAX_XML_ELEMENTS:
        raise InterfaceDecodeError(
            f"Interface XML contains {len(elements)} elements; limit is {MAX_XML_ELEMENTS}"
        )

    nodes: list[dict[str, Any]] = []
    connections: list[dict[str, Any]] = []
    constraints: list[dict[str, Any]] = []
    generated = 0

    def walk(
        element: ET.Element,
        parent_object: str | None,
        controller: str | None,
    ) -> None:
        nonlocal generated
        tag = _local_name(element.tag)
        native_id = element.attrib.get("id")
        mapped_class = element_tags.get(tag)
        custom_class = element.attrib.get("customClass")
        is_controller = tag in _CONTROLLER_TAGS or (
            (custom_class or mapped_class or "").endswith("ViewController")
        )
        is_object = mapped_class is not None or is_controller
        current_object = parent_object
        current_controller = controller
        if is_object:
            if not native_id:
                generated += 1
                native_id = f"xml:auto:{generated:06d}"
            current_object = native_id
            if is_controller:
                current_controller = native_id
            properties: dict[str, Any] = {}
            for child in element:
                child_tag = _local_name(child.tag)
                if child_tag in _PROPERTY_TAGS:
                    key = child.attrib.get("key") or child_tag
                    candidate = _xml_property(child)
                    if key in properties:
                        prior = properties[key]
                        properties[key] = prior + [candidate] if isinstance(prior, list) else [prior, candidate]
                    else:
                        properties[key] = candidate
            frame = None
            bounds = None
            for child in element:
                if _local_name(child.tag) != "rect":
                    continue
                parsed = _geometry({key: child.attrib.get(key) for key in ("x", "y", "width", "height")})
                if child.attrib.get("key") == "frame":
                    frame = parsed
                elif child.attrib.get("key") == "bounds":
                    bounds = parsed
            nodes.append({
                "native_id": native_id,
                "tag": tag,
                "class_name": custom_class or mapped_class or tag,
                "base_class_name": mapped_class,
                "custom_class": custom_class,
                "role": "controller" if is_controller else "element",
                "attributes": {
                    key: value for key, value in sorted(element.attrib.items())
                    if key not in {"id", "customClass"}
                },
                "properties": properties,
                "frame": frame,
                "bounds": bounds,
                "parent_native_id": parent_object,
                "controller_native_id": current_controller,
                "child_native_ids": [],
            })

        if tag in _CONNECTION_TAGS:
            generated += 1
            connection_id = native_id or f"xml:connection:{generated:06d}"
            kind = "action" if tag == "action" else "outlet" if tag.startswith("outlet") else "segue"
            connections.append({
                "native_id": connection_id,
                "kind": kind,
                "subkind": element.attrib.get("kind") or tag,
                "source_native_id": parent_object,
                "destination_native_id": element.attrib.get("destination"),
                "label": element.attrib.get("property") or element.attrib.get("identifier"),
                "selector": element.attrib.get("selector"),
                "event": element.attrib.get("eventType"),
                "attributes": {key: value for key, value in sorted(element.attrib.items())},
            })
        elif tag == "constraint":
            generated += 1
            constraints.append({
                "native_id": native_id or f"xml:constraint:{generated:06d}",
                "owner_native_id": parent_object,
                "first_item_native_id": element.attrib.get("firstItem") or parent_object,
                "second_item_native_id": element.attrib.get("secondItem"),
                "first_attribute": element.attrib.get("firstAttribute"),
                "second_attribute": element.attrib.get("secondAttribute"),
                "relation": element.attrib.get("relation", "equal"),
                "constant": element.attrib.get("constant"),
                "multiplier": element.attrib.get("multiplier"),
                "priority": element.attrib.get("priority"),
                "attributes": {key: value for key, value in sorted(element.attrib.items())},
            })

        for child in element:
            walk(child, current_object, current_controller)

    walk(root, None, None)
    node_by_id = {item["native_id"]: item for item in nodes}
    for node in nodes:
        parent_id = node["parent_native_id"]
        if parent_id in node_by_id:
            node_by_id[parent_id]["child_native_ids"].append(node["native_id"])
    for node in nodes:
        node["child_native_ids"].sort()
    nodes.sort(key=lambda item: item["native_id"])
    connections.sort(key=lambda item: item["native_id"])
    constraints.sort(key=lambda item: item["native_id"])
    suffix = PurePosixPath(relative_path).suffix.lower()
    return {
        "format": "interface_builder_xml",
        "source_kind": "storyboard" if suffix == ".storyboard" else "xib_or_nib_xml",
        "initial_controller_native_id": root.attrib.get("initialViewController"),
        "top_level_native_ids": sorted(
            item["native_id"] for item in nodes if item["parent_native_id"] is None
        ),
        "nodes": nodes,
        "connections": connections,
        "constraints": constraints,
        "manifest": {},
        "issues": [],
    }


def _uid(value: Any) -> int | None:
    return value.data if isinstance(value, plistlib.UID) else None


class _KeyedArchive:
    def __init__(self, document: dict[str, Any]):
        objects = document.get("$objects")
        top = document.get("$top")
        if not isinstance(objects, list) or not isinstance(top, dict):
            raise InterfaceDecodeError("Keyed interface archive is missing $objects or $top")
        if len(objects) > MAX_ARCHIVE_OBJECTS:
            raise InterfaceDecodeError(
                f"Keyed interface archive contains {len(objects)} objects; limit is {MAX_ARCHIVE_OBJECTS}"
            )
        self.objects = objects
        self.top = top

    def object(self, value: Any) -> Any:
        index = _uid(value)
        if index is None:
            return value
        if index < 0 or index >= len(self.objects):
            raise InterfaceDecodeError(f"Keyed interface archive reference is out of range: {index}")
        return self.objects[index]

    def class_name(self, value: Any) -> str | None:
        item = self.object(value)
        if not isinstance(item, dict):
            return None
        class_index = _uid(item.get("$class"))
        if class_index is None or class_index < 0 or class_index >= len(self.objects):
            return None
        class_record = self.objects[class_index]
        if not isinstance(class_record, dict):
            return None
        name = class_record.get("$classname")
        return str(name) if isinstance(name, str) and name else None

    def scalar(self, value: Any, depth: int = 0, seen: frozenset[int] = frozenset()) -> Any:
        if depth > MAX_ARCHIVE_DEPTH:
            return None
        index = _uid(value)
        if index is None:
            if isinstance(value, dict):
                return {
                    str(key): self.scalar(item, depth + 1, seen)
                    for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
                    if key != "$class"
                }
            if isinstance(value, (list, tuple)):
                return [self.scalar(item, depth + 1, seen) for item in value]
            return value
        if index in seen:
            return {"archive_reference": index}
        item = self.object(value)
        class_name = self.class_name(value) or ""
        next_seen = seen | {index}
        if class_name in {"NSString", "NSMutableString"} and isinstance(item, dict):
            return self.scalar(item.get("NS.string"), depth + 1, next_seen)
        if class_name in {"NSNumber", "NSCFNumber", "__NSCFBoolean"} and isinstance(item, dict):
            for key in ("NS.boolval", "NS.intval", "NS.integer", "NS.real", "NS.floatval", "NS.doubleval"):
                if key in item:
                    return self.scalar(item[key], depth + 1, next_seen)
        if class_name in {"NSArray", "NSMutableArray", "NSSet", "NSMutableSet", "NSOrderedSet"} and isinstance(item, dict):
            return self.scalar(item.get("NS.objects", []), depth + 1, next_seen)
        if class_name in {"NSDictionary", "NSMutableDictionary"} and isinstance(item, dict):
            keys = self.scalar(item.get("NS.keys", []), depth + 1, next_seen)
            values = self.scalar(item.get("NS.objects", []), depth + 1, next_seen)
            if isinstance(keys, list) and isinstance(values, list) and len(keys) == len(values):
                return {str(key): values[position] for position, key in enumerate(keys)}
        if isinstance(item, (str, int, float, bool, bytes)) or item is None:
            return item
        return {"archive_reference": index}

    def references(self, value: Any, depth: int = 0, seen: frozenset[int] = frozenset()) -> list[int]:
        if depth > MAX_ARCHIVE_DEPTH:
            return []
        index = _uid(value)
        if index is not None:
            if index in seen:
                return []
            item = self.object(value)
            class_name = self.class_name(value) or ""
            if class_name in {"NSArray", "NSMutableArray", "NSSet", "NSMutableSet", "NSOrderedSet"} and isinstance(item, dict):
                return self.references(item.get("NS.objects", []), depth + 1, seen | {index})
            return [index]
        if isinstance(value, (list, tuple)):
            return sorted({
                index
                for item in value
                for index in self.references(item, depth + 1, seen)
            })
        return []

    def first_reference(self, item: dict[str, Any], keys: Iterable[str]) -> int | None:
        lowered = {str(key).lower(): key for key in item}
        for requested in keys:
            actual = lowered.get(requested.lower())
            if actual is None:
                continue
            references = self.references(item[actual])
            if references:
                return references[0]
        return None

    def first_scalar(self, item: dict[str, Any], keys: Iterable[str]) -> Any:
        lowered = {str(key).lower(): key for key in item}
        for requested in keys:
            actual = lowered.get(requested.lower())
            if actual is not None:
                return self.scalar(item[actual])
        return None


def _archive_text(value: Any) -> str | None:
    if isinstance(value, str):
        return value or None
    if isinstance(value, bytes):
        raw = value[:-1] if value.endswith(b"\x00") else value
        for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
            try:
                decoded = raw.decode(encoding)
            except (UnicodeDecodeError, UnicodeError):
                continue
            if decoded and "\x00" not in decoded:
                return decoded
    return None


def _archive_class_identity(
    archive: _KeyedArchive,
    index: int,
) -> tuple[str, str | None, str | None]:
    encoded = archive.class_name(plistlib.UID(index)) or "UnknownArchiveClass"
    item = archive.objects[index]
    if isinstance(item, dict) and "ClassSwapper" in encoded:
        custom = _archive_text(archive.first_scalar(item, ("UIClassName", "className")))
        original = _archive_text(
            archive.first_scalar(item, ("UIOriginalClassName", "originalClassName"))
        )
        if custom:
            return custom, original or None, custom
    return encoded, encoded if encoded.startswith("UI") else None, None if encoded.startswith("UI") else encoded


def _archive_is_controller(class_name: str, controller_classes: set[str], fields: set[str]) -> bool:
    return (
        class_name in controller_classes
        or class_name.endswith("ViewController")
        or ("UIView" in fields and any(key.startswith("UI") for key in fields))
    )


def _archive_is_node(class_name: str, controller: bool, fields: set[str]) -> bool:
    if controller:
        return True
    excluded = ("Connection", "Constraint", "Segue", "Proxy", "Nib", "Storyboard", "ClassSwapper")
    if any(value in class_name for value in excluded):
        return False
    if class_name.startswith(("UIView", "UIControl", "UILabel", "UIButton", "UIImageView", "UIWindow")):
        return True
    return bool(fields & {"UISubviews", "UIFrame", "UIBounds", "UIConstraints"})


def _decode_keyed_archive(
    document: dict[str, Any],
    controller_classes: set[str],
) -> dict[str, Any]:
    archive = _KeyedArchive(document)
    node_indexes: set[int] = set()
    controller_indexes: set[int] = set()
    for index, item in enumerate(archive.objects):
        if not isinstance(item, dict) or "$class" not in item:
            continue
        class_name, base_class_name, _ = _archive_class_identity(archive, index)
        fields = {str(key) for key in item if key != "$class"}
        controller = _archive_is_controller(class_name, controller_classes, fields) or (
            base_class_name is not None
            and _archive_is_controller(base_class_name, controller_classes, fields)
        )
        if _archive_is_node(class_name, controller, fields):
            node_indexes.add(index)
            if controller:
                controller_indexes.add(index)

    children: dict[int, set[int]] = {index: set() for index in node_indexes}
    for index in sorted(node_indexes):
        item = archive.objects[index]
        assert isinstance(item, dict)
        for key, value in item.items():
            if key not in _ARCHIVE_CHILD_KEYS:
                continue
            children[index].update(
                child for child in archive.references(value) if child in node_indexes and child != index
            )
    parents: dict[int, list[int]] = {index: [] for index in node_indexes}
    for parent, values in children.items():
        for child in values:
            parents[child].append(parent)

    controller_for: dict[int, int | None] = {index: None for index in node_indexes}
    for controller in sorted(controller_indexes):
        stack = list(sorted(children[controller], reverse=True))
        while stack:
            current = stack.pop()
            if current in controller_indexes:
                continue
            if controller_for[current] is None:
                controller_for[current] = controller
                stack.extend(sorted(children[current], reverse=True))

    nodes: list[dict[str, Any]] = []
    for index in sorted(node_indexes):
        item = archive.objects[index]
        assert isinstance(item, dict)
        class_name, base_class_name, custom_class = _archive_class_identity(archive, index)
        scalar_fields: dict[str, Any] = {}
        for key, value in sorted(item.items(), key=lambda pair: str(pair[0])):
            if key == "$class":
                continue
            scalar = archive.scalar(value)
            if not (isinstance(scalar, dict) and set(scalar) == {"archive_reference"}):
                scalar_fields[str(key)] = _stable_scalar(scalar)
        frame = None
        bounds = None
        for key, value in item.items():
            lowered = str(key).lower()
            parsed = _geometry(archive.scalar(value))
            if parsed is None:
                continue
            if "frame" in lowered and frame is None:
                frame = parsed
            elif "bounds" in lowered and bounds is None:
                bounds = parsed
        parent = min(parents[index]) if parents[index] else None
        nodes.append({
            "native_id": f"archive:{index}",
            "tag": None,
            "class_name": class_name,
            "base_class_name": base_class_name,
            "custom_class": custom_class,
            "role": "controller" if index in controller_indexes else "element",
            "attributes": scalar_fields,
            "properties": {},
            "frame": frame,
            "bounds": bounds,
            "parent_native_id": f"archive:{parent}" if parent is not None else None,
            "controller_native_id": (
                f"archive:{index}" if index in controller_indexes
                else f"archive:{controller_for[index]}" if controller_for[index] is not None
                else None
            ),
            "child_native_ids": [f"archive:{child}" for child in sorted(children[index])],
        })

    connections: list[dict[str, Any]] = []
    constraints: list[dict[str, Any]] = []
    for index, item in enumerate(archive.objects):
        if not isinstance(item, dict) or "$class" not in item:
            continue
        class_name = archive.class_name(plistlib.UID(index)) or ""
        if "Connection" in class_name or "Segue" in class_name:
            if "Outlet" in class_name:
                kind = "outlet"
            elif "Event" in class_name or "Action" in class_name:
                kind = "action"
            else:
                kind = "segue"
            source = archive.first_reference(item, ("UISource", "source"))
            destination = archive.first_reference(
                item, ("UIDestination", "destination", "UIDestinationViewController")
            )
            connections.append({
                "native_id": f"archive:{index}",
                "kind": kind,
                "subkind": class_name,
                "source_native_id": f"archive:{source}" if source is not None else None,
                "destination_native_id": f"archive:{destination}" if destination is not None else None,
                "label": archive.first_scalar(
                    item, ("UILabel", "UIOutletName", "UIIdentifier", "property", "label")
                ),
                "selector": archive.first_scalar(item, ("UIActionName", "selector")),
                "event": archive.first_scalar(item, ("UIEventMask", "event")),
                "attributes": {
                    str(key): _stable_scalar(archive.scalar(value))
                    for key, value in sorted(item.items(), key=lambda pair: str(pair[0]))
                    if key != "$class"
                },
            })
        if "Constraint" in class_name:
            first = archive.first_reference(item, ("UIFirstItem", "NSFirstItem", "firstItem"))
            second = archive.first_reference(item, ("UISecondItem", "NSSecondItem", "secondItem"))
            constraints.append({
                "native_id": f"archive:{index}",
                "owner_native_id": None,
                "first_item_native_id": f"archive:{first}" if first is not None else None,
                "second_item_native_id": f"archive:{second}" if second is not None else None,
                "first_attribute": archive.first_scalar(item, ("UIFirstAttribute", "firstAttribute")),
                "second_attribute": archive.first_scalar(item, ("UISecondAttribute", "secondAttribute")),
                "relation": archive.first_scalar(item, ("UIRelation", "relation")),
                "constant": archive.first_scalar(item, ("UIConstant", "constant")),
                "multiplier": archive.first_scalar(item, ("UIMultiplier", "multiplier")),
                "priority": archive.first_scalar(item, ("UIPriority", "priority")),
                "attributes": {
                    str(key): _stable_scalar(archive.scalar(value))
                    for key, value in sorted(item.items(), key=lambda pair: str(pair[0]))
                    if key != "$class"
                },
            })

    top_level = sorted({
        f"archive:{index}"
        for value in archive.top.values()
        for index in archive.references(value)
        if index in node_indexes
    })
    if not top_level:
        top_level = sorted(
            f"archive:{index}" for index in node_indexes if not parents[index]
        )
    initial = None
    for key, value in sorted(archive.top.items()):
        if "initial" in str(key).lower() or "entry" in str(key).lower():
            refs = archive.references(value)
            if refs and refs[0] in controller_indexes:
                initial = f"archive:{refs[0]}"
                break
    return {
        "format": "nskeyedarchiver",
        "source_kind": "compiled_nib",
        "initial_controller_native_id": initial,
        "top_level_native_ids": top_level,
        "nodes": sorted(nodes, key=lambda item: item["native_id"]),
        "connections": sorted(connections, key=lambda item: item["native_id"]),
        "constraints": sorted(constraints, key=lambda item: item["native_id"]),
        "manifest": {},
        "issues": [],
    }


def _storyboard_manifest(document: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "UIStoryboardDesignatedEntryPointIdentifier",
        "UIViewControllerIdentifiersToNibNames",
        "UIStoryboardVersion",
        "UIStoryboardIdentifierToNibNameMap",
    )
    return {key: _stable_scalar(document[key]) for key in keys if key in document}


def decode_interface_artifact(
    relative_path: str,
    data: bytes,
    catalog: dict[str, Any],
) -> dict[str, Any]:
    """Decode one bundle interface file into a normalized, source-local graph."""
    if len(data) > MAX_INTERFACE_BYTES:
        raise InterfaceDecodeError(
            f"Interface artifact is {len(data)} bytes; limit is {MAX_INTERFACE_BYTES}"
        )
    stripped = data.lstrip()
    element_tags = {
        str(key): str(value) for key, value in catalog.get("element_tags", {}).items()
    }
    controller_classes = {
        str(value) for value in catalog.get("controller_classes", [])
    }
    if stripped.startswith(b"<"):
        return _decode_xml(relative_path, data, element_tags)
    if data.startswith(b"NIBArchive"):
        try:
            archive = decode_nibarchive(data)
        except NIBArchiveError as exc:
            raise InterfaceDecodeError(f"Malformed compiled NIBArchive: {exc}") from exc
        decoded = _decode_keyed_archive(archive.document, controller_classes)
        decoded["format"] = "nibarchive"
        decoded["manifest"] = {
            "format_version": archive.format_version,
            "coder_version": archive.coder_version,
            "object_count": archive.object_count,
            "key_count": archive.key_count,
            "value_count": archive.value_count,
            "class_count": archive.class_count,
            "trailing_byte_count": archive.trailing_byte_count,
        }
        return decoded
    try:
        document = plistlib.loads(data)
    except plistlib.InvalidFileException as exc:
        raise InterfaceDecodeError(f"Interface artifact is neither XML nor a property-list archive: {exc}") from exc
    if not isinstance(document, dict):
        raise InterfaceDecodeError("Interface property list has a non-dictionary root")
    if "$objects" in document and "$top" in document:
        return _decode_keyed_archive(document, controller_classes)
    if relative_path.replace("\\", "/").lower().endswith(".storyboardc/info.plist"):
        return {
            "format": "storyboard_manifest",
            "source_kind": "compiled_storyboard_manifest",
            "initial_controller_native_id": None,
            "top_level_native_ids": [],
            "nodes": [],
            "connections": [],
            "constraints": [],
            "manifest": _storyboard_manifest(document),
            "issues": [],
        }
    raise InterfaceDecodeError("Interface property list is not an NSKeyedArchiver archive")
