"""Deterministic, evidence-bounded interaction and behavior recovery."""

from __future__ import annotations

import hashlib
import importlib.resources
import json
import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .errors import IPALiftError
from .util import report_envelope, sha256_file, write_json_atomic, write_text_atomic


class InteractionRecoveryError(IPALiftError):
    """A workspace cannot support trustworthy interaction recovery."""


@dataclass(frozen=True)
class InteractionRecoveryResult:
    workspace: Path
    interaction_model: dict[str, Any]
    interaction_model_path: Path
    report_path: Path


REQUIRED_REPORTS = (
    "functions",
    "callgraph",
    "recovered-code-index",
    "objc-dispatch",
    "platform-api-map",
    "native-type-flow",
    "ui-model",
)
CLASSIFICATIONS = ("exact", "candidate_set", "unresolved")
TRIGGER_KINDS = ("ui_action", "lifecycle", "delegate", "notification", "timer", "callback")
EFFECT_KINDS = (
    "state_read",
    "state_write",
    "navigation",
    "ui_update",
    "persistence_read",
    "persistence_write",
    "persistence_access",
    "network_request",
    "notification_post",
    "timer_schedule",
    "platform_api",
)
_ADDRESS = re.compile(r"^0x[0-9a-f]+$")
_ASSIGNMENT = re.compile(r"(?<![=!<>])=(?!=)")
_QUOTED = re.compile(r'@?"((?:\\.|[^"\\])*)"')
_NUMBER_LITERAL = re.compile(r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?")


def _load_report(workspace: Path, name: str) -> dict[str, Any]:
    path = workspace / "analysis" / f"{name}.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise InteractionRecoveryError(f"Analysis workspace is missing analysis/{name}.json") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise InteractionRecoveryError(f"Cannot read {path}: {exc}") from exc
    if (
        document.get("schema_version") != 1
        or document.get("artifact") != name
        or not isinstance(document.get("facts"), dict)
        or not isinstance(document.get("hypotheses"), list)
        or not isinstance(document.get("errors"), list)
    ):
        raise InteractionRecoveryError(f"Invalid IPALift {name} report: {path}")
    return document


def _relative_file(workspace: Path, relative: str) -> Path:
    portable = relative.replace("\\", "/")
    parts = portable.split("/")
    if (
        not portable
        or portable.startswith("/")
        or re.match(r"^[A-Za-z]:", portable)
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise InteractionRecoveryError(f"Artifact path escapes the analysis workspace: {relative}")
    candidate = (workspace / Path(*parts)).resolve()
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise InteractionRecoveryError(f"Artifact path escapes the analysis workspace: {relative}") from exc
    return candidate


def _stable_id(kind: str, *parts: Any) -> str:
    identity = "\0".join([kind, *(str(part) for part in parts)])
    return f"{kind}:{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:20]}"


def _address_key(value: str | None) -> tuple[int, str]:
    if value and _ADDRESS.match(value):
        return (0, f"{int(value, 16):016x}")
    return (1, value or "")


def _classification(*values: str) -> str:
    normalized = [value for value in values if value in CLASSIFICATIONS]
    if "unresolved" in normalized:
        return "unresolved"
    if "candidate_set" in normalized:
        return "candidate_set"
    return "exact"


def _confidence(classification: str) -> str:
    return {"exact": "high", "candidate_set": "medium", "unresolved": "low"}[classification]


def _evidence(
    kind: str,
    source: str,
    *,
    basis: str,
    confidence: str = "high",
    source_object: str | None = None,
    field: str | None = None,
    source_address: str | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "source": source,
        "source_object": source_object,
        "field": field,
        "source_address": source_address,
        "confidence": confidence,
        "basis": basis,
        "details": details or {},
    }


def _load_catalog() -> tuple[dict[str, Any], str]:
    resource = importlib.resources.files("ipalift").joinpath("catalogs/interaction-apis-v1.json")
    try:
        data = resource.read_bytes()
        document = json.loads(data.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InteractionRecoveryError(f"Cannot load the interaction API catalog: {exc}") from exc
    required = {
        "catalog_id",
        "catalog_version",
        "description",
        "bounds",
        "lifecycle_selectors",
        "notification_registrations",
        "notification_posts",
        "timer_registrations",
        "callback_registrations",
        "effect_selectors",
        "imported_effects",
    }
    if not isinstance(document, dict) or set(document) != required:
        raise InteractionRecoveryError("Interaction API catalog has an invalid top-level shape")
    if document["catalog_id"] != "ipalift-interaction-apis":
        raise InteractionRecoveryError("Interaction API catalog has an unexpected identity")
    bounds = document.get("bounds")
    expected_bounds = {
        "max_call_depth",
        "max_functions_per_slice",
        "max_edges_per_slice",
        "max_pseudocode_bytes_per_function",
        "max_total_pseudocode_bytes",
    }
    if (
        not isinstance(bounds, dict)
        or set(bounds) != expected_bounds
        or any(not isinstance(bounds[key], int) or bounds[key] <= 0 for key in expected_bounds)
    ):
        raise InteractionRecoveryError("Interaction API catalog has invalid resource bounds")
    for collection in (
        "lifecycle_selectors",
        "notification_registrations",
        "notification_posts",
        "timer_registrations",
        "callback_registrations",
        "effect_selectors",
        "imported_effects",
    ):
        if not isinstance(document.get(collection), list) or not all(
            isinstance(item, dict) for item in document[collection]
        ):
            raise InteractionRecoveryError(f"Interaction API catalog has invalid {collection}")
    for collection in (
        "lifecycle_selectors",
        "notification_registrations",
        "notification_posts",
        "timer_registrations",
        "callback_registrations",
        "effect_selectors",
    ):
        selectors = [str(item.get("selector") or "") for item in document[collection]]
        if not all(selectors) or len(selectors) != len(set(selectors)):
            raise InteractionRecoveryError(f"Interaction API catalog has duplicate or empty {collection}")
    imported = [str(item.get("symbol") or "") for item in document["imported_effects"]]
    if not all(imported) or len(imported) != len(set(imported)):
        raise InteractionRecoveryError("Interaction API catalog has duplicate or empty imported effects")
    return document, hashlib.sha256(data).hexdigest()


def _input_artifacts(workspace: Path, names: Iterable[str]) -> list[dict[str, Any]]:
    return [
        {
            "artifact": name,
            "path": f"analysis/{name}.json",
            "sha256": sha256_file(workspace / "analysis" / f"{name}.json"),
        }
        for name in sorted(names)
    ]


def _unique_records(records: Iterable[dict[str, Any]], key: str, source: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for record in records:
        identity = str(record.get(key) or "")
        if not identity:
            continue
        if identity in result:
            raise InteractionRecoveryError(f"Duplicate {key} {identity!r} in {source}")
        result[identity] = record
    return result


def _load_pseudocode(
    workspace: Path,
    recovered_functions: list[dict[str, Any]],
    bounds: dict[str, int],
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    code_by_function: dict[str, str] = {}
    artifacts: list[dict[str, Any]] = []
    total = 0
    for function in sorted(recovered_functions, key=lambda item: str(item.get("function_id") or "")):
        function_id = str(function.get("function_id") or "")
        decompilation = function.get("decompilation") or {}
        if decompilation.get("status") != "success" or not decompilation.get("output_path"):
            continue
        relative = str(decompilation["output_path"])
        path = _relative_file(workspace, relative)
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise InteractionRecoveryError(f"Cannot stat pseudocode artifact {relative}: {exc}") from exc
        if size > bounds["max_pseudocode_bytes_per_function"]:
            raise InteractionRecoveryError(
                f"Pseudocode artifact {relative} is {size} bytes; limit is "
                f"{bounds['max_pseudocode_bytes_per_function']}"
            )
        total += size
        if total > bounds["max_total_pseudocode_bytes"]:
            raise InteractionRecoveryError(
                f"Pseudocode artifacts total more than {bounds['max_total_pseudocode_bytes']} bytes"
            )
        digest = sha256_file(path)
        expected = decompilation.get("sha256")
        if expected and str(expected) != digest:
            raise InteractionRecoveryError(f"Pseudocode hash mismatch for {relative}")
        try:
            code = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise InteractionRecoveryError(f"Cannot read pseudocode artifact {relative}: {exc}") from exc
        if function_id in code_by_function:
            raise InteractionRecoveryError(f"Duplicate successful pseudocode for function {function_id}")
        code_by_function[function_id] = code
        artifacts.append({
            "function_id": function_id,
            "path": relative.replace("\\", "/"),
            "sha256": digest,
            "size": size,
        })
    return code_by_function, artifacts


def _method_screen_ids(
    method_ids: Iterable[str],
    method_by_id: dict[str, dict[str, Any]],
    screens_by_controller: dict[str, list[str]],
) -> list[str]:
    return sorted({
        screen_id
        for method_id in method_ids
        for class_name in [str(method_by_id.get(str(method_id), {}).get("class_name") or "")]
        for screen_id in screens_by_controller.get(class_name, [])
    })


def _screen_classification(screen_ids: list[str], screen_by_id: dict[str, dict[str, Any]]) -> str:
    if not screen_ids:
        return "unresolved"
    if len(screen_ids) == 1 and screen_by_id.get(screen_ids[0], {}).get("classification") == "exact":
        return "exact"
    return "candidate_set"


def _function_method_ids(
    function_id: str,
    recovered_function_by_id: dict[str, dict[str, Any]],
) -> list[str]:
    return sorted(str(value) for value in recovered_function_by_id.get(function_id, {}).get("method_ids", []))


def _function_classes(
    function_id: str,
    recovered_function_by_id: dict[str, dict[str, Any]],
    method_by_id: dict[str, dict[str, Any]],
) -> list[str]:
    return sorted({
        str(method_by_id[method_id].get("class_name"))
        for method_id in _function_method_ids(function_id, recovered_function_by_id)
        if method_id in method_by_id and method_by_id[method_id].get("class_name")
    })


def _function_screens(
    function_id: str,
    recovered_function_by_id: dict[str, dict[str, Any]],
    method_by_id: dict[str, dict[str, Any]],
    screens_by_controller: dict[str, list[str]],
) -> list[str]:
    return sorted({
        screen_id
        for class_name in _function_classes(function_id, recovered_function_by_id, method_by_id)
        for screen_id in screens_by_controller.get(class_name, [])
    })


def _quoted_value(expression: str) -> str | None:
    matches = _QUOTED.findall(expression)
    if not matches:
        return None
    value = matches[-1]
    try:
        return bytes(value, "utf-8").decode("unicode_escape")
    except UnicodeDecodeError:
        return value


def _split_arguments(value: str) -> list[str]:
    arguments: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    escaped = False
    for index, character in enumerate(value):
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
        elif character in "([{":
            depth += 1
        elif character in ")]}" and depth:
            depth -= 1
        elif character == "," and depth == 0:
            arguments.append(value[start:index].strip())
            start = index + 1
    arguments.append(value[start:].strip())
    return arguments


def _call_occurrences(code: str, selector: str) -> list[dict[str, Any]]:
    token = f'"{selector}"'
    result: list[dict[str, Any]] = []
    position = 0
    while True:
        found = code.find(token, position)
        if found < 0:
            return result
        opening = code.rfind("(", 0, found)
        if opening < 0:
            position = found + len(token)
            continue
        quote: str | None = None
        escaped = False
        depth = 0
        closing = None
        for index in range(opening, len(code)):
            character = code[index]
            if quote is not None:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == quote:
                    quote = None
                continue
            if character in {'"', "'"}:
                quote = character
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    closing = index
                    break
        if closing is None or closing < found:
            position = found + len(token)
            continue
        arguments = _split_arguments(code[opening + 1:closing])
        selector_index = next(
            (index for index, argument in enumerate(arguments) if _quoted_value(argument) == selector),
            None,
        )
        if selector_index is not None:
            result.append({
                "start": opening,
                "line": code.count("\n", 0, opening) + 1,
                "arguments": arguments,
                "selector_index": selector_index,
            })
        position = closing + 1


def _argument_value(occurrence: dict[str, Any] | None, offset: int | None) -> str | None:
    if occurrence is None or offset is None:
        return None
    index = int(occurrence["selector_index"]) + offset
    arguments = occurrence["arguments"]
    if index < 0 or index >= len(arguments):
        return None
    return _quoted_value(str(arguments[index]))


def _argument_number(occurrence: dict[str, Any] | None, offset: int | None) -> str | None:
    if occurrence is None or offset is None:
        return None
    index = int(occurrence["selector_index"]) + offset
    arguments = occurrence["arguments"]
    if index < 0 or index >= len(arguments):
        return None
    candidate = str(arguments[index]).strip()
    return candidate if _NUMBER_LITERAL.fullmatch(candidate) else None


def _correlate_occurrences(
    callsites: list[dict[str, Any]],
    code_by_function: dict[str, str],
) -> dict[str, dict[str, Any] | None]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for callsite in callsites:
        grouped[(str(callsite.get("caller_function_id") or ""), str(callsite.get("selector") or ""))].append(callsite)
    result: dict[str, dict[str, Any] | None] = {}
    for (function_id, selector), records in sorted(grouped.items()):
        ordered = sorted(records, key=lambda item: (_address_key(str(item.get("call_site") or "")), str(item.get("id") or "")))
        occurrences = _call_occurrences(code_by_function.get(function_id, ""), selector)
        if len(ordered) == len(occurrences):
            for record, occurrence in zip(ordered, occurrences):
                result[str(record.get("id") or "")] = occurrence
        else:
            for record in ordered:
                result[str(record.get("id") or "")] = None
    return result


def _trigger(
    *,
    kind: str,
    identity: Iterable[Any],
    classification: str,
    screen_ids: Iterable[str],
    element_ids: Iterable[str] = (),
    connection_ids: Iterable[str] = (),
    event: str | None = None,
    selector: str | None = None,
    callback_contract: str | None = None,
    notification_name: str | None = None,
    timer_interval: str | None = None,
    handler_method_ids: Iterable[str] = (),
    handler_function_ids: Iterable[str] = (),
    registration_function_ids: Iterable[str] = (),
    evidence: list[dict[str, Any]],
    failure_reasons: Iterable[str] = (),
) -> dict[str, Any]:
    if kind not in TRIGGER_KINDS:
        raise InteractionRecoveryError(f"Internal unsupported trigger kind: {kind}")
    identity_values = list(identity)
    return {
        "id": _stable_id("interaction-trigger", kind, *identity_values),
        "kind": kind,
        "classification": classification,
        "screen_ids": sorted(set(screen_ids)),
        "element_ids": sorted(set(element_ids)),
        "connection_ids": sorted(set(connection_ids)),
        "event": event,
        "selector": selector,
        "callback_contract": callback_contract,
        "notification_name": notification_name,
        "timer_interval": timer_interval,
        "handler_method_ids": sorted(set(handler_method_ids)),
        "handler_function_ids": sorted(set(handler_function_ids)),
        "registration_function_ids": sorted(set(registration_function_ids)),
        "evidence": evidence,
        "failure_reasons": sorted(set(failure_reasons)),
    }


def _build_call_slice(
    trigger: dict[str, Any],
    functions_by_id: dict[str, dict[str, Any]],
    recovered_function_by_id: dict[str, dict[str, Any]],
    method_by_id: dict[str, dict[str, Any]],
    call_edges: list[dict[str, Any]],
    inferred_edges: list[dict[str, Any]],
    bounds: dict[str, int],
) -> dict[str, Any]:
    roots = sorted(set(str(value) for value in trigger["handler_function_ids"] if value))
    direct_by_caller: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in call_edges:
        caller = str(edge.get("caller_id") or "")
        if caller:
            direct_by_caller[caller].append(edge)
    dynamic_by_caller: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in inferred_edges:
        caller = str(edge.get("caller_function_id") or "")
        if caller and edge.get("target_function_id"):
            dynamic_by_caller[caller].append(edge)

    depths: dict[str, int] = {root: 0 for root in roots}
    paths: dict[str, str] = {root: "exact" for root in roots}
    via: dict[str, set[str]] = {root: set() for root in roots}
    queue = deque(roots)
    edges: list[dict[str, Any]] = []
    seen_edges: set[str] = set()
    truncated = False
    failure_reasons: list[str] = []
    while queue:
        caller = queue.popleft()
        depth = depths[caller]
        candidates: list[tuple[str, dict[str, Any], str | None, str]] = []
        for edge in direct_by_caller.get(caller, []):
            target = str(edge.get("target_function_id") or "") or None
            exact = bool(
                target
                and edge.get("resolved_function_target")
                and edge.get("semantic_target_resolved")
                and not edge.get("indirect")
                and not edge.get("objective_c_dispatch")
            )
            candidates.append(("direct", edge, target, "exact" if exact else "unresolved"))
        for edge in dynamic_by_caller.get(caller, []):
            candidates.append(("objective_c_dynamic", edge, str(edge.get("target_function_id")), "candidate_set"))
        candidates.sort(key=lambda item: (
            _address_key(str(item[1].get("call_site") or "")),
            item[0],
            item[2] or "",
            str(item[1].get("id") or ""),
        ))
        for edge_kind, source_edge, target, edge_classification in candidates:
            edge_id = _stable_id(
                "interaction-call-edge",
                trigger["id"],
                edge_kind,
                caller,
                source_edge.get("call_site"),
                target,
                source_edge.get("id"),
            )
            if edge_id in seen_edges:
                continue
            if len(edges) >= bounds["max_edges_per_slice"]:
                truncated = True
                failure_reasons.append("call_slice_edge_limit_reached")
                continue
            seen_edges.add(edge_id)
            basis = (
                "The normalized direct call graph resolves this semantic function target"
                if edge_kind == "direct" and edge_classification == "exact"
                else "Objective-C dispatch analysis supplies an additive candidate target"
                if edge_kind == "objective_c_dynamic"
                else "The call boundary is retained but no semantic function target is proven"
            )
            edges.append({
                "id": edge_id,
                "kind": edge_kind,
                "caller_function_id": caller,
                "target_function_id": target,
                "call_site": source_edge.get("call_site"),
                "classification": edge_classification,
                "evidence": [_evidence(
                    "direct_callgraph_edge" if edge_kind == "direct" else "objective_c_dispatch_edge",
                    "analysis/callgraph.json" if edge_kind == "direct" else "analysis/objc-dispatch.json",
                    source_object=str(source_edge.get("id") or "") or None,
                    source_address=str(source_edge.get("call_site") or "") or None,
                    basis=basis,
                    confidence=_confidence(edge_classification),
                )],
                "failure_reasons": [] if edge_classification != "unresolved" else [
                    str(source_edge.get("unresolved_reason") or "semantic_call_target_not_proven")
                ],
            })
            if not target or edge_classification == "unresolved":
                continue
            if depth >= bounds["max_call_depth"]:
                truncated = True
                failure_reasons.append("call_slice_depth_limit_reached")
                continue
            target_path = _classification(paths[caller], edge_classification)
            if target not in depths:
                if len(depths) >= bounds["max_functions_per_slice"]:
                    truncated = True
                    failure_reasons.append("call_slice_function_limit_reached")
                    continue
                depths[target] = depth + 1
                paths[target] = target_path
                via[target] = {edge_id}
                if not functions_by_id.get(target, {}).get("external"):
                    queue.append(target)
            elif depth + 1 == depths[target]:
                paths[target] = _classification(paths[target], target_path)
                via[target].add(edge_id)

    nodes = []
    for function_id in sorted(depths, key=lambda value: (depths[value], value)):
        method_ids = _function_method_ids(function_id, recovered_function_by_id)
        nodes.append({
            "function_id": function_id,
            "depth": depths[function_id],
            "path_classification": paths[function_id],
            "method_ids": method_ids,
            "class_names": sorted({
                str(method_by_id[value].get("class_name"))
                for value in method_ids
                if value in method_by_id and method_by_id[value].get("class_name")
            }),
            "selectors": sorted({
                str(method_by_id[value].get("selector"))
                for value in method_ids
                if value in method_by_id and method_by_id[value].get("selector")
            }),
            "via_edge_ids": sorted(via[function_id]),
        })
    return {
        "id": _stable_id("interaction-call-slice", trigger["id"]),
        "trigger_id": trigger["id"],
        "root_function_ids": roots,
        "max_depth": bounds["max_call_depth"],
        "max_functions": bounds["max_functions_per_slice"],
        "max_edges": bounds["max_edges_per_slice"],
        "nodes": nodes,
        "edges": sorted(edges, key=lambda item: (
            _address_key(str(item.get("call_site") or "")), item["kind"], item["id"]
        )),
        "truncated": truncated,
        "failure_reasons": sorted(set(failure_reasons)),
    }


def _function_resources(function: dict[str, Any]) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    for record in function.get("referenced_strings", []):
        value = record.get("value") if isinstance(record, dict) else record
        if value is not None:
            resources.append({
                "kind": "string",
                "value": str(value),
                "classification": "candidate_set",
                "failure_reason": "function_level_string_reference_does_not_prove_effect_argument",
            })
    for record in function.get("referenced_assets", []):
        value = record.get("path") if isinstance(record, dict) else record
        if value is not None:
            resources.append({
                "kind": "asset",
                "value": str(value),
                "classification": "candidate_set",
                "failure_reason": "function_level_asset_reference_does_not_prove_effect_argument",
            })
    return sorted(resources, key=lambda item: (item["kind"], item["value"]))


def _effect(
    *,
    trigger_id: str,
    source_identity: Iterable[Any],
    kind: str,
    classification: str,
    function_id: str | None,
    call_site: str | None = None,
    selector: str | None = None,
    symbol: str | None = None,
    operation: str | None = None,
    state_id: str | None = None,
    source_screen_ids: Iterable[str] = (),
    destination_screen_ids: Iterable[str] = (),
    ui_operation_ids: Iterable[str] = (),
    platform_dependency_ids: Iterable[str] = (),
    details: dict[str, Any] | None = None,
    evidence: list[dict[str, Any]],
    failure_reasons: Iterable[str] = (),
) -> dict[str, Any]:
    if kind not in EFFECT_KINDS:
        raise InteractionRecoveryError(f"Internal unsupported effect kind: {kind}")
    identity_values = list(source_identity)
    return {
        "id": _stable_id("interaction-effect", trigger_id, kind, *identity_values),
        "trigger_id": trigger_id,
        "kind": kind,
        "classification": classification,
        "function_id": function_id,
        "call_site": call_site,
        "selector": selector,
        "symbol": symbol,
        "operation": operation,
        "state_id": state_id,
        "source_screen_ids": sorted(set(source_screen_ids)),
        "destination_screen_ids": sorted(set(destination_screen_ids)),
        "ui_operation_ids": sorted(set(ui_operation_ids)),
        "platform_dependency_ids": sorted(set(platform_dependency_ids)),
        "details": details or {},
        "evidence": evidence,
        "failure_reasons": sorted(set(failure_reasons)),
    }


def _global_access_kind(line: str, labels: Iterable[str]) -> str:
    match = _ASSIGNMENT.search(line)
    if match is None:
        return "read"
    left = line[:match.start()]
    return "write" if any(label and label in left for label in labels) else "read"


def _member_accesses(
    code: str,
    class_names: Iterable[str],
    class_records_by_name: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    members: list[tuple[str, str, str]] = []
    for class_name in sorted(set(class_names)):
        for record in class_records_by_name.get(class_name, []):
            for ivar in record.get("ivars", []):
                name = str(ivar.get("name") or "")
                if name:
                    members.append((class_name, "ivar", name))
            for prop in record.get("properties", []):
                name = str(prop.get("name") or "")
                if name:
                    members.append((class_name, "property", name))
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, int, str]] = set()
    for line_number, line in enumerate(code.splitlines(), 1):
        assignment = _ASSIGNMENT.search(line)
        for class_name, member_kind, name in members:
            patterns = (f"self->{name}", f"self->{name.lstrip('_')}", f"this->{name}", f"this->{name.lstrip('_')}")
            token = next((value for value in patterns if value and value in line), None)
            if token is None:
                continue
            access = "write" if assignment and token in line[:assignment.start()] else "read"
            identity = (class_name, member_kind, name, line_number, access)
            if identity in seen:
                continue
            seen.add(identity)
            result.append({
                "class_name": class_name,
                "member_kind": member_kind,
                "name": name,
                "line": line_number,
                "access_kind": access,
                "expression": line.strip(),
            })
    return result


def _render_report(facts: dict[str, Any]) -> str:
    summary = facts["summary"]
    lines = [
        "# IPALift interaction reconstruction report",
        "",
        "> Evidence-linked trigger → handler → effect guidance. This report does not claim runtime coverage or original behavior.",
        "",
        "## Summary",
        "",
        f"- Triggers: {summary['trigger_count']}",
        f"- Interaction chains: {summary['interaction_count']}",
        f"- Effects: {summary['effect_count']}",
        f"- Call-slice functions: {summary['call_slice_function_count']}",
        f"- Call-slice edges: {summary['call_slice_edge_count']}",
        f"- State reads / writes: {summary['state_read_count']} / {summary['state_write_count']}",
        f"- Network requests: {summary['network_request_count']}",
        f"- Persistence effects: {summary['persistence_effect_count']}",
        "",
        "## Screen-by-screen interactions",
        "",
    ]
    trigger_by_id = {item["id"]: item for item in facts["triggers"]}
    effect_by_id = {item["id"]: item for item in facts["effects"]}
    slice_by_id = {item["id"]: item for item in facts["call_slices"]}
    interactions_by_screen: dict[str, list[dict[str, Any]]] = defaultdict(list)
    unassigned: list[dict[str, Any]] = []
    for interaction in facts["interactions"]:
        if interaction["screen_ids"]:
            for screen_id in interaction["screen_ids"]:
                interactions_by_screen[screen_id].append(interaction)
        else:
            unassigned.append(interaction)
    for screen in facts["screens"]:
        lines.extend([f"### {screen['name']}", "", f"- Controller: `{screen['controller_class_name'] or 'unknown'}`", f"- UI evidence: {screen['classification']}", ""])
        records = sorted(interactions_by_screen.get(screen["id"], []), key=lambda item: item["id"])
        if not records:
            lines.extend(["No interaction chain was recovered for this screen.", ""])
            continue
        for interaction in records:
            trigger = trigger_by_id[interaction["trigger_id"]]
            handler = ", ".join(f"`{value}`" for value in interaction["handler_method_ids"] or interaction["handler_function_ids"]) or "unresolved handler"
            label = trigger["event"] or trigger["selector"] or trigger["callback_contract"] or trigger["kind"]
            lines.append(f"#### {trigger['kind']}: {label} ({interaction['classification']})")
            lines.extend(["", f"- Handler: {handler}"])
            call_slice = slice_by_id.get(interaction["call_slice_id"])
            if call_slice:
                lines.append(
                    f"- Bounded call slice: {len(call_slice['nodes'])} functions, {len(call_slice['edges'])} edges"
                    + ("; truncated at configured limits" if call_slice["truncated"] else "")
                )
            effects = [effect_by_id[value] for value in interaction["effect_ids"] if value in effect_by_id]
            if not effects:
                lines.append("- Effects: none proven")
            else:
                lines.append("- Effects:")
                for effect in effects:
                    subject = effect["selector"] or effect["symbol"] or effect["state_id"] or effect["operation"] or "unspecified"
                    destinations = f" → {', '.join(effect['destination_screen_ids'])}" if effect["destination_screen_ids"] else ""
                    lines.append(f"  - {effect['kind']}: `{subject}`{destinations} ({effect['classification']})")
            if interaction["failure_reasons"]:
                lines.append(f"- Uncertainty: {', '.join(interaction['failure_reasons'])}")
            lines.append("")
    if unassigned:
        lines.extend(["## Application-level or unassigned interactions", ""])
        for interaction in sorted(unassigned, key=lambda item: item["id"]):
            trigger = trigger_by_id[interaction["trigger_id"]]
            label = trigger["selector"] or trigger["callback_contract"] or trigger["kind"]
            lines.append(f"- {trigger['kind']} `{label}`: {interaction['classification']}")
        lines.append("")
    lines.extend([
        "## Evidence boundary",
        "",
        "- Serialized UI links, recovered method identities, direct call edges, and explicit state accesses remain distinct facts.",
        "- Objective-C dynamic edges, ambiguous callback bindings, and function-level resource references remain candidate sets.",
        "- Selectors and names select generic mechanisms or preserve storage identities; they never invent application behavior.",
        "- Call slices are statically bounded and are not claims of runtime execution or branch coverage.",
        "- The complete machine-readable graph is in `analysis/interaction-model.json`.",
        "",
    ])
    return "\n".join(lines)


def recover_interactions(workspace: Path) -> InteractionRecoveryResult:
    """Recover app-neutral trigger → handler → effect chains from a completed workspace."""
    workspace = workspace.resolve()
    reports = {name: _load_report(workspace, name) for name in REQUIRED_REPORTS}
    catalog, catalog_sha256 = _load_catalog()
    bounds = {key: int(value) for key, value in catalog["bounds"].items()}

    ui_facts = reports["ui-model"]["facts"]
    screens = list(ui_facts.get("screens") or [])
    screen_by_id = _unique_records(screens, "id", "analysis/ui-model.json screens")
    screens_by_controller: dict[str, list[str]] = defaultdict(list)
    for screen in screens:
        class_name = str(screen.get("controller_class_name") or "")
        if class_name:
            screens_by_controller[class_name].append(str(screen["id"]))
    for values in screens_by_controller.values():
        values.sort()

    recovered_facts = reports["recovered-code-index"]["facts"]
    recovered_functions = list(recovered_facts.get("functions") or [])
    methods = list(recovered_facts.get("methods") or [])
    classes = list(recovered_facts.get("classes") or [])
    recovered_function_by_id = _unique_records(
        recovered_functions, "function_id", "analysis/recovered-code-index.json functions"
    )
    method_by_id = _unique_records(methods, "id", "analysis/recovered-code-index.json methods")
    functions_by_id = _unique_records(
        list(reports["functions"]["facts"].get("functions") or []),
        "id",
        "analysis/functions.json functions",
    )
    class_records_by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in classes:
        if record.get("name"):
            class_records_by_name[str(record["name"])].append(record)
    code_by_function, pseudocode_artifacts = _load_pseudocode(workspace, recovered_functions, bounds)

    platform_facts = reports["platform-api-map"]["facts"]
    platform_callsites = list(platform_facts.get("message_callsites") or [])
    occurrence_by_callsite = _correlate_occurrences(platform_callsites, code_by_function)
    lifecycle = {str(item["selector"]): str(item["scope"]) for item in catalog["lifecycle_selectors"]}
    notification_registration = {str(item["selector"]): item for item in catalog["notification_registrations"]}
    timer_registration = {str(item["selector"]): item for item in catalog["timer_registrations"]}
    callback_registration = {str(item["selector"]): item for item in catalog["callback_registrations"]}
    effect_selectors = {str(item["selector"]): item for item in catalog["effect_selectors"]}
    imported_effects = {str(item["symbol"]): item for item in catalog["imported_effects"]}

    triggers: list[dict[str, Any]] = []
    trigger_keys: set[tuple[Any, ...]] = set()

    def add_trigger(record: dict[str, Any]) -> None:
        key = (
            record["kind"],
            record["selector"],
            record["callback_contract"],
            tuple(record["connection_ids"]),
            tuple(record["handler_method_ids"]),
            tuple(record["handler_function_ids"]),
            tuple(record["registration_function_ids"]),
        )
        if key not in trigger_keys:
            trigger_keys.add(key)
            triggers.append(record)

    for connection in sorted(ui_facts.get("connections") or [], key=lambda item: str(item.get("id") or "")):
        if connection.get("kind") != "action":
            continue
        matches = [
            item for item in connection.get("code_matches", [])
            if item.get("kind") == "objective_c_action_method"
        ]
        method_ids = sorted({
            str(value)
            for match in matches
            for value in match.get("candidate_ids", [])
            if str(value) in method_by_id
        })
        function_ids = sorted({
            str(method_by_id[value].get("function_id"))
            for value in method_ids
            if method_by_id[value].get("function_id")
        })
        match_classification = _classification(*[
            str(item.get("classification") or "unresolved") for item in matches
        ]) if matches else "unresolved"
        screen_ids = [str(connection["screen_id"])] if connection.get("screen_id") else []
        classification = _classification(
            str(connection.get("classification") or "unresolved"),
            match_classification,
            "exact" if function_ids else "unresolved",
            _screen_classification(screen_ids, screen_by_id),
        )
        failures = list(connection.get("failure_reasons") or [])
        if not function_ids:
            failures.append("ui_action_handler_function_not_recovered")
        add_trigger(_trigger(
            kind="ui_action",
            identity=[connection.get("id"), connection.get("selector")],
            classification=classification,
            screen_ids=screen_ids,
            element_ids=[str(connection["source_object_id"])] if connection.get("source_object_id") else [],
            connection_ids=[str(connection["id"])],
            event=str(connection.get("event") or "ui_control_action"),
            selector=str(connection.get("selector") or "") or None,
            handler_method_ids=method_ids,
            handler_function_ids=function_ids,
            evidence=[_evidence(
                "ui_action_connection",
                "analysis/ui-model.json",
                source_object=str(connection.get("id") or ""),
                field=str(connection.get("selector") or "") or None,
                basis="The UI model connects a serialized control action to recovered Objective-C method candidates",
                confidence=_confidence(classification),
            )],
            failure_reasons=failures,
        ))

    navigation_by_connection = {
        str(item.get("connection_id")): item
        for item in ui_facts.get("navigation_edges", [])
        if item.get("connection_id")
    }
    for connection_id, navigation in sorted(navigation_by_connection.items()):
        connection = next(
            (item for item in ui_facts.get("connections", []) if item.get("id") == connection_id),
            None,
        )
        if connection is None:
            continue
        screen_ids = [str(value) for value in [navigation.get("source_screen_id")] if value]
        classification = _classification(
            str(navigation.get("classification") or "unresolved"),
            _screen_classification(screen_ids, screen_by_id),
        )
        add_trigger(_trigger(
            kind="ui_action",
            identity=[connection_id, "serialized_navigation"],
            classification=classification,
            screen_ids=screen_ids,
            element_ids=[str(connection["source_object_id"])] if connection.get("source_object_id") else [],
            connection_ids=[connection_id],
            event=f"segue:{navigation.get('subkind') or 'navigation'}",
            evidence=[_evidence(
                "serialized_navigation_trigger",
                "analysis/ui-model.json",
                source_object=str(navigation.get("id") or ""),
                basis="A serialized segue or relationship supplies a direct UI-triggered navigation chain",
                confidence=_confidence(classification),
            )],
            failure_reasons=navigation.get("failure_reasons") or [],
        ))

    for method in sorted(methods, key=lambda item: str(item.get("id") or "")):
        selector = str(method.get("selector") or "")
        if selector not in lifecycle or not method.get("function_id"):
            continue
        method_id = str(method["id"])
        function_id = str(method["function_id"])
        class_name = str(method.get("class_name") or "")
        screen_ids = sorted(screens_by_controller.get(class_name, []))
        scope = lifecycle[selector]
        mapping_classification = (
            _screen_classification(screen_ids, screen_by_id)
            if scope == "view_controller" else "exact"
        )
        classification = _classification(
            "exact" if method.get("mapping_status", "mapped") == "mapped" else "unresolved",
            mapping_classification,
        )
        failures = [] if classification == "exact" else [
            "lifecycle_method_does_not_map_to_one_exact_screen"
            if scope == "view_controller" else "lifecycle_handler_mapping_not_exact"
        ]
        add_trigger(_trigger(
            kind="lifecycle",
            identity=[method_id, selector],
            classification=classification,
            screen_ids=screen_ids,
            event=scope,
            selector=selector,
            callback_contract=f"{scope}::{selector}",
            handler_method_ids=[method_id],
            handler_function_ids=[function_id],
            evidence=[_evidence(
                "objective_c_lifecycle_method",
                "analysis/recovered-code-index.json",
                source_object=method_id,
                field=selector,
                basis="Recovered method metadata matches an explicit app-neutral lifecycle contract",
                confidence=_confidence(classification),
            )],
            failure_reasons=failures,
        ))

    for dependency in sorted(platform_facts.get("callback_dependencies") or [], key=lambda item: str(item.get("id") or "")):
        selector = str(dependency.get("selector") or "")
        if selector in lifecycle:
            continue
        method_ids = sorted(str(value) for value in dependency.get("affected_method_ids", []) if str(value) in method_by_id)
        function_ids = sorted({
            str(method_by_id[value].get("function_id"))
            for value in method_ids
            if method_by_id[value].get("function_id")
        } | {str(value) for value in dependency.get("affected_function_ids", []) if value})
        screen_ids = sorted({
            *(_method_screen_ids(method_ids, method_by_id, screens_by_controller)),
            *(
                screen_id
                for class_name in dependency.get("affected_class_names", [])
                for screen_id in screens_by_controller.get(str(class_name), [])
            ),
        })
        classification = _classification(
            str(dependency.get("classification") or "unresolved"),
            "exact" if function_ids else "unresolved",
            _screen_classification(screen_ids, screen_by_id) if screen_ids else "exact",
        )
        trigger_kind = "delegate" if dependency.get("kind") == "protocol_callback" else "callback"
        failures = list(dependency.get("failure_reasons") or [])
        if not function_ids:
            failures.append("callback_handler_function_not_recovered")
        add_trigger(_trigger(
            kind=trigger_kind,
            identity=[dependency.get("id"), selector],
            classification=classification,
            screen_ids=screen_ids,
            event=str(dependency.get("protocol_name") or dependency.get("kind") or "callback"),
            selector=selector or None,
            callback_contract=str(dependency.get("callback_contract") or "") or None,
            handler_method_ids=method_ids,
            handler_function_ids=function_ids,
            evidence=[_evidence(
                "platform_callback_contract",
                "analysis/platform-api-map.json",
                source_object=str(dependency.get("id") or ""),
                field=selector or None,
                basis="The platform map joins recovered method metadata to an explicit superclass or protocol callback contract",
                confidence=_confidence(classification),
            )],
            failure_reasons=failures,
        ))

    direct_targets_by_caller: dict[str, set[str]] = defaultdict(set)
    call_edges = list(reports["callgraph"]["facts"].get("edges") or [])
    for edge in call_edges:
        if (
            edge.get("resolved_function_target")
            and edge.get("semantic_target_resolved")
            and not edge.get("external")
            and edge.get("target_function_id")
        ):
            direct_targets_by_caller[str(edge.get("caller_id") or "")].add(str(edge["target_function_id"]))

    for callsite in sorted(platform_callsites, key=lambda item: (
        _address_key(str(item.get("call_site") or "")), str(item.get("id") or "")
    )):
        selector = str(callsite.get("selector") or "")
        if selector not in notification_registration and selector not in timer_registration and selector not in callback_registration:
            continue
        callsite_id = str(callsite.get("id") or "")
        function_id = str(callsite.get("caller_function_id") or "")
        occurrence = occurrence_by_callsite.get(callsite_id)
        class_names = sorted(str(value) for value in callsite.get("affected_class_names", []))
        registration_screens = sorted({
            screen_id for class_name in class_names for screen_id in screens_by_controller.get(class_name, [])
        } or set(_function_screens(function_id, recovered_function_by_id, method_by_id, screens_by_controller)))
        correlation_classification = "exact" if occurrence is not None else "candidate_set"
        if selector in notification_registration:
            definition = notification_registration[selector]
            callback_selector = _argument_value(occurrence, definition.get("callback_argument_offset"))
            notification_name = _argument_value(occurrence, definition.get("name_argument_offset"))
            method_candidates = sorted({
                method_id
                for method_id, method in method_by_id.items()
                if callback_selector
                and method.get("selector") == callback_selector
                and (not class_names or method.get("class_name") in class_names)
            })
            function_candidates = sorted({
                str(method_by_id[value].get("function_id"))
                for value in method_candidates
                if method_by_id[value].get("function_id")
            })
            classification = _classification(
                str(callsite.get("classification") or "unresolved"),
                correlation_classification,
                "exact" if function_candidates else "unresolved",
            )
            failures = []
            if occurrence is None:
                failures.append("registration_callsite_does_not_map_to_one_pseudocode_call")
            if not function_candidates:
                failures.append("notification_callback_handler_not_recovered")
            add_trigger(_trigger(
                kind="notification",
                identity=[callsite_id, callback_selector, notification_name],
                classification=classification,
                screen_ids=_method_screen_ids(method_candidates, method_by_id, screens_by_controller) or registration_screens,
                event="notification_delivery",
                selector=callback_selector,
                callback_contract=selector,
                notification_name=notification_name,
                handler_method_ids=method_candidates,
                handler_function_ids=function_candidates,
                registration_function_ids=[function_id] if function_id else [],
                evidence=[_evidence(
                    "notification_registration_callsite",
                    "analysis/platform-api-map.json",
                    source_object=callsite_id,
                    field=selector,
                    source_address=str(callsite.get("call_site") or "") or None,
                    basis="A cataloged notification registration call and literal callback selector identify the delivery handler",
                    confidence=_confidence(classification),
                    details={"pseudocode_line": occurrence.get("line") if occurrence else None},
                )],
                failure_reasons=failures,
            ))
        if selector in timer_registration:
            definition = timer_registration[selector]
            callback_selector = _argument_value(occurrence, definition.get("callback_argument_offset"))
            interval = _argument_number(occurrence, definition.get("interval_argument_offset"))
            method_candidates = sorted({
                method_id
                for method_id, method in method_by_id.items()
                if callback_selector
                and method.get("selector") == callback_selector
                and (not class_names or method.get("class_name") in class_names)
            })
            function_candidates = sorted({
                str(method_by_id[value].get("function_id"))
                for value in method_candidates
                if method_by_id[value].get("function_id")
            })
            classification = _classification(
                str(callsite.get("classification") or "unresolved"),
                correlation_classification,
                "exact" if function_candidates else "unresolved",
            )
            failures = []
            if occurrence is None:
                failures.append("registration_callsite_does_not_map_to_one_pseudocode_call")
            if not function_candidates:
                failures.append("timer_callback_handler_not_recovered")
            add_trigger(_trigger(
                kind="timer",
                identity=[callsite_id, callback_selector, interval],
                classification=classification,
                screen_ids=_method_screen_ids(method_candidates, method_by_id, screens_by_controller) or registration_screens,
                event="timer_fire",
                selector=callback_selector,
                callback_contract=selector,
                timer_interval=interval,
                handler_method_ids=method_candidates,
                handler_function_ids=function_candidates,
                registration_function_ids=[function_id] if function_id else [],
                evidence=[_evidence(
                    "timer_registration_callsite",
                    "analysis/platform-api-map.json",
                    source_object=callsite_id,
                    field=selector,
                    source_address=str(callsite.get("call_site") or "") or None,
                    basis="A cataloged timer registration call and literal callback selector identify the future handler",
                    confidence=_confidence(classification),
                    details={"pseudocode_line": occurrence.get("line") if occurrence else None},
                )],
                failure_reasons=failures,
            ))
        if selector in callback_registration:
            definition = callback_registration[selector]
            candidates = sorted(
                target for target in direct_targets_by_caller.get(function_id, set())
                if target in functions_by_id and not functions_by_id[target].get("external")
            )
            classification = "candidate_set" if candidates else "unresolved"
            add_trigger(_trigger(
                kind="callback",
                identity=[callsite_id, definition.get("contract")],
                classification=classification,
                screen_ids=registration_screens,
                event="completion_or_block_invocation",
                selector=selector,
                callback_contract=str(definition.get("contract") or "callback"),
                handler_function_ids=candidates,
                registration_function_ids=[function_id] if function_id else [],
                evidence=[_evidence(
                    "callback_registration_callsite",
                    "analysis/platform-api-map.json",
                    source_object=callsite_id,
                    field=selector,
                    source_address=str(callsite.get("call_site") or "") or None,
                    basis="A cataloged completion/block API proves callback registration; nearby direct callees remain handler candidates",
                    confidence=_confidence(classification),
                )],
                failure_reasons=[
                    "block_or_function_pointer_target_not_proven"
                    if candidates else "callback_handler_not_recovered"
                ],
            ))

    triggers.sort(key=lambda item: (item["kind"], tuple(item["screen_ids"]), item["selector"] or "", item["id"]))
    inferred_edges = [
        item for item in reports["objc-dispatch"].get("hypotheses", [])
        if item.get("edge_kind") == "objective_c_dynamic_dispatch_inference"
    ]
    call_slices = [
        _build_call_slice(
            trigger,
            functions_by_id,
            recovered_function_by_id,
            method_by_id,
            call_edges,
            inferred_edges,
            bounds,
        )
        for trigger in triggers
    ]

    ui_operations = list(ui_facts.get("code_operations") or [])
    native_facts = reports["native-type-flow"]["facts"]
    global_records = list(native_facts.get("globals") or [])
    native_field_accesses = list(native_facts.get("field_accesses") or [])
    dependencies = list(platform_facts.get("dependencies") or [])
    effects: list[dict[str, Any]] = []
    interactions: list[dict[str, Any]] = []
    hypotheses: list[dict[str, Any]] = []
    callsite_by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in platform_callsites:
        callsite_by_function[str(item.get("caller_function_id") or "")].append(item)
    ui_operations_by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in ui_operations:
        ui_operations_by_function[str(item.get("caller_function_id") or "")].append(item)
    fields_by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in native_field_accesses:
        fields_by_function[str(item.get("function_id") or "")].append(item)
    globals_by_function: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = defaultdict(list)
    for item in global_records:
        for reference in item.get("references", []):
            globals_by_function[str(reference.get("function_id") or "")].append((item, reference))
    imported_dependencies_by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in dependencies:
        if item.get("kind") != "imported_function":
            continue
        for function_id in item.get("affected_function_ids", []):
            imported_dependencies_by_function[str(function_id)].append(item)

    for trigger, call_slice in zip(triggers, call_slices):
        node_classification = {
            str(item["function_id"]): str(item["path_classification"])
            for item in call_slice["nodes"]
        }
        trigger_effects: list[dict[str, Any]] = []
        connection_ids = set(trigger["connection_ids"])
        for navigation in ui_facts.get("navigation_edges", []):
            if str(navigation.get("connection_id") or "") not in connection_ids:
                continue
            classification = _classification(trigger["classification"], str(navigation.get("classification") or "unresolved"))
            trigger_effects.append(_effect(
                trigger_id=trigger["id"],
                source_identity=[navigation.get("id")],
                kind="navigation",
                classification=classification,
                function_id=None,
                operation=str(navigation.get("subkind") or "segue"),
                source_screen_ids=[str(value) for value in [navigation.get("source_screen_id")] if value],
                destination_screen_ids=[str(value) for value in [navigation.get("destination_screen_id")] if value],
                details={"identifier": navigation.get("identifier")},
                evidence=[_evidence(
                    "serialized_navigation_effect",
                    "analysis/ui-model.json",
                    source_object=str(navigation.get("id") or ""),
                    basis="The UI model directly identifies a serialized navigation destination",
                    confidence=_confidence(classification),
                )],
                failure_reasons=navigation.get("failure_reasons") or [],
            ))

        for function_id in sorted(node_classification):
            path_classification = node_classification[function_id]
            function = recovered_function_by_id.get(function_id, {})
            function_screens = _function_screens(
                function_id, recovered_function_by_id, method_by_id, screens_by_controller
            ) or trigger["screen_ids"]
            resources = _function_resources(function)
            for operation in sorted(ui_operations_by_function.get(function_id, []), key=lambda item: str(item.get("id") or "")):
                kind = "navigation" if operation.get("category") == "navigation" else "ui_update"
                classification = _classification(trigger["classification"], path_classification, str(operation.get("classification") or "unresolved"))
                trigger_effects.append(_effect(
                    trigger_id=trigger["id"],
                    source_identity=[operation.get("id")],
                    kind=kind,
                    classification=classification,
                    function_id=function_id,
                    call_site=str(operation.get("call_site") or "") or None,
                    selector=str(operation.get("selector") or "") or None,
                    operation=str(operation.get("category") or "ui"),
                    source_screen_ids=operation.get("screen_candidate_ids") or function_screens,
                    ui_operation_ids=[str(operation.get("id"))],
                    details={"resource_candidates": operation.get("resource_candidates") or []},
                    evidence=[_evidence(
                        "ui_code_operation",
                        "analysis/ui-model.json",
                        source_object=str(operation.get("id") or ""),
                        field=str(operation.get("selector") or "") or None,
                        source_address=str(operation.get("call_site") or "") or None,
                        basis="The UI model classifies this UIKit callsite and associates it with screen candidates",
                        confidence=_confidence(classification),
                    )],
                    failure_reasons=operation.get("failure_reasons") or [],
                ))

            for access in sorted(fields_by_function.get(function_id, []), key=lambda item: str(item.get("id") or "")):
                access_kind = str(access.get("access_kind") or "")
                effect_kind = "state_write" if access_kind == "write" else "state_read"
                classification = _classification(trigger["classification"], path_classification, str(access.get("classification") or "unresolved"))
                trigger_effects.append(_effect(
                    trigger_id=trigger["id"],
                    source_identity=[access.get("id")],
                    kind=effect_kind,
                    classification=classification,
                    function_id=function_id,
                    operation=access_kind,
                    state_id=str(access.get("field_value_id") or access.get("id")),
                    source_screen_ids=function_screens,
                    details={
                        "offset": access.get("offset"),
                        "width": access.get("width"),
                        "expression": access.get("expression"),
                        "pseudocode_line": access.get("pseudocode_line"),
                    },
                    evidence=[_evidence(
                        "native_field_access",
                        "analysis/native-type-flow.json",
                        source_object=str(access.get("id") or ""),
                        basis="Native type flow records an explicit numeric field read or write in this function",
                        confidence=_confidence(classification),
                    )],
                    failure_reasons=access.get("failure_reasons") or [],
                ))

            for global_record, reference in sorted(
                globals_by_function.get(function_id, []),
                key=lambda pair: (str(pair[0].get("id") or ""), int(pair[1].get("pseudocode_line") or 0)),
            ):
                line_number = int(reference.get("pseudocode_line") or 0)
                code_lines = code_by_function.get(function_id, "").splitlines()
                line = code_lines[line_number - 1] if 0 < line_number <= len(code_lines) else ""
                labels = [str(reference.get("label") or ""), *[str(value) for value in global_record.get("exact_symbols", [])]]
                access_kind = _global_access_kind(line, labels)
                effect_kind = "state_write" if access_kind == "write" else "state_read"
                base = str(global_record.get("classification") or "unresolved")
                classification = _classification(trigger["classification"], path_classification, base, "exact" if line else "unresolved")
                failures = list(global_record.get("failure_reasons") or [])
                if not line:
                    failures.append("global_reference_pseudocode_line_not_available")
                trigger_effects.append(_effect(
                    trigger_id=trigger["id"],
                    source_identity=[global_record.get("id"), line_number, access_kind],
                    kind=effect_kind,
                    classification=classification,
                    function_id=function_id,
                    operation=access_kind,
                    state_id=str(global_record.get("id") or ""),
                    source_screen_ids=function_screens,
                    details={
                        "address": global_record.get("address"),
                        "symbols": global_record.get("exact_symbols") or [],
                        "expression": line.strip() or None,
                        "pseudocode_line": line_number or None,
                    },
                    evidence=[_evidence(
                        "native_global_reference",
                        "analysis/native-type-flow.json",
                        source_object=str(global_record.get("id") or ""),
                        basis="Native type flow records this exact global reference; assignment position determines read versus write",
                        confidence=_confidence(classification),
                    )],
                    failure_reasons=failures,
                ))

            class_names = _function_classes(function_id, recovered_function_by_id, method_by_id)
            for member in _member_accesses(code_by_function.get(function_id, ""), class_names, class_records_by_name):
                effect_kind = "state_write" if member["access_kind"] == "write" else "state_read"
                classification = _classification(trigger["classification"], path_classification)
                state_id = f"objc-{member['member_kind']}:{member['class_name']}:{member['name']}"
                trigger_effects.append(_effect(
                    trigger_id=trigger["id"],
                    source_identity=[state_id, member["line"], member["access_kind"]],
                    kind=effect_kind,
                    classification=classification,
                    function_id=function_id,
                    operation=member["access_kind"],
                    state_id=state_id,
                    source_screen_ids=function_screens,
                    details={
                        "class_name": member["class_name"],
                        "member_kind": member["member_kind"],
                        "member_name": member["name"],
                        "expression": member["expression"],
                        "pseudocode_line": member["line"],
                    },
                    evidence=[_evidence(
                        "objective_c_member_access",
                        str(function.get("decompilation", {}).get("output_path") or "analysis/recovered-code-index.json"),
                        source_object=function_id,
                        field=member["name"],
                        basis="A recovered property or ivar identity appears in an explicit self/this member access",
                        confidence=_confidence(classification),
                    )],
                ))

            for callsite in sorted(callsite_by_function.get(function_id, []), key=lambda item: (
                _address_key(str(item.get("call_site") or "")), str(item.get("id") or "")
            )):
                selector = str(callsite.get("selector") or "")
                definition = effect_selectors.get(selector)
                categories = {str(value) for value in callsite.get("categories", [])}
                if definition:
                    effect_kind = str(definition["effect_kind"])
                    operation_name = str(definition["operation"])
                elif "networking" in categories:
                    effect_kind, operation_name = "network_request", "platform_network_operation"
                elif "persistence" in categories:
                    effect_kind, operation_name = "persistence_access", "platform_persistence_operation"
                elif callsite.get("platform_status") in {"external_exact", "external_candidate"}:
                    effect_kind, operation_name = "platform_api", "platform_message"
                else:
                    continue
                classification = _classification(trigger["classification"], path_classification, str(callsite.get("classification") or "unresolved"))
                occurrence = occurrence_by_callsite.get(str(callsite.get("id") or ""))
                literal_arguments = []
                if occurrence is not None:
                    selector_index = int(occurrence["selector_index"])
                    literal_arguments = [
                        value
                        for argument in occurrence["arguments"][selector_index + 1:]
                        for value in [_quoted_value(str(argument))]
                        if value is not None
                    ]
                failures = list(callsite.get("failure_reasons") or [])
                if resources:
                    failures.append("function_level_resources_not_promoted_to_effect_arguments")
                trigger_effects.append(_effect(
                    trigger_id=trigger["id"],
                    source_identity=[callsite.get("id"), effect_kind],
                    kind=effect_kind,
                    classification=classification,
                    function_id=function_id,
                    call_site=str(callsite.get("call_site") or "") or None,
                    selector=selector or None,
                    operation=operation_name,
                    source_screen_ids=function_screens,
                    details={
                        "frameworks": sorted(str(value) for value in callsite.get("frameworks", [])),
                        "categories": sorted(categories),
                        "literal_arguments": literal_arguments,
                        "resource_candidates": resources,
                    },
                    evidence=[_evidence(
                        "platform_message_effect",
                        "analysis/platform-api-map.json",
                        source_object=str(callsite.get("id") or ""),
                        field=selector or None,
                        source_address=str(callsite.get("call_site") or "") or None,
                        basis="A platform message callsite matches a generic effect selector or category",
                        confidence=_confidence(classification),
                        details={"pseudocode_line": occurrence.get("line") if occurrence else None},
                    )],
                    failure_reasons=failures,
                ))
                if selector in timer_registration:
                    trigger_effects.append(_effect(
                        trigger_id=trigger["id"],
                        source_identity=[callsite.get("id"), "schedule"],
                        kind="timer_schedule",
                        classification=classification,
                        function_id=function_id,
                        call_site=str(callsite.get("call_site") or "") or None,
                        selector=selector,
                        operation="schedule",
                        source_screen_ids=function_screens,
                        details={"timer_interval": _argument_number(occurrence, timer_registration[selector].get("interval_argument_offset"))},
                        evidence=[_evidence(
                            "timer_schedule_callsite",
                            "analysis/platform-api-map.json",
                            source_object=str(callsite.get("id") or ""),
                            field=selector,
                            source_address=str(callsite.get("call_site") or "") or None,
                            basis="A cataloged timer creation or delayed-selector call schedules future work",
                            confidence=_confidence(classification),
                        )],
                    ))

            for dependency in sorted(imported_dependencies_by_function.get(function_id, []), key=lambda item: str(item.get("id") or "")):
                symbol = str(dependency.get("symbol") or "").lstrip("_")
                definition = imported_effects.get(symbol)
                categories = {str(value) for value in dependency.get("categories", [])}
                if definition:
                    effect_kind = str(definition["effect_kind"])
                    operation_name = str(definition["operation"])
                elif "networking" in categories:
                    effect_kind, operation_name = "network_request", "imported_network_operation"
                elif "persistence" in categories:
                    effect_kind, operation_name = "persistence_access", "imported_persistence_operation"
                else:
                    effect_kind, operation_name = "platform_api", "imported_platform_operation"
                classification = _classification(trigger["classification"], path_classification, str(dependency.get("classification") or "unresolved"))
                trigger_effects.append(_effect(
                    trigger_id=trigger["id"],
                    source_identity=[dependency.get("id"), effect_kind],
                    kind=effect_kind,
                    classification=classification,
                    function_id=function_id,
                    call_site=(sorted(str(value) for value in dependency.get("call_sites", [])) or [None])[0],
                    symbol=str(dependency.get("symbol") or "") or None,
                    operation=operation_name,
                    source_screen_ids=function_screens,
                    platform_dependency_ids=[str(dependency.get("id"))],
                    details={
                        "frameworks": sorted(str(value) for value in dependency.get("frameworks", [])),
                        "categories": sorted(categories),
                        "resource_candidates": resources,
                    },
                    evidence=[_evidence(
                        "imported_platform_effect",
                        "analysis/platform-api-map.json",
                        source_object=str(dependency.get("id") or ""),
                        field=str(dependency.get("symbol") or "") or None,
                        basis="The platform map associates an imported API dependency with this function",
                        confidence=_confidence(classification),
                    )],
                    failure_reasons=dependency.get("failure_reasons") or [],
                ))

        unique_effects: dict[str, dict[str, Any]] = {item["id"]: item for item in trigger_effects}
        ordered_effects = sorted(unique_effects.values(), key=lambda item: (
            item["kind"], _address_key(item.get("call_site")), item["state_id"] or "", item["id"]
        ))
        effects.extend(ordered_effects)
        if ordered_effects:
            chain_classification = _classification(
                trigger["classification"],
                *[str(value) for value in node_classification.values()],
                *[str(item["classification"]) for item in ordered_effects],
            )
        else:
            chain_classification = "unresolved"
        failures = list(call_slice["failure_reasons"])
        if not trigger["handler_function_ids"] and not ordered_effects:
            failures.append("interaction_handler_and_effects_not_recovered")
        elif not ordered_effects:
            failures.append("no_effect_recovered_in_bounded_call_slice")
        interaction = {
            "id": _stable_id("interaction-chain", trigger["id"]),
            "trigger_id": trigger["id"],
            "classification": chain_classification,
            "screen_ids": trigger["screen_ids"],
            "handler_method_ids": trigger["handler_method_ids"],
            "handler_function_ids": trigger["handler_function_ids"],
            "call_slice_id": call_slice["id"],
            "effect_ids": [item["id"] for item in ordered_effects],
            "evidence": [_evidence(
                "interaction_chain_join",
                "analysis/interaction-model.json",
                source_object=trigger["id"],
                basis="The trigger handler roots, bounded call slice, and effects are joined by exact identifiers",
                confidence=_confidence(chain_classification),
            )],
            "failure_reasons": sorted(set(failures)),
        }
        interactions.append(interaction)
        for record in [trigger, *ordered_effects, interaction]:
            if record["classification"] == "candidate_set":
                hypotheses.append({
                    "id": _stable_id("interaction-hypothesis", record["id"]),
                    "kind": "candidate_interaction_record",
                    "subject_id": record["id"],
                    "confidence": "medium",
                    "basis": (record.get("failure_reasons") or [
                        "At least one evidence join retains multiple possible targets"
                    ])[0],
                })

    effects.sort(key=lambda item: (item["trigger_id"], item["kind"], _address_key(item.get("call_site")), item["id"]))
    interactions.sort(key=lambda item: (tuple(item["screen_ids"]), item["trigger_id"], item["id"]))
    call_slices.sort(key=lambda item: item["trigger_id"])
    hypotheses.sort(key=lambda item: item["id"])
    classified_records = [*triggers, *effects, *interactions]
    counts = Counter(str(item["classification"]) for item in classified_records)
    failure_counts = Counter(
        reason for item in classified_records for reason in item.get("failure_reasons", [])
    )
    effect_kind_counts = Counter(str(item["kind"]) for item in effects)
    trigger_kind_counts = Counter(str(item["kind"]) for item in triggers)

    indexes = {
        "interactions_by_screen": [
            {
                "screen_id": screen_id,
                "interaction_ids": sorted(item["id"] for item in interactions if screen_id in item["screen_ids"]),
            }
            for screen_id in sorted(screen_by_id)
        ],
        "triggers_by_kind": [
            {"trigger_kind": kind, "trigger_ids": sorted(item["id"] for item in triggers if item["kind"] == kind)}
            for kind in TRIGGER_KINDS
        ],
        "effects_by_kind": [
            {"effect_kind": kind, "effect_ids": sorted(item["id"] for item in effects if item["kind"] == kind)}
            for kind in EFFECT_KINDS
        ],
        "interactions_by_handler": [
            {
                "function_id": function_id,
                "interaction_ids": sorted(item["id"] for item in interactions if function_id in item["handler_function_ids"]),
            }
            for function_id in sorted({
                value for item in interactions for value in item["handler_function_ids"]
            })
        ],
    }
    summary = {
        "trigger_count": len(triggers),
        "interaction_count": len(interactions),
        "effect_count": len(effects),
        "call_slice_count": len(call_slices),
        "call_slice_function_count": sum(len(item["nodes"]) for item in call_slices),
        "call_slice_edge_count": sum(len(item["edges"]) for item in call_slices),
        "truncated_call_slice_count": sum(bool(item["truncated"]) for item in call_slices),
        "pseudocode_artifact_count": len(pseudocode_artifacts),
        "state_read_count": effect_kind_counts.get("state_read", 0),
        "state_write_count": effect_kind_counts.get("state_write", 0),
        "navigation_effect_count": effect_kind_counts.get("navigation", 0),
        "ui_update_count": effect_kind_counts.get("ui_update", 0),
        "persistence_effect_count": sum(effect_kind_counts.get(value, 0) for value in ("persistence_read", "persistence_write", "persistence_access")),
        "network_request_count": effect_kind_counts.get("network_request", 0),
        "notification_post_count": effect_kind_counts.get("notification_post", 0),
        "timer_schedule_count": effect_kind_counts.get("timer_schedule", 0),
        "platform_api_effect_count": effect_kind_counts.get("platform_api", 0),
        "trigger_kind_counts": {kind: trigger_kind_counts.get(kind, 0) for kind in TRIGGER_KINDS},
        "effect_kind_counts": {kind: effect_kind_counts.get(kind, 0) for kind in EFFECT_KINDS},
        "classified_record_count": len(classified_records),
        "classification_counts": {name: counts.get(name, 0) for name in CLASSIFICATIONS},
        "failure_reason_counts": dict(sorted(failure_counts.items())),
        "error_count": 0,
    }
    facts = {
        "catalog": {
            "catalog_id": catalog["catalog_id"],
            "catalog_version": catalog["catalog_version"],
            "sha256": catalog_sha256,
            "lifecycle_selector_count": len(catalog["lifecycle_selectors"]),
            "registration_selector_count": len({
                *(str(item["selector"]) for item in catalog["notification_registrations"]),
                *(str(item["selector"]) for item in catalog["timer_registrations"]),
                *(str(item["selector"]) for item in catalog["callback_registrations"]),
            }),
            "effect_selector_count": len(catalog["effect_selectors"]),
            "imported_effect_count": len(catalog["imported_effects"]),
            "bounds": bounds,
        },
        "input_artifacts": _input_artifacts(workspace, REQUIRED_REPORTS),
        "summary": summary,
        "screens": [
            {
                "id": str(item["id"]),
                "name": str(item.get("name") or item["id"]),
                "classification": str(item.get("classification") or "unresolved"),
                "controller_class_name": str(item.get("controller_class_name") or "") or None,
            }
            for item in sorted(screens, key=lambda value: str(value.get("id") or ""))
        ],
        "triggers": triggers,
        "call_slices": call_slices,
        "effects": effects,
        "interactions": interactions,
        "pseudocode_artifacts": pseudocode_artifacts,
        "indexes": indexes,
        "evidence_boundary": {
            "application_specific_rules_used": False,
            "names_used_to_invent_behavior": False,
            "function_level_resources_promoted_to_arguments": False,
            "objective_c_dynamic_edges_treated_as_facts": False,
            "call_slices_claim_runtime_coverage": False,
            "ui_model_reparsed_or_duplicated": False,
            "upstream_artifacts_preserved": True,
        },
    }
    model = report_envelope("interaction-model", facts, hypotheses=hypotheses, errors=[])
    interaction_model_path = workspace / "analysis" / "interaction-model.json"
    report_path = workspace / "reports" / "interaction-reconstruction-report.md"
    write_json_atomic(interaction_model_path, model)
    write_text_atomic(report_path, _render_report(facts))
    return InteractionRecoveryResult(workspace, model, interaction_model_path, report_path)
