"""Deterministic, evidence-bounded behavioral lifting and state synthesis."""

from __future__ import annotations

import hashlib
import importlib.resources
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .errors import IPALiftError
from .util import report_envelope, sha256_file, write_json_atomic, write_text_atomic


class BehaviorLiftError(IPALiftError):
    """A workspace cannot support trustworthy behavioral lifting."""


@dataclass(frozen=True)
class BehaviorLiftResult:
    workspace: Path
    behavior_ir: dict[str, Any]
    behavior_ir_path: Path
    state_model: dict[str, Any]
    state_model_path: Path
    report_path: Path


REQUIRED_REPORTS = (
    "functions",
    "callgraph",
    "recovered-code-index",
    "objc-dispatch",
    "objc-type-flow",
    "platform-api-map",
    "native-type-flow",
    "ui-model",
    "interaction-model",
)
CLASSIFICATIONS = ("exact", "candidate_set", "unresolved")
_ADDRESS = re.compile(r"^0x[0-9a-f]+$")
_SIGNATURE = re.compile(
    r"^\s*(?P<return>[^{}();]+?)\s+(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<parameters>.*)\)\s*$",
    re.DOTALL,
)
_IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]*")
_BRANCH = re.compile(r"\b(if|switch|while|for)\s*\(")
_RETURN = re.compile(r"\breturn\b\s*(.*?)\s*;")
_STRING = re.compile(r'(?P<prefix>@|u8|u|U|L)?"(?P<value>(?:\\.|[^"\\])*)"')
_NUMBER = re.compile(
    r"(?<![\w.])(?:0[xX][0-9a-fA-F]+|[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?)(?:[uUlLfF]+)?(?![\w.])"
)


def _stable_id(kind: str, *parts: Any) -> str:
    identity = "\0".join([kind, *(str(part) for part in parts)])
    return f"{kind}:{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:20]}"


def _classification(*values: str) -> str:
    normalized = [value for value in values if value in CLASSIFICATIONS]
    if "unresolved" in normalized:
        return "unresolved"
    if "candidate_set" in normalized:
        return "candidate_set"
    return "exact"


def _candidate_classification(value: str) -> str:
    return "unresolved" if value == "unresolved" else "candidate_set"


def _records(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        return [item for _, item in sorted(value.items()) if isinstance(item, dict)]
    return []


def _load_policy() -> tuple[dict[str, Any], str]:
    resource = importlib.resources.files("ipalift").joinpath("catalogs/behavior-policy-v1.json")
    try:
        data = resource.read_bytes()
        document = json.loads(data.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BehaviorLiftError(f"Cannot load the behavior policy: {exc}") from exc
    required = {
        "catalog_id", "catalog_version", "description", "bounds",
        "async_trigger_kinds", "branch_keywords",
    }
    if not isinstance(document, dict) or set(document) != required:
        raise BehaviorLiftError("Behavior policy has an invalid top-level shape")
    if document["catalog_id"] != "ipalift-behavior-policy":
        raise BehaviorLiftError("Behavior policy has an unexpected identity")
    expected_bounds = {
        "max_input_report_bytes", "max_total_input_report_bytes",
        "max_pseudocode_bytes_per_function", "max_total_pseudocode_bytes",
        "max_functions", "max_parameters_per_function",
        "max_branch_guards_per_function", "max_constants_per_function",
        "max_state_accesses_per_function", "max_call_edges",
        "max_async_callbacks", "max_transitions", "max_evidence_links_per_record",
    }
    bounds = document.get("bounds")
    if (
        not isinstance(bounds, dict)
        or set(bounds) != expected_bounds
        or any(not isinstance(bounds[key], int) or bounds[key] <= 0 for key in expected_bounds)
    ):
        raise BehaviorLiftError("Behavior policy has invalid resource bounds")
    if sorted(document["async_trigger_kinds"]) != ["callback", "notification", "timer"]:
        raise BehaviorLiftError("Behavior policy has invalid asynchronous trigger kinds")
    if sorted(document["branch_keywords"]) != ["for", "if", "switch", "while"]:
        raise BehaviorLiftError("Behavior policy has invalid branch keywords")
    return document, hashlib.sha256(data).hexdigest()


def _load_reports(
    workspace: Path,
    names: Iterable[str],
    bounds: dict[str, int],
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    reports: dict[str, dict[str, Any]] = {}
    artifacts: list[dict[str, Any]] = []
    total = 0
    for name in names:
        path = workspace / "analysis" / f"{name}.json"
        try:
            size = path.stat().st_size
        except FileNotFoundError as exc:
            raise BehaviorLiftError(f"Analysis workspace is missing analysis/{name}.json") from exc
        except OSError as exc:
            raise BehaviorLiftError(f"Cannot stat {path}: {exc}") from exc
        if size > bounds["max_input_report_bytes"]:
            raise BehaviorLiftError(
                f"analysis/{name}.json is {size} bytes; limit is {bounds['max_input_report_bytes']}"
            )
        total += size
        if total > bounds["max_total_input_report_bytes"]:
            raise BehaviorLiftError(
                f"Input reports total more than {bounds['max_total_input_report_bytes']} bytes"
            )
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BehaviorLiftError(f"Cannot read {path}: {exc}") from exc
        if (
            document.get("schema_version") != 1
            or document.get("artifact") != name
            or not isinstance(document.get("facts"), dict)
            or not isinstance(document.get("hypotheses"), list)
            or not isinstance(document.get("errors"), list)
        ):
            raise BehaviorLiftError(f"Invalid IPALift {name} report: {path}")
        digest = sha256_file(path)
        reports[name] = document
        artifacts.append({
            "artifact": name,
            "path": f"analysis/{name}.json",
            "sha256": digest,
            "size": size,
        })
    hashes = {item["artifact"]: item["sha256"] for item in artifacts}
    # Dispatch pass two intentionally consumes the previous type-flow pass; validate only
    # final downstream consumers whose fingerprints must describe the current artifacts.
    for consumer in ("objc-type-flow", "platform-api-map", "native-type-flow", "ui-model", "interaction-model"):
        report = reports[consumer]
        references = report["facts"].get("input_artifacts", [])
        if isinstance(references, dict):
            iterator = ({"artifact": name, **reference} for name, reference in references.items())
        elif isinstance(references, list):
            iterator = references
        else:
            raise BehaviorLiftError(f"Invalid input_artifacts in analysis/{consumer}.json")
        for reference in iterator:
            if not isinstance(reference, dict):
                raise BehaviorLiftError(f"Invalid input artifact reference in analysis/{consumer}.json")
            artifact = str(reference.get("artifact") or "")
            expected = str(reference.get("sha256") or "")
            if artifact in hashes and expected and expected != hashes[artifact]:
                raise BehaviorLiftError(
                    f"analysis/{consumer}.json was built from a different {artifact} artifact"
                )
    return reports, artifacts


def _assert_inputs_unchanged(workspace: Path, artifacts: Iterable[dict[str, Any]]) -> None:
    for artifact in artifacts:
        path = workspace / Path(*str(artifact["path"]).split("/"))
        try:
            digest = sha256_file(path)
        except OSError as exc:
            raise BehaviorLiftError(f"Cannot revalidate upstream artifact {artifact['path']}: {exc}") from exc
        if digest != artifact["sha256"]:
            raise BehaviorLiftError(f"Upstream artifact changed while lifting behavior: {artifact['path']}")


def _relative_file(workspace: Path, relative: str) -> Path:
    portable = relative.replace("\\", "/")
    parts = portable.split("/")
    if (
        not portable
        or portable.startswith("/")
        or re.match(r"^[A-Za-z]:", portable)
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise BehaviorLiftError(f"Artifact path escapes the analysis workspace: {relative}")
    candidate = (workspace / Path(*parts)).resolve()
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise BehaviorLiftError(f"Artifact path escapes the analysis workspace: {relative}") from exc
    return candidate


def _load_pseudocode(
    workspace: Path,
    functions: list[dict[str, Any]],
    bounds: dict[str, int],
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    if len(functions) > bounds["max_functions"]:
        raise BehaviorLiftError(
            f"Recovered function count {len(functions)} exceeds limit {bounds['max_functions']}"
        )
    code_by_function: dict[str, str] = {}
    artifacts: list[dict[str, Any]] = []
    total = 0
    for function in sorted(functions, key=lambda item: str(item.get("function_id") or "")):
        function_id = str(function.get("function_id") or "")
        decompilation = function.get("decompilation") or {}
        if decompilation.get("status") != "success" or not decompilation.get("output_path"):
            continue
        relative = str(decompilation["output_path"])
        path = _relative_file(workspace, relative)
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise BehaviorLiftError(f"Cannot stat pseudocode artifact {relative}: {exc}") from exc
        if size > bounds["max_pseudocode_bytes_per_function"]:
            raise BehaviorLiftError(
                f"Pseudocode artifact {relative} is {size} bytes; limit is "
                f"{bounds['max_pseudocode_bytes_per_function']}"
            )
        total += size
        if total > bounds["max_total_pseudocode_bytes"]:
            raise BehaviorLiftError(
                f"Pseudocode artifacts total more than {bounds['max_total_pseudocode_bytes']} bytes"
            )
        digest = sha256_file(path)
        expected = str(decompilation.get("sha256") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise BehaviorLiftError(f"Verified pseudocode hash is missing for {relative}")
        if expected != digest:
            raise BehaviorLiftError(f"Pseudocode hash mismatch for {relative}")
        try:
            code = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise BehaviorLiftError(f"Cannot read pseudocode artifact {relative}: {exc}") from exc
        if function_id in code_by_function:
            raise BehaviorLiftError(f"Duplicate successful pseudocode for function {function_id}")
        code_by_function[function_id] = code
        artifacts.append({
            "function_id": function_id,
            "path": relative.replace("\\", "/"),
            "sha256": digest,
            "size": size,
            "line_count": len(code.splitlines()),
        })
    return code_by_function, artifacts


def _unique_positions(
    records: Iterable[dict[str, Any]],
    key: str,
    source: str,
) -> tuple[dict[str, dict[str, Any]], dict[str, int]]:
    values: dict[str, dict[str, Any]] = {}
    positions: dict[str, int] = {}
    for index, record in enumerate(records):
        identity = str(record.get(key) or "")
        if not identity:
            continue
        if identity in values:
            raise BehaviorLiftError(f"Duplicate {key} {identity!r} in {source}")
        values[identity] = record
        positions[identity] = index
    return values, positions


def _artifact_link(
    artifact: str,
    collection: str,
    position: int,
    record_id: str,
    classification: str,
    hashes: dict[str, str],
) -> dict[str, Any]:
    return {
        "kind": "artifact_record",
        "artifact": artifact,
        "path": f"analysis/{artifact}.json",
        "json_pointer": f"/facts/{collection}/{position}",
        "record_id": record_id,
        "classification": classification,
        "sha256": hashes[artifact],
    }


def _pseudocode_link(artifact: dict[str, Any], line: int | None = None) -> dict[str, Any]:
    return {
        "kind": "pseudocode",
        "artifact": "pseudocode",
        "path": artifact["path"],
        "json_pointer": f"/lines/{line}" if line else "",
        "record_id": artifact["function_id"],
        "classification": "exact",
        "sha256": artifact["sha256"],
    }


def _dedupe_links(links: Iterable[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    unique: dict[tuple[Any, ...], dict[str, Any]] = {}
    for link in links:
        key = (
            link["kind"], link["artifact"], link["path"], link["json_pointer"],
            link["record_id"], link["classification"], link["sha256"],
        )
        unique[key] = link
    return [unique[key] for key in sorted(unique)[:limit]]


def _split_parameters(source: str, limit: int) -> list[str]:
    source = source.strip()
    if not source or source == "void":
        return []
    result: list[str] = []
    current: list[str] = []
    depth = 0
    for character in source:
        if character in "([{<":
            depth += 1
        elif character in ")]}>" and depth:
            depth -= 1
        if character == "," and depth == 0:
            result.append("".join(current).strip())
            current = []
        else:
            current.append(character)
    if current:
        result.append("".join(current).strip())
    if len(result) > limit:
        raise BehaviorLiftError(f"Function parameter count {len(result)} exceeds limit {limit}")
    return result


def _signature_source(code: str) -> tuple[str, int]:
    prefix = code.split("{", 1)[0].strip()
    return " ".join(prefix.split()), max(1, prefix.count("\n") + 1)


def _candidate_types(record: dict[str, Any] | None) -> list[str]:
    if not record:
        return []
    result = []
    for candidate in record.get("type_candidates") or []:
        if not isinstance(candidate, dict):
            continue
        value = candidate.get("class_name") or candidate.get("type_name") or candidate.get("name")
        if value:
            result.append(str(value))
    declared = record.get("declared_type") or record.get("declared_encoding")
    if declared:
        result.append(str(declared))
    return sorted(set(result))


def _parse_signature(
    function_id: str,
    code: str,
    type_records: list[tuple[str, dict[str, Any], int]],
    pseudocode: dict[str, Any],
    input_hashes: dict[str, str],
    bounds: dict[str, int],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    source, _ = _signature_source(code)
    match = _SIGNATURE.match(source)
    failures: list[str] = []
    if match is None:
        failures.append("decompiler_function_signature_not_parsed")
        signature = {
            "name": None,
            "declared_return_type": None,
            "source_text": source or None,
            "classification": "unresolved",
            "evidence": [_pseudocode_link(pseudocode, 1)],
            "failure_reasons": failures[:],
        }
        return signature, [], failures
    raw_parameters = _split_parameters(
        match.group("parameters"), bounds["max_parameters_per_function"]
    )
    parameter_types = [
        item for item in type_records
        if str(item[1].get("kind") or "") in {
            "function_parameter", "parameter", "method_parameter", "argument"
        }
    ]
    parameters: list[dict[str, Any]] = []
    used_type_ids: set[str] = set()
    for position, raw in enumerate(raw_parameters):
        identifiers = _IDENTIFIER.findall(raw)
        name = identifiers[-1] if identifiers else f"parameter_{position}"
        declared_type = raw[: raw.rfind(name)].strip() if name in raw else raw
        declared_type = declared_type or None
        match_record: tuple[str, dict[str, Any], int] | None = next(
            (
                item for item in parameter_types
                if str(item[1].get("name") or "") == name and str(item[1].get("id") or "") not in used_type_ids
            ),
            None,
        )
        if match_record is None:
            match_record = next(
                (
                    item for item in parameter_types
                    if item[1].get("position") == position
                    and str(item[1].get("id") or "") not in used_type_ids
                ),
                None,
            )
        if match_record is None:
            unpositioned = [
                item for item in parameter_types
                if not isinstance(item[1].get("position"), int)
                and str(item[1].get("id") or "") not in used_type_ids
            ]
            if position < len(unpositioned):
                match_record = unpositioned[position]
        links = [_pseudocode_link(pseudocode, 1)]
        classification = "candidate_set"
        type_candidates: list[str] = []
        reasons = ["decompiler_parameter_signature_requires_validation"]
        type_value_ids: list[str] = []
        if match_record is not None:
            artifact, record, index = match_record
            type_id = str(record.get("id") or "")
            used_type_ids.add(type_id)
            type_value_ids.append(type_id)
            type_candidates = _candidate_types(record)
            classification = _classification(
                "candidate_set", str(record.get("classification") or "unresolved")
            )
            links.append(_artifact_link(
                artifact, "values", index, type_id,
                str(record.get("classification") or "unresolved"), input_hashes,
            ))
            reasons.extend(str(value) for value in record.get("failure_reasons") or [])
        parameters.append({
            "position": position,
            "name": name,
            "declared_type": declared_type,
            "source_text": raw,
            "type_value_ids": sorted(type_value_ids),
            "type_candidates": type_candidates,
            "classification": classification,
            "evidence": _dedupe_links(links, bounds["max_evidence_links_per_record"]),
            "failure_reasons": sorted(set(reasons)),
        })
    signature = {
        "name": match.group("name"),
        "declared_return_type": match.group("return").strip(),
        "source_text": source,
        "classification": "candidate_set",
        "evidence": [_pseudocode_link(pseudocode, 1)],
        "failure_reasons": ["decompiler_function_signature_requires_validation"],
    }
    return signature, parameters, failures


def _parenthesized_expression(line: str, open_index: int) -> str | None:
    depth = 0
    in_string = False
    escaped = False
    for index in range(open_index, len(line)):
        character = line[index]
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return line[open_index + 1:index].strip()
    return None


def _branch_guards(
    function_id: str,
    code: str,
    pseudocode: dict[str, Any],
    bounds: dict[str, int],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for line_number, line in enumerate(code.splitlines(), 1):
        for ordinal, match in enumerate(_BRANCH.finditer(line)):
            expression = _parenthesized_expression(line, line.find("(", match.start()))
            classification = "candidate_set" if expression is not None else "unresolved"
            reasons = ["static_guard_does_not_prove_runtime_path"]
            if expression is None:
                reasons.append("multiline_or_malformed_guard_not_parsed")
            result.append({
                "id": _stable_id("behavior-guard", function_id, line_number, ordinal, match.group(1), expression),
                "function_id": function_id,
                "kind": match.group(1),
                "expression": expression,
                "pseudocode_line": line_number,
                "classification": classification,
                "evidence": [_pseudocode_link(pseudocode, line_number)],
                "failure_reasons": sorted(set(reasons)),
            })
            if len(result) > bounds["max_branch_guards_per_function"]:
                raise BehaviorLiftError(
                    f"Function {function_id} exceeds branch guard limit "
                    f"{bounds['max_branch_guards_per_function']}"
                )
    return result


def _return_behavior(
    function_id: str,
    code: str,
    signature: dict[str, Any],
    pseudocode: dict[str, Any],
    bounds: dict[str, int],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    sites: list[dict[str, Any]] = []
    for line_number, line in enumerate(code.splitlines(), 1):
        for ordinal, match in enumerate(_RETURN.finditer(line)):
            expression = match.group(1).strip() or None
            sites.append({
                "id": _stable_id("behavior-return", function_id, line_number, ordinal, expression),
                "function_id": function_id,
                "expression": expression,
                "pseudocode_line": line_number,
                "classification": "candidate_set",
                "evidence": [_pseudocode_link(pseudocode, line_number)],
                "failure_reasons": ["decompiler_return_expression_requires_validation"],
            })
    declared = signature.get("declared_return_type")
    if declared == "void":
        mode = "void"
        classification = signature["classification"]
        reasons = ["decompiler_return_type_requires_validation"]
    elif sites:
        mode = "explicit_values"
        classification = "candidate_set"
        reasons = ["static_return_sites_do_not_prove_runtime_result"]
    else:
        mode = "implicit_or_unresolved"
        classification = "unresolved"
        reasons = ["nonvoid_return_site_not_recovered"]
    behavior = {
        "declared_type": declared,
        "mode": mode,
        "return_site_ids": [item["id"] for item in sites],
        "expressions": sorted({str(item["expression"]) for item in sites if item["expression"] is not None}),
        "classification": classification,
        "evidence": _dedupe_links(
            [signature["evidence"][0], *[item["evidence"][0] for item in sites]],
            bounds["max_evidence_links_per_record"],
        ),
        "failure_reasons": reasons,
    }
    return behavior, sites


def _constants(
    function_id: str,
    code: str,
    pseudocode: dict[str, Any],
    bounds: dict[str, int],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for line_number, line in enumerate(code.splitlines(), 1):
        string_ranges: list[tuple[int, int]] = []
        ordinal = 0
        for match in _STRING.finditer(line):
            string_ranges.append(match.span())
            result.append({
                "id": _stable_id("behavior-constant", function_id, line_number, ordinal, "string", match.group("value")),
                "function_id": function_id,
                "kind": "string",
                "value": match.group("value"),
                "source_text": match.group(0),
                "pseudocode_line": line_number,
                "classification": "exact",
                "evidence": [_pseudocode_link(pseudocode, line_number)],
                "failure_reasons": [],
            })
            ordinal += 1
        for match in _NUMBER.finditer(line):
            if any(start <= match.start() < end for start, end in string_ranges):
                continue
            result.append({
                "id": _stable_id("behavior-constant", function_id, line_number, ordinal, "number", match.group(0)),
                "function_id": function_id,
                "kind": "number",
                "value": match.group(0),
                "source_text": match.group(0),
                "pseudocode_line": line_number,
                "classification": "exact",
                "evidence": [_pseudocode_link(pseudocode, line_number)],
                "failure_reasons": [],
            })
            ordinal += 1
        if len(result) > bounds["max_constants_per_function"]:
            raise BehaviorLiftError(
                f"Function {function_id} exceeds constant limit {bounds['max_constants_per_function']}"
            )
    return result


def _call_records(
    call_edges: list[dict[str, Any]],
    call_edge_positions: dict[int, int],
    call_slices: list[dict[str, Any]],
    input_hashes: dict[str, str],
    bounds: dict[str, int],
) -> list[dict[str, Any]]:
    result: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for edge_index, edge in enumerate(call_edges):
        caller = str(edge.get("caller_id") or edge.get("caller_function_id") or "")
        target = str(edge.get("target_function_id") or "") or None
        call_site = str(edge.get("call_site") or "") or None
        if not caller:
            continue
        if target and not edge.get("indirect"):
            classification = "exact"
        elif target:
            classification = "candidate_set"
        else:
            classification = "unresolved"
        key = (caller, call_site or "", target or "", "direct")
        record_id = _stable_id("behavior-call", *key)
        result[key] = {
            "id": record_id,
            "kind": "direct" if not edge.get("indirect") else "indirect",
            "caller_function_id": caller,
            "target_function_id": target,
            "call_site": call_site,
            "classification": classification,
            "evidence": [_artifact_link(
                "callgraph", "edges", call_edge_positions.get(id(edge), edge_index), record_id,
                classification, input_hashes,
            )],
            "failure_reasons": [] if target else ["call_target_not_recovered"],
        }
    for slice_index, call_slice in enumerate(call_slices):
        for edge_index, edge in enumerate(call_slice.get("edges") or []):
            if str(edge.get("kind") or "") != "objective_c_dynamic":
                continue
            caller = str(edge.get("caller_function_id") or "")
            target = str(edge.get("target_function_id") or "") or None
            call_site = str(edge.get("call_site") or "") or None
            if not caller:
                continue
            classification = str(edge.get("classification") or "candidate_set")
            key = (caller, call_site or "", target or "", "objective_c_dynamic")
            record_id = _stable_id("behavior-call", *key)
            link = {
                "kind": "artifact_record",
                "artifact": "interaction-model",
                "path": "analysis/interaction-model.json",
                "json_pointer": f"/facts/call_slices/{slice_index}/edges/{edge_index}",
                "record_id": str(edge.get("id") or record_id),
                "classification": classification,
                "sha256": input_hashes["interaction-model"],
            }
            if key in result:
                result[key]["classification"] = _classification(result[key]["classification"], classification)
                result[key]["evidence"] = _dedupe_links(
                    [*result[key]["evidence"], link], bounds["max_evidence_links_per_record"]
                )
            else:
                result[key] = {
                    "id": record_id,
                    "kind": "objective_c_dynamic",
                    "caller_function_id": caller,
                    "target_function_id": target,
                    "call_site": call_site,
                    "classification": classification,
                    "evidence": [link],
                    "failure_reasons": sorted(set(edge.get("failure_reasons") or [])),
                }
    if len(result) > bounds["max_call_edges"]:
        raise BehaviorLiftError(f"Call edge count {len(result)} exceeds limit {bounds['max_call_edges']}")
    return sorted(
        result.values(),
        key=lambda item: (
            item["caller_function_id"],
            int(item["call_site"], 16) if item["call_site"] and _ADDRESS.match(item["call_site"]) else 2**128,
            item["call_site"] or "",
            item["target_function_id"] or "",
            item["id"],
        ),
    )


def _state_accesses(
    effects: list[dict[str, Any]],
    effect_positions: dict[str, int],
    pseudocode_by_function: dict[str, dict[str, Any]],
    input_hashes: dict[str, str],
    bounds: dict[str, int],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    for effect in effects:
        kind = str(effect.get("kind") or "")
        if kind not in {"state_read", "state_write"}:
            continue
        function_id = str(effect.get("function_id") or "") or None
        state_id = str(effect.get("state_id") or "")
        effect_id = str(effect.get("id") or "")
        if not state_id or not effect_id:
            continue
        if function_id:
            counts[function_id] += 1
            if counts[function_id] > bounds["max_state_accesses_per_function"]:
                raise BehaviorLiftError(
                    f"Function {function_id} exceeds state access limit "
                    f"{bounds['max_state_accesses_per_function']}"
                )
        classification = str(effect.get("classification") or "unresolved")
        details = effect.get("details") or {}
        line = details.get("pseudocode_line")
        links = [_artifact_link(
            "interaction-model", "effects", effect_positions[effect_id], effect_id,
            classification, input_hashes,
        )]
        if function_id in pseudocode_by_function and isinstance(line, int) and line > 0:
            links.append(_pseudocode_link(pseudocode_by_function[function_id], line))
        result.append({
            "id": _stable_id("behavior-state-access", effect_id),
            "effect_id": effect_id,
            "trigger_id": str(effect.get("trigger_id") or ""),
            "function_id": function_id,
            "state_id": state_id,
            "access_kind": "read" if kind == "state_read" else "write",
            "expression": details.get("expression"),
            "pseudocode_line": line if isinstance(line, int) and line > 0 else None,
            "classification": classification,
            "evidence": _dedupe_links(links, bounds["max_evidence_links_per_record"]),
            "failure_reasons": sorted(set(str(value) for value in effect.get("failure_reasons") or [])),
        })
    return sorted(result, key=lambda item: (item["function_id"] or "", item["state_id"], item["access_kind"], item["id"]))


def _async_callbacks(
    triggers: list[dict[str, Any]],
    trigger_positions: dict[str, int],
    async_kinds: set[str],
    input_hashes: dict[str, str],
    bounds: dict[str, int],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for trigger in triggers:
        kind = str(trigger.get("kind") or "")
        if kind not in async_kinds:
            continue
        trigger_id = str(trigger.get("id") or "")
        classification = str(trigger.get("classification") or "unresolved")
        result.append({
            "id": _stable_id("behavior-async-callback", trigger_id),
            "trigger_id": trigger_id,
            "kind": kind,
            "event": trigger.get("event"),
            "selector": trigger.get("selector"),
            "callback_contract": trigger.get("callback_contract"),
            "notification_name": trigger.get("notification_name"),
            "timer_interval": trigger.get("timer_interval"),
            "handler_function_ids": sorted(set(str(value) for value in trigger.get("handler_function_ids") or [])),
            "registration_function_ids": sorted(set(str(value) for value in trigger.get("registration_function_ids") or [])),
            "classification": classification,
            "evidence": [_artifact_link(
                "interaction-model", "triggers", trigger_positions[trigger_id], trigger_id,
                classification, input_hashes,
            )],
            "failure_reasons": sorted(set(str(value) for value in trigger.get("failure_reasons") or [])),
        })
    if len(result) > bounds["max_async_callbacks"]:
        raise BehaviorLiftError(
            f"Asynchronous callback count {len(result)} exceeds limit {bounds['max_async_callbacks']}"
        )
    return sorted(result, key=lambda item: (item["kind"], item["trigger_id"], item["id"]))


def _type_records_by_function(
    reports: dict[str, dict[str, Any]],
) -> dict[str, list[tuple[str, dict[str, Any], int]]]:
    result: dict[str, list[tuple[str, dict[str, Any], int]]] = defaultdict(list)
    for artifact in ("objc-type-flow", "native-type-flow"):
        for index, record in enumerate(_records(reports[artifact]["facts"].get("values"))):
            function_id = str(record.get("function_id") or "")
            if function_id:
                result[function_id].append((artifact, record, index))
    for values in result.values():
        values.sort(key=lambda item: (
            int(item[1].get("position")) if isinstance(item[1].get("position"), int) else 2**31,
            str(item[1].get("id") or ""),
            item[0],
        ))
    return result


def _render_report(behavior: dict[str, Any], state: dict[str, Any]) -> str:
    behavior_summary = behavior["summary"]
    state_summary = state["summary"]
    lines = [
        "# IPALift behavioral lifting report",
        "",
        "> Static, evidence-linked implementation guidance. Contracts and transitions are not runtime traces or recovered original source.",
        "",
        "## Behavior IR",
        "",
        f"- Function contracts: {behavior_summary['function_contract_count']}",
        f"- Parameters: {behavior_summary['parameter_count']}",
        f"- Return sites: {behavior_summary['return_site_count']}",
        f"- Branch guards: {behavior_summary['branch_guard_count']}",
        f"- State reads / writes: {behavior_summary['state_read_count']} / {behavior_summary['state_write_count']}",
        f"- Constants: {behavior_summary['constant_count']}",
        f"- Calls: {behavior_summary['call_count']}",
        f"- Asynchronous callbacks: {behavior_summary['async_callback_count']}",
        "",
        "## State model",
        "",
        f"- State variables: {state_summary['state_variable_count']}",
        f"- Screen/application states: {state_summary['state_count']}",
        f"- Transition candidates: {state_summary['transition_count']}",
        f"- State machines: {state_summary['state_machine_count']}",
        "",
        "## Function contracts",
        "",
    ]
    for contract in behavior["function_contracts"]:
        signature = contract["signature"]
        lines.extend([
            f"### `{contract['function_id']}` {signature['name'] or ''}".rstrip(),
            "",
            f"- Classification: {contract['classification']}",
            f"- Parameters: {len(contract['parameters'])}",
            f"- Return behavior: {contract['return_behavior']['mode']}",
            f"- Guards: {len(contract['branch_guard_ids'])}",
            f"- State reads / writes: {len(contract['state_read_ids'])} / {len(contract['state_write_ids'])}",
            f"- Calls: {len(contract['outgoing_call_ids'])}",
            "",
        ])
    lines.extend([
        "## Evidence boundary",
        "",
        "- Pseudocode hashes and every upstream report fingerprint are verified before lifting.",
        "- Decompiler signatures, guards, returns, and synthesized transitions remain candidate or unresolved semantics.",
        "- Literal and record transcription can be exact evidence without becoming a runtime claim.",
        "- Names do not invent behavior, candidate sets are never promoted, and static call reachability is not execution coverage.",
        "- Complete machine-readable artifacts are in `analysis/behavior-ir.json` and `analysis/state-model.json`.",
        "",
    ])
    return "\n".join(lines)


def lift_behavior(workspace: Path) -> BehaviorLiftResult:
    """Lift verified static evidence into conservative contracts and state machines."""
    workspace = workspace.resolve()
    policy, policy_sha256 = _load_policy()
    bounds = {key: int(value) for key, value in policy["bounds"].items()}
    reports, input_artifacts = _load_reports(workspace, REQUIRED_REPORTS, bounds)
    input_hashes = {item["artifact"]: item["sha256"] for item in input_artifacts}

    recovered_facts = reports["recovered-code-index"]["facts"]
    recovered_functions = list(recovered_facts.get("functions") or [])
    recovered_methods = list(recovered_facts.get("methods") or [])
    functions_by_id, function_positions = _unique_positions(
        recovered_functions, "function_id", "analysis/recovered-code-index.json functions"
    )
    methods_by_id, method_positions = _unique_positions(
        recovered_methods, "id", "analysis/recovered-code-index.json methods"
    )
    code_by_function, pseudocode_artifacts = _load_pseudocode(
        workspace, recovered_functions, bounds
    )
    pseudocode_by_function = {item["function_id"]: item for item in pseudocode_artifacts}
    type_records = _type_records_by_function(reports)

    interaction_facts = reports["interaction-model"]["facts"]
    effects = list(interaction_facts.get("effects") or [])
    triggers = list(interaction_facts.get("triggers") or [])
    interactions = list(interaction_facts.get("interactions") or [])
    call_slices = list(interaction_facts.get("call_slices") or [])
    screens = list(interaction_facts.get("screens") or [])
    effects_by_id, effect_positions = _unique_positions(
        effects, "id", "analysis/interaction-model.json effects"
    )
    triggers_by_id, trigger_positions = _unique_positions(
        triggers, "id", "analysis/interaction-model.json triggers"
    )
    interactions_by_id, interaction_positions = _unique_positions(
        interactions, "id", "analysis/interaction-model.json interactions"
    )
    slices_by_id, slice_positions = _unique_positions(
        call_slices, "id", "analysis/interaction-model.json call_slices"
    )
    screens_by_id, screen_positions = _unique_positions(
        screens, "id", "analysis/interaction-model.json screens"
    )

    callgraph_edges = list(reports["callgraph"]["facts"].get("edges") or [])
    calls = _call_records(
        callgraph_edges,
        {id(item): index for index, item in enumerate(callgraph_edges)},
        call_slices,
        input_hashes,
        bounds,
    )
    state_accesses = _state_accesses(
        effects, effect_positions, pseudocode_by_function, input_hashes, bounds
    )
    async_callbacks = _async_callbacks(
        triggers,
        trigger_positions,
        set(str(value) for value in policy["async_trigger_kinds"]),
        input_hashes,
        bounds,
    )

    calls_by_caller: dict[str, list[str]] = defaultdict(list)
    calls_by_target: dict[str, list[str]] = defaultdict(list)
    for call in calls:
        calls_by_caller[call["caller_function_id"]].append(call["id"])
        if call["target_function_id"]:
            calls_by_target[call["target_function_id"]].append(call["id"])
    accesses_by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
    access_by_effect: dict[str, list[str]] = defaultdict(list)
    for access in state_accesses:
        if access["function_id"]:
            accesses_by_function[access["function_id"]].append(access)
        access_by_effect[access["effect_id"]].append(access["id"])
    callbacks_by_function: dict[str, list[str]] = defaultdict(list)
    for callback in async_callbacks:
        for function_id in [*callback["handler_function_ids"], *callback["registration_function_ids"]]:
            callbacks_by_function[function_id].append(callback["id"])

    interaction_ids_by_function: dict[str, set[str]] = defaultdict(set)
    screen_ids_by_function: dict[str, set[str]] = defaultdict(set)
    for interaction in interactions:
        interaction_id = str(interaction.get("id") or "")
        call_slice = slices_by_id.get(str(interaction.get("call_slice_id") or ""), {})
        function_ids = {
            *[str(value) for value in interaction.get("handler_function_ids") or []],
            *[str(node.get("function_id") or "") for node in call_slice.get("nodes") or []],
        }
        function_ids.discard("")
        for function_id in function_ids:
            interaction_ids_by_function[function_id].add(interaction_id)
            screen_ids_by_function[function_id].update(
                str(value) for value in interaction.get("screen_ids") or []
            )

    branch_guards: list[dict[str, Any]] = []
    return_sites: list[dict[str, Any]] = []
    constants: list[dict[str, Any]] = []
    function_contracts: list[dict[str, Any]] = []
    guards_by_function: dict[str, list[str]] = defaultdict(list)
    for function_id in sorted(functions_by_id):
        function = functions_by_id[function_id]
        code = code_by_function.get(function_id)
        function_link = _artifact_link(
            "recovered-code-index", "functions", function_positions[function_id], function_id,
            "exact" if code is not None else "unresolved", input_hashes,
        )
        method_ids = sorted(set(str(value) for value in function.get("method_ids") or []))
        method_links = [
            _artifact_link(
                "recovered-code-index", "methods", method_positions[method_id], method_id,
                "exact", input_hashes,
            )
            for method_id in method_ids if method_id in methods_by_id
        ]
        if code is None or function_id not in pseudocode_by_function:
            function_contracts.append({
                "id": _stable_id("behavior-contract", function_id),
                "function_id": function_id,
                "method_ids": method_ids,
                "screen_ids": sorted(screen_ids_by_function.get(function_id, set())),
                "interaction_ids": sorted(interaction_ids_by_function.get(function_id, set())),
                "signature": {
                    "name": None,
                    "declared_return_type": None,
                    "source_text": None,
                    "classification": "unresolved",
                    "evidence": [function_link],
                    "failure_reasons": ["verified_pseudocode_not_available"],
                },
                "parameters": [],
                "return_behavior": {
                    "declared_type": None,
                    "mode": "unavailable",
                    "return_site_ids": [],
                    "expressions": [],
                    "classification": "unresolved",
                    "evidence": [function_link],
                    "failure_reasons": ["verified_pseudocode_not_available"],
                },
                "branch_guard_ids": [],
                "state_read_ids": [item["id"] for item in accesses_by_function.get(function_id, []) if item["access_kind"] == "read"],
                "state_write_ids": [item["id"] for item in accesses_by_function.get(function_id, []) if item["access_kind"] == "write"],
                "constant_ids": [],
                "outgoing_call_ids": sorted(calls_by_caller.get(function_id, [])),
                "incoming_call_ids": sorted(calls_by_target.get(function_id, [])),
                "async_callback_ids": sorted(set(callbacks_by_function.get(function_id, []))),
                "classification": "unresolved",
                "evidence": _dedupe_links([function_link, *method_links], bounds["max_evidence_links_per_record"]),
                "failure_reasons": ["verified_pseudocode_not_available"],
            })
            continue
        pseudocode = pseudocode_by_function[function_id]
        signature, parameters, signature_failures = _parse_signature(
            function_id, code, type_records.get(function_id, []), pseudocode, input_hashes, bounds
        )
        function_guards = _branch_guards(function_id, code, pseudocode, bounds)
        return_behavior, function_returns = _return_behavior(
            function_id, code, signature, pseudocode, bounds
        )
        function_constants = _constants(function_id, code, pseudocode, bounds)
        branch_guards.extend(function_guards)
        return_sites.extend(function_returns)
        constants.extend(function_constants)
        guards_by_function[function_id].extend(item["id"] for item in function_guards)
        function_accesses = accesses_by_function.get(function_id, [])
        classification = _classification(
            "candidate_set",
            signature["classification"],
            return_behavior["classification"],
            *[item["classification"] for item in parameters],
        )
        failures = sorted(set([
            "decompiler_contract_does_not_prove_original_source_or_runtime_behavior",
            *signature_failures,
        ]))
        function_contracts.append({
            "id": _stable_id("behavior-contract", function_id),
            "function_id": function_id,
            "method_ids": method_ids,
            "screen_ids": sorted(screen_ids_by_function.get(function_id, set())),
            "interaction_ids": sorted(interaction_ids_by_function.get(function_id, set())),
            "signature": signature,
            "parameters": parameters,
            "return_behavior": return_behavior,
            "branch_guard_ids": [item["id"] for item in function_guards],
            "state_read_ids": [item["id"] for item in function_accesses if item["access_kind"] == "read"],
            "state_write_ids": [item["id"] for item in function_accesses if item["access_kind"] == "write"],
            "constant_ids": [item["id"] for item in function_constants],
            "outgoing_call_ids": sorted(calls_by_caller.get(function_id, [])),
            "incoming_call_ids": sorted(calls_by_target.get(function_id, [])),
            "async_callback_ids": sorted(set(callbacks_by_function.get(function_id, []))),
            "classification": classification,
            "evidence": _dedupe_links(
                [function_link, *method_links, _pseudocode_link(pseudocode)],
                bounds["max_evidence_links_per_record"],
            ),
            "failure_reasons": failures,
        })

    function_contracts.sort(key=lambda item: item["function_id"])
    branch_guards.sort(key=lambda item: (item["function_id"], item["pseudocode_line"], item["id"]))
    return_sites.sort(key=lambda item: (item["function_id"], item["pseudocode_line"], item["id"]))
    constants.sort(key=lambda item: (item["function_id"], item["pseudocode_line"], item["kind"], item["id"]))
    behavior_classified = [*function_contracts, *branch_guards, *state_accesses, *calls, *async_callbacks]
    behavior_counts = Counter(str(item["classification"]) for item in behavior_classified)
    behavior_failures = Counter(
        reason for item in behavior_classified for reason in item.get("failure_reasons", [])
    )
    behavior_summary = {
        "function_contract_count": len(function_contracts),
        "parameter_count": sum(len(item["parameters"]) for item in function_contracts),
        "return_site_count": len(return_sites),
        "branch_guard_count": len(branch_guards),
        "state_access_count": len(state_accesses),
        "state_read_count": sum(item["access_kind"] == "read" for item in state_accesses),
        "state_write_count": sum(item["access_kind"] == "write" for item in state_accesses),
        "constant_count": len(constants),
        "call_count": len(calls),
        "async_callback_count": len(async_callbacks),
        "pseudocode_artifact_count": len(pseudocode_artifacts),
        "classified_record_count": len(behavior_classified),
        "classification_counts": {name: behavior_counts.get(name, 0) for name in CLASSIFICATIONS},
        "failure_reason_counts": dict(sorted(behavior_failures.items())),
        "error_count": 0,
    }
    behavior_facts = {
        "policy": {
            "catalog_id": policy["catalog_id"],
            "catalog_version": policy["catalog_version"],
            "sha256": policy_sha256,
            "bounds": bounds,
        },
        "input_artifacts": input_artifacts,
        "summary": behavior_summary,
        "function_contracts": function_contracts,
        "return_sites": return_sites,
        "branch_guards": branch_guards,
        "state_accesses": state_accesses,
        "constants": constants,
        "calls": calls,
        "async_callbacks": async_callbacks,
        "pseudocode_artifacts": pseudocode_artifacts,
        "evidence_boundary": {
            "verified_pseudocode_only": True,
            "static_paths_claim_runtime_execution": False,
            "decompiler_types_claim_original_source_types": False,
            "names_used_to_invent_behavior": False,
            "candidate_sets_promoted": False,
            "application_specific_rules_used": False,
            "upstream_artifacts_preserved": True,
        },
    }
    behavior_hypotheses = [
        {
            "id": _stable_id("behavior-hypothesis", item["id"]),
            "kind": "candidate_behavior_record",
            "subject_id": item["id"],
            "confidence": "medium" if item["classification"] == "candidate_set" else "low",
            "basis": (
                "Static decompiler and upstream evidence support this candidate but do not prove runtime behavior."
                if item["classification"] == "candidate_set"
                else "Required evidence is missing or contradictory, so the behavior remains unresolved."
            ),
        }
        for item in behavior_classified if item["classification"] != "exact"
    ]
    behavior_ir = report_envelope(
        "behavior-ir", behavior_facts, hypotheses=behavior_hypotheses, errors=[]
    )
    behavior_ir_path = workspace / "analysis" / "behavior-ir.json"
    _assert_inputs_unchanged(workspace, input_artifacts)
    write_json_atomic(behavior_ir_path, behavior_ir)
    behavior_artifact = {
        "artifact": "behavior-ir",
        "path": "analysis/behavior-ir.json",
        "sha256": sha256_file(behavior_ir_path),
        "size": behavior_ir_path.stat().st_size,
    }

    # State variables preserve upstream storage identity and aggregate only explicit accesses.
    native_values = _records(reports["native-type-flow"]["facts"].get("values"))
    objc_values = _records(reports["objc-type-flow"]["facts"].get("values"))
    native_by_id = {str(item.get("id") or ""): item for item in native_values if item.get("id")}
    state_access_by_id = {item["id"]: item for item in state_accesses}
    accesses_by_state: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for access in state_accesses:
        accesses_by_state[access["state_id"]].append(access)
    state_variables: list[dict[str, Any]] = []
    for state_id in sorted(accesses_by_state):
        accesses = accesses_by_state[state_id]
        source_effects = [effects_by_id[item["effect_id"]] for item in accesses]
        details = [item.get("details") or {} for item in source_effects]
        owner_classes = sorted({str(item.get("class_name")) for item in details if item.get("class_name")})
        member_names = sorted({str(item.get("member_name")) for item in details if item.get("member_name")})
        type_records_for_state: list[dict[str, Any]] = []
        if state_id in native_by_id:
            type_records_for_state.append(native_by_id[state_id])
        for value in objc_values:
            if member_names and str(value.get("name") or "") in member_names:
                owner = str(value.get("owner_class") or value.get("class_name") or "")
                if not owner_classes or not owner or owner in owner_classes:
                    type_records_for_state.append(value)
        classifications = [item["classification"] for item in accesses]
        type_candidates = sorted({
            candidate
            for record in type_records_for_state
            for candidate in _candidate_types(record)
        })
        state_variables.append({
            "id": state_id,
            "owner_class_names": owner_classes,
            "member_names": member_names,
            "type_candidates": type_candidates,
            "read_access_ids": sorted(item["id"] for item in accesses if item["access_kind"] == "read"),
            "write_access_ids": sorted(item["id"] for item in accesses if item["access_kind"] == "write"),
            "reader_function_ids": sorted({str(item["function_id"]) for item in accesses if item["access_kind"] == "read" and item["function_id"]}),
            "writer_function_ids": sorted({str(item["function_id"]) for item in accesses if item["access_kind"] == "write" and item["function_id"]}),
            "observed_write_expressions": sorted({str(item["expression"]) for item in accesses if item["access_kind"] == "write" and item["expression"]}),
            "classification": _classification(*classifications),
            "evidence": _dedupe_links(
                [link for item in accesses for link in item["evidence"]],
                bounds["max_evidence_links_per_record"],
            ),
            "failure_reasons": sorted({
                reason for item in accesses for reason in item.get("failure_reasons", [])
            }),
        })

    state_nodes: list[dict[str, Any]] = []
    state_node_by_screen: dict[str, str] = {}
    for screen_id in sorted(screens_by_id):
        screen = screens_by_id[screen_id]
        node_id = _stable_id("state-node", "screen", screen_id)
        state_node_by_screen[screen_id] = node_id
        classification = str(screen.get("classification") or "unresolved")
        state_nodes.append({
            "id": node_id,
            "kind": "screen",
            "screen_id": screen_id,
            "name": str(screen.get("name") or screen_id),
            "classification": classification,
            "evidence": [_artifact_link(
                "interaction-model", "screens", screen_positions[screen_id], screen_id,
                classification, input_hashes,
            )],
            "failure_reasons": [],
        })

    guard_by_id = {item["id"]: item for item in branch_guards}
    transitions: list[dict[str, Any]] = []
    for interaction_id in sorted(interactions_by_id):
        interaction = interactions_by_id[interaction_id]
        trigger_id = str(interaction.get("trigger_id") or "")
        trigger = triggers_by_id.get(trigger_id, {})
        call_slice_id = str(interaction.get("call_slice_id") or "")
        call_slice = slices_by_id.get(call_slice_id, {})
        function_ids = sorted({
            *[str(value) for value in interaction.get("handler_function_ids") or []],
            *[str(node.get("function_id") or "") for node in call_slice.get("nodes") or []],
        } - {""})
        guard_ids = sorted({guard_id for function_id in function_ids for guard_id in guards_by_function.get(function_id, [])})
        effect_ids = [str(value) for value in interaction.get("effect_ids") or []]
        transition_access_ids = sorted({access_id for effect_id in effect_ids for access_id in access_by_effect.get(effect_id, [])})
        source_screen_ids = sorted(set(str(value) for value in interaction.get("screen_ids") or []))
        destination_screen_ids = sorted({
            str(value)
            for effect_id in effect_ids
            for value in effects_by_id.get(effect_id, {}).get("destination_screen_ids") or []
        })
        interaction_classification = str(interaction.get("classification") or "unresolved")
        classification = _candidate_classification(interaction_classification)
        links = [
            _artifact_link(
                "interaction-model", "interactions", interaction_positions[interaction_id],
                interaction_id, interaction_classification, input_hashes,
            )
        ]
        if trigger_id in trigger_positions:
            links.append(_artifact_link(
                "interaction-model", "triggers", trigger_positions[trigger_id], trigger_id,
                str(trigger.get("classification") or "unresolved"), input_hashes,
            ))
        if call_slice_id in slice_positions:
            links.append(_artifact_link(
                "interaction-model", "call_slices", slice_positions[call_slice_id], call_slice_id,
                interaction_classification, input_hashes,
            ))
        links.extend(link for guard_id in guard_ids for link in guard_by_id[guard_id]["evidence"])
        reasons = {
            "static_interaction_does_not_prove_runtime_transition",
            *[str(value) for value in interaction.get("failure_reasons") or []],
            *[str(value) for value in call_slice.get("failure_reasons") or []],
        }
        if guard_ids:
            reasons.add("guard_to_effect_path_not_proven")
        transitions.append({
            "id": _stable_id("state-transition", interaction_id),
            "interaction_id": interaction_id,
            "trigger_id": trigger_id,
            "event": trigger.get("event") or trigger.get("selector") or trigger.get("callback_contract") or trigger.get("kind"),
            "source_state_ids": sorted(state_node_by_screen[value] for value in source_screen_ids if value in state_node_by_screen),
            "destination_state_ids": sorted(state_node_by_screen[value] for value in destination_screen_ids if value in state_node_by_screen),
            "handler_function_ids": function_ids,
            "branch_guard_ids": guard_ids,
            "state_read_access_ids": sorted(access_id for access_id in transition_access_ids if state_access_by_id[access_id]["access_kind"] == "read"),
            "state_write_access_ids": sorted(access_id for access_id in transition_access_ids if state_access_by_id[access_id]["access_kind"] == "write"),
            "effect_ids": sorted(effect_ids),
            "async_callback_ids": sorted(
                callback["id"] for callback in async_callbacks if callback["trigger_id"] == trigger_id
            ),
            "classification": classification,
            "evidence": _dedupe_links(links, bounds["max_evidence_links_per_record"]),
            "failure_reasons": sorted(reasons),
        })
    if len(transitions) > bounds["max_transitions"]:
        raise BehaviorLiftError(
            f"Transition count {len(transitions)} exceeds limit {bounds['max_transitions']}"
        )

    state_variable_by_access = {
        access_id: variable["id"]
        for variable in state_variables
        for access_id in [*variable["read_access_ids"], *variable["write_access_ids"]]
    }
    state_machines: list[dict[str, Any]] = []
    machine_scopes: list[tuple[str, str | None, list[dict[str, Any]]]] = [
        ("application", None, transitions)
    ]
    for screen_id in sorted(state_node_by_screen):
        node_id = state_node_by_screen[screen_id]
        scoped = [item for item in transitions if node_id in item["source_state_ids"]]
        machine_scopes.append(("screen", screen_id, scoped))
    for scope, screen_id, scoped_transitions in machine_scopes:
        transition_ids = [item["id"] for item in scoped_transitions]
        state_ids = sorted({
            state_id
            for transition in scoped_transitions
            for state_id in [*transition["source_state_ids"], *transition["destination_state_ids"]]
        })
        variable_ids = sorted({
            state_variable_by_access[access_id]
            for transition in scoped_transitions
            for access_id in [*transition["state_read_access_ids"], *transition["state_write_access_ids"]]
            if access_id in state_variable_by_access
        })
        callback_ids = sorted({
            value for transition in scoped_transitions for value in transition["async_callback_ids"]
        })
        if scope == "application":
            evidence = _dedupe_links(
                [link for transition in scoped_transitions for link in transition["evidence"]],
                bounds["max_evidence_links_per_record"],
            )
            if not evidence:
                evidence = [{
                    "kind": "artifact_record",
                    "artifact": "behavior-ir",
                    "path": behavior_artifact["path"],
                    "json_pointer": "/facts",
                    "record_id": "behavior-ir",
                    "classification": "unresolved",
                    "sha256": behavior_artifact["sha256"],
                }]
        else:
            screen = screens_by_id[screen_id or ""]
            evidence = [_artifact_link(
                "interaction-model", "screens", screen_positions[screen_id or ""], screen_id or "",
                str(screen.get("classification") or "unresolved"), input_hashes,
            )]
        classification = (
            _classification(*[item["classification"] for item in scoped_transitions])
            if scoped_transitions else "unresolved"
        )
        state_machines.append({
            "id": _stable_id("state-machine", scope, screen_id or "application"),
            "scope": scope,
            "screen_id": screen_id,
            "state_ids": state_ids,
            "state_variable_ids": variable_ids,
            "transition_ids": transition_ids,
            "async_callback_ids": callback_ids,
            "classification": classification,
            "evidence": evidence,
            "failure_reasons": (
                ["static_state_machine_requires_runtime_validation"]
                if scoped_transitions else ["no_transition_recovered_for_scope"]
            ),
        })

    state_classified = [*state_variables, *state_nodes, *transitions, *state_machines]
    state_counts = Counter(str(item["classification"]) for item in state_classified)
    state_failures = Counter(
        reason for item in state_classified for reason in item.get("failure_reasons", [])
    )
    state_summary = {
        "state_variable_count": len(state_variables),
        "state_count": len(state_nodes),
        "transition_count": len(transitions),
        "state_machine_count": len(state_machines),
        "async_callback_count": len(async_callbacks),
        "classified_record_count": len(state_classified),
        "classification_counts": {name: state_counts.get(name, 0) for name in CLASSIFICATIONS},
        "failure_reason_counts": dict(sorted(state_failures.items())),
        "error_count": 0,
    }
    state_input_artifacts = [
        behavior_artifact,
        next(item for item in input_artifacts if item["artifact"] == "interaction-model"),
        next(item for item in input_artifacts if item["artifact"] == "objc-type-flow"),
        next(item for item in input_artifacts if item["artifact"] == "native-type-flow"),
    ]
    state_facts = {
        "policy": {
            "catalog_id": policy["catalog_id"],
            "catalog_version": policy["catalog_version"],
            "sha256": policy_sha256,
            "bounds": bounds,
        },
        "input_artifacts": state_input_artifacts,
        "summary": state_summary,
        "state_variables": state_variables,
        "states": state_nodes,
        "transitions": transitions,
        "state_machines": state_machines,
        "async_callbacks": async_callbacks,
        "evidence_boundary": {
            "transitions_claim_runtime_execution": False,
            "initial_runtime_state_invented": False,
            "guard_to_effect_paths_claimed_exact": False,
            "candidate_sets_promoted": False,
            "application_specific_rules_used": False,
            "upstream_artifacts_preserved": True,
        },
    }
    state_hypotheses = [
        {
            "id": _stable_id("state-hypothesis", item["id"]),
            "kind": "candidate_state_record",
            "subject_id": item["id"],
            "confidence": "medium" if item["classification"] == "candidate_set" else "low",
            "basis": (
                "The record composes explicit static evidence but requires runtime validation."
                if item["classification"] == "candidate_set"
                else "The record lacks enough evidence to form a bounded transition or state contract."
            ),
        }
        for item in state_classified if item["classification"] != "exact"
    ]
    state_model = report_envelope(
        "state-model", state_facts, hypotheses=state_hypotheses, errors=[]
    )
    state_model_path = workspace / "analysis" / "state-model.json"
    report_path = workspace / "reports" / "behavior-lifting-report.md"
    _assert_inputs_unchanged(workspace, input_artifacts)
    if sha256_file(behavior_ir_path) != behavior_artifact["sha256"]:
        raise BehaviorLiftError("behavior-ir.json changed while building state-model.json")
    write_json_atomic(state_model_path, state_model)
    write_text_atomic(report_path, _render_report(behavior_facts, state_facts))
    _assert_inputs_unchanged(workspace, input_artifacts)
    return BehaviorLiftResult(
        workspace,
        behavior_ir,
        behavior_ir_path,
        state_model,
        state_model_path,
        report_path,
    )
