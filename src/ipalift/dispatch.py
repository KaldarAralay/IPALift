"""Deterministic, evidence-bounded Objective-C dynamic dispatch analysis."""

from __future__ import annotations

import ast
import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .errors import IPALiftError
from .report import render_objc_dispatch_report
from .typeflow import dispatch_baseline_projection
from .util import report_envelope, sha256_file, write_json_atomic, write_text_atomic


class DispatchError(IPALiftError):
    """A workspace cannot support trustworthy Objective-C dispatch analysis."""


@dataclass(frozen=True)
class DispatchResult:
    workspace: Path
    dispatch: dict[str, Any]
    dispatch_path: Path
    report_path: Path


REQUIRED_REPORTS = ("callgraph", "functions", "strings", "recovered-code-index")
CLASSIFICATIONS = ("resolved", "candidate_set", "unresolved")
SELECTOR_STATUSES = ("resolved", "candidate_set", "unresolved")
RECEIVER_STATUSES = ("resolved", "candidate_set", "unresolved")
CONFIDENCE_LEVELS = ("high", "medium", "low")
_ADDRESS_PATTERN = re.compile(r"^0x[0-9a-f]+$")
_PSEUDO_CALL_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_$])(?P<callee>_?objc_msg(?:send|lookup)[A-Za-z0-9_$]*)\s*\(",
    re.IGNORECASE,
)
_CLASS_SYMBOL_PATTERN = re.compile(r"&?\s*objc::class_t::([A-Za-z_$][A-Za-z0-9_$]*)")


def _load_report(workspace: Path, name: str) -> dict[str, Any]:
    path = workspace / "analysis" / f"{name}.json"
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise DispatchError(f"Analysis workspace is missing analysis/{name}.json") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise DispatchError(f"Cannot read {path}: {exc}") from exc
    if (
        report.get("schema_version") != 1
        or report.get("artifact") != name
        or not isinstance(report.get("facts"), dict)
    ):
        raise DispatchError(f"Invalid IPALift {name} report: {path}")
    return report


def _relative_file(workspace: Path, relative: str) -> Path:
    portable = relative.replace("\\", "/")
    parts = portable.split("/")
    if (
        not portable
        or portable.startswith("/")
        or re.match(r"^[A-Za-z]:", portable)
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise DispatchError(f"Artifact path escapes the analysis workspace: {relative}")
    candidate = (workspace / Path(*parts)).resolve()
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise DispatchError(f"Artifact path escapes the analysis workspace: {relative}") from exc
    return candidate


def _address(value: Any) -> str | None:
    if value is None:
        return None
    try:
        number = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return None
    return f"0x{number:08x}"


def _address_key(value: str | None) -> tuple[int, str]:
    if value and _ADDRESS_PATTERN.match(value):
        return (0, f"{int(value, 16):016x}")
    return (1, value or "")


def _stable_id(kind: str, *parts: Any) -> str:
    identity = "\0".join([kind, *(str(part) for part in parts)])
    return f"{kind}:{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:20]}"


def _symbol_fragment(value: str) -> str:
    rendered = re.sub(r"[^A-Za-z0-9_$]", "_", value)
    rendered = re.sub(r"_+", "_", rendered).strip("_") or "anonymous"
    if rendered[0].isdigit():
        rendered = "n_" + rendered
    return rendered[:180]


def _runtime_info(edge: dict[str, Any]) -> dict[str, Any] | None:
    names = [
        str(value)
        for value in (edge.get("target_name"), edge.get("thunk_target_name"))
        if value
    ]
    matched = None
    normalized = None
    for name in names:
        candidate = re.sub(r"[^a-z0-9]", "", name.lower())
        if "objcmsgsend" in candidate or "objcmsglookup" in candidate:
            matched = name
            normalized = candidate
            break
    if matched is None or normalized is None:
        return None
    is_super = "super" in normalized
    if "objcmsgsendsuper2" in normalized and "stret" in normalized:
        variant = "objc_msgSendSuper2_stret"
    elif "objcmsgsendsuper2" in normalized:
        variant = "objc_msgSendSuper2"
    elif "objcmsgsendsuper" in normalized and "stret" in normalized:
        variant = "objc_msgSendSuper_stret"
    elif "objcmsgsendsuper" in normalized:
        variant = "objc_msgSendSuper"
    elif "objcmsgsendstret" in normalized:
        variant = "objc_msgSend_stret"
    elif "objcmsgsendfpret" in normalized:
        variant = "objc_msgSend_fpret"
    elif "objcmsgsend" in normalized:
        variant = "objc_msgSend"
    elif "objcmsglookupsuper" in normalized:
        variant = "objc_msgLookupSuper"
    else:
        variant = "objc_msgLookup"
    return {
        "name": matched,
        "variant": variant,
        "family": "super" if is_super else "normal",
        "super_dispatch": is_super,
        "structure_return": "stret" in normalized,
        "floating_point_return": "fpret" in normalized,
    }


def _matching_paren(text: str, opening: int) -> int | None:
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(opening, len(text)):
        char = text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _split_arguments(value: str) -> list[str]:
    arguments: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    escaped = False
    for index, char in enumerate(value):
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}" and depth:
            depth -= 1
        elif char == "," and depth == 0:
            arguments.append(value[start:index].strip())
            start = index + 1
    arguments.append(value[start:].strip())
    return arguments


def _string_literal(value: str) -> str | None:
    match = re.fullmatch(r'\s*"((?:\\.|[^"\\])*)"\s*', value, re.DOTALL)
    if not match:
        return None
    try:
        decoded = ast.literal_eval('"' + match.group(1) + '"')
    except (SyntaxError, ValueError):
        return None
    return decoded if isinstance(decoded, str) else None


def _first_parameter_name(code: str) -> str | None:
    header = code.split("{", 1)[0]
    match = re.search(r"\(([^()]*)\)\s*$", header.strip(), re.DOTALL)
    if not match:
        return None
    arguments = _split_arguments(match.group(1))
    if not arguments or arguments[0].strip() in {"", "void"}:
        return None
    name = re.search(r"([A-Za-z_$][A-Za-z0-9_$]*)\s*$", arguments[0])
    return name.group(1) if name else None


def _strip_casts(value: str) -> str:
    rendered = value.strip()
    cast = re.compile(r"^\([A-Za-z_$][A-Za-z0-9_$ :<>*]*\)\s*(.+)$", re.DOTALL)
    while True:
        match = cast.match(rendered)
        if not match:
            return rendered
        rendered = match.group(1).strip()


def _typed_variables(code: str, symbol_classes: dict[str, list[str]]) -> dict[str, list[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    pattern = re.compile(
        r"(?m)^\s*(?:struct\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*\*\s*"
        r"([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:;|=)"
    )
    for type_name, variable in pattern.findall(code):
        for class_name in symbol_classes.get(type_name, []):
            result[variable].add(class_name)
    return {name: sorted(values) for name, values in result.items()}


def _parse_pseudocode_calls(
    code: str,
    caller_methods: list[dict[str, Any]],
    symbol_classes: dict[str, list[str]],
) -> list[dict[str, Any]]:
    first_parameter = _first_parameter_name(code)
    typed = _typed_variables(code, symbol_classes)
    caller_contexts = sorted({
        (str(item.get("class_name")), str(item.get("kind")))
        for item in caller_methods
        if item.get("class_name") and item.get("kind") in {"instance", "class"}
    })
    records: list[dict[str, Any]] = []
    for match in _PSEUDO_CALL_PATTERN.finditer(code):
        opening = match.end() - 1
        closing = _matching_paren(code, opening)
        if closing is None:
            continue
        arguments = _split_arguments(code[opening + 1:closing])
        if len(arguments) < 2:
            continue
        selector = _string_literal(arguments[1])
        if selector is None:
            continue
        runtime = _runtime_info({"target_name": match.group("callee")})
        if runtime is None:
            continue
        receiver = _strip_casts(arguments[0])
        context = {
            "receiver_kind": "unknown",
            "class_names": [],
            "static_type": None,
            "receiver_expression": receiver[:240],
        }
        class_match = _CLASS_SYMBOL_PATTERN.fullmatch(receiver)
        if class_match:
            names = symbol_classes.get(class_match.group(1), [])
            if len(names) == 1:
                context.update({"receiver_kind": "class_object", "class_names": names})
        elif first_parameter and receiver == first_parameter and len(caller_contexts) == 1:
            context.update({
                "receiver_kind": "self",
                "class_names": [caller_contexts[0][0]],
                "static_type": caller_contexts[0][0],
            })
        elif receiver in typed and len(typed[receiver]) == 1:
            context.update({
                "receiver_kind": "typed_instance",
                "class_names": typed[receiver],
                "static_type": typed[receiver][0],
            })
        records.append({
            "callee": match.group("callee"),
            "runtime_family": runtime["family"],
            "selector": selector,
            **context,
        })
    return records


def _class_symbol_map(classes: list[dict[str, Any]]) -> dict[str, list[str]]:
    values: dict[str, set[str]] = defaultdict(set)
    for item in classes:
        name = str(item["name"])
        values[_symbol_fragment(name)].add(name)
        values[name].add(name)
    return {key: sorted(names) for key, names in values.items()}


def _class_from_reference(
    reference: dict[str, Any],
    address_classes: dict[str, list[str]],
    symbol_classes: dict[str, list[str]],
) -> list[str]:
    result: set[str] = set(address_classes.get(_address(reference.get("to_address")) or "", []))
    symbol = str(reference.get("target_symbol") or "")
    match = re.search(r"objc::class_t::([A-Za-z_$][A-Za-z0-9_$]*)", symbol)
    if match:
        result.update(symbol_classes.get(match.group(1), []))
    return sorted(result)


def _method_sort_key(method: dict[str, Any]) -> tuple[str, str, str, tuple[int, str], str]:
    return (
        str(method.get("architecture") or "unknown"),
        str(method.get("class_name") or "").casefold(),
        str(method.get("selector") or ""),
        _address_key(_address(method.get("canonical_address"))),
        str(method.get("id") or ""),
    )


class _Hierarchy:
    def __init__(self, classes: list[dict[str, Any]], methods: list[dict[str, Any]]):
        self.classes = {
            (str(item.get("architecture") or "unknown"), str(item["name"])): item
            for item in classes
        }
        self.methods_at: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
        self.methods_by_selector: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        self.architectures = sorted({str(item.get("architecture") or "unknown") for item in classes})
        for method in methods:
            architecture = str(method.get("architecture") or "unknown")
            class_name = str(method.get("class_name") or "")
            kind = str(method.get("kind") or "")
            selector = str(method.get("selector") or "")
            if class_name and kind and selector:
                self.methods_at[(architecture, class_name, kind, selector)].append(method)
                self.methods_by_selector[(architecture, selector)].append(method)
        for records in self.methods_at.values():
            records.sort(key=_method_sort_key)
        for records in self.methods_by_selector.values():
            records.sort(key=_method_sort_key)

        self.children: dict[tuple[str, str], set[str]] = defaultdict(set)
        for (architecture, class_name), item in self.classes.items():
            superclass = item.get("superclass") or {}
            super_name = superclass.get("name") if isinstance(superclass, dict) else superclass
            if super_name:
                self.children[(architecture, str(super_name))].add(class_name)

    def superclass(self, architecture: str, class_name: str) -> str | None:
        item = self.classes.get((architecture, class_name))
        if not item:
            return None
        superclass = item.get("superclass") or {}
        value = superclass.get("name") if isinstance(superclass, dict) else superclass
        return str(value) if value else None

    def descendants(self, architecture: str, class_name: str) -> list[str]:
        seen = {class_name}
        pending = [class_name]
        while pending:
            current = pending.pop()
            for child in sorted(self.children.get((architecture, current), set())):
                if child not in seen:
                    seen.add(child)
                    pending.append(child)
        return sorted(seen)

    def lookup(
        self, architecture: str, class_name: str, kind: str, selector: str
    ) -> tuple[list[dict[str, Any]], list[str]]:
        chain: list[str] = []
        seen: set[str] = set()
        current: str | None = class_name
        while current and current not in seen:
            seen.add(current)
            chain.append(current)
            records = self.methods_at.get((architecture, current, kind, selector), [])
            if records:
                return list(records), chain
            current = self.superclass(architecture, current)
        return [], chain

    def global_candidates(self, architectures: Iterable[str], selectors: Iterable[str]) -> list[dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for architecture in architectures:
            for selector in selectors:
                for method in self.methods_by_selector.get((architecture, selector), []):
                    result[str(method["id"])] = method
        return sorted(result.values(), key=_method_sort_key)


def _architecture_for_caller(
    caller: dict[str, Any], recovered_function: dict[str, Any], methods_by_id: dict[str, dict[str, Any]],
    known_architectures: list[str],
) -> str:
    values = {
        str(method.get("architecture"))
        for method in caller.get("objective_c_methods", [])
        if method.get("architecture")
    }
    values.update(
        str(methods_by_id[method_id].get("architecture"))
        for method_id in recovered_function.get("method_ids", [])
        if method_id in methods_by_id and methods_by_id[method_id].get("architecture")
    )
    if len(values) == 1:
        return next(iter(values))
    if not values and len(known_architectures) == 1:
        return known_architectures[0]
    return "unknown"


def _target_record(method: dict[str, Any], lookup_path: list[str] | None = None) -> dict[str, Any]:
    return {
        "method_id": method["id"],
        "function_id": method.get("function_id"),
        "mapping_status": method.get("mapping_status"),
        "exact_name": method.get("exact_name"),
        "class_name": method.get("class_name"),
        "category_name": method.get("category_name"),
        "kind": method.get("kind"),
        "selector": method.get("selector"),
        "canonical_address": method.get("canonical_address"),
        "implementation_pointer": method.get("implementation_pointer"),
        "lookup_path": lookup_path or [],
    }


def _targets_for_callsite(
    hierarchy: _Hierarchy,
    architecture: str,
    selector_record: dict[str, Any],
    receiver_record: dict[str, Any],
    caller_methods: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str], bool]:
    selectors = selector_record["candidates"]
    architectures = hierarchy.architectures if architecture == "unknown" else [architecture]
    exact_receiver = False
    targets: dict[str, dict[str, Any]] = {}
    lookup_notes: list[str] = []

    if len(selectors) == 1 and receiver_record["receiver_kind"] == "super":
        contexts = sorted({
            (str(method.get("architecture") or architecture), str(method.get("class_name")), str(method.get("kind")))
            for method in caller_methods
            if method.get("class_name") and method.get("kind") in {"instance", "class"}
        })
        if len(contexts) == 1:
            current_architecture, current_class, kind = contexts[0]
            start = hierarchy.superclass(current_architecture, current_class)
            if start:
                records, chain = hierarchy.lookup(current_architecture, start, kind, selectors[0])
                lookup_notes.append(" -> ".join(chain))
                for method in records:
                    targets[str(method["id"])] = _target_record(method, chain)
                exact_receiver = True
    elif len(selectors) == 1 and receiver_record["receiver_kind"] == "class_object" and len(receiver_record["class_candidates"]) == 1:
        class_name = receiver_record["class_candidates"][0]
        for candidate_architecture in architectures:
            records, chain = hierarchy.lookup(candidate_architecture, class_name, "class", selectors[0])
            if chain:
                lookup_notes.append(" -> ".join(chain))
            for method in records:
                targets[str(method["id"])] = _target_record(method, chain)
        exact_receiver = architecture != "unknown"
    elif len(selectors) == 1 and receiver_record["receiver_kind"] in {"self", "typed_instance"} and receiver_record["class_candidates"]:
        base = receiver_record["class_candidates"][0]
        kinds = sorted({str(method.get("kind")) for method in caller_methods if method.get("kind")}) \
            if receiver_record["receiver_kind"] == "self" else ["instance"]
        if not kinds:
            kinds = ["instance"]
        for candidate_architecture in architectures:
            for dynamic_class in hierarchy.descendants(candidate_architecture, base):
                for kind in kinds:
                    records, chain = hierarchy.lookup(candidate_architecture, dynamic_class, kind, selectors[0])
                    for method in records:
                        targets[str(method["id"])] = _target_record(method, chain)
                    if chain:
                        lookup_notes.append(" -> ".join(chain))
    else:
        for method in hierarchy.global_candidates(architectures, selectors):
            targets[str(method["id"])] = _target_record(method)
    return (
        sorted(targets.values(), key=lambda item: (
            str(item.get("class_name") or "").casefold(), str(item.get("kind") or ""),
            _address_key(_address(item.get("canonical_address"))), str(item["method_id"]),
        )),
        sorted(set(lookup_notes)),
        exact_receiver,
    )


def _selector_record(
    references: list[dict[str, Any]], strings_by_address: dict[str, dict[str, Any]],
    previous_site: int, call_site: int,
) -> dict[str, Any]:
    evidence: list[dict[str, Any]] = []
    for reference in references:
        from_address = _address(reference.get("from_address"))
        to_address = _address(reference.get("to_address"))
        if not from_address or not to_address or not (previous_site < int(from_address, 16) <= call_site):
            continue
        string = strings_by_address.get(to_address)
        if not string or not string.get("is_selector") or reference.get("reference_type") != "PARAM":
            continue
        evidence.append({
            "kind": "selector_reference",
            "value": str(string.get("value") or ""),
            "from_address": from_address,
            "to_address": to_address,
            "reference_type": reference.get("reference_type"),
            "source": "analysis/functions.json",
            "provenance": ["ghidra", "objective_c_metadata"],
            "confidence": "high",
            "basis": "Ghidra PARAM reference to a recovered selector string after the previous dispatch and before this callsite",
        })
    evidence.sort(key=lambda item: (_address_key(item["from_address"]), item["value"], item["to_address"]))
    candidates = sorted({item["value"] for item in evidence if item["value"]})
    status = "resolved" if len(candidates) == 1 else ("candidate_set" if candidates else "unresolved")
    return {"status": status, "value": candidates[0] if len(candidates) == 1 else None, "candidates": candidates, "evidence": evidence}


def _receiver_record(
    runtime: dict[str, Any], caller_methods: list[dict[str, Any]], pseudo_context: dict[str, Any] | None,
    class_references: list[dict[str, Any]], pseudocode: dict[str, Any] | None,
) -> dict[str, Any]:
    evidence: list[dict[str, Any]] = []
    if runtime["super_dispatch"]:
        contexts = sorted({
            (str(method.get("class_name")), str(method.get("kind")))
            for method in caller_methods
            if method.get("class_name") and method.get("kind") in {"instance", "class"}
        })
        if len(contexts) == 1:
            evidence.append({
                "kind": "super_context",
                "class_name": contexts[0][0],
                "method_kind": contexts[0][1],
                "source": "analysis/recovered-code-index.json",
                "provenance": ["objective_c_metadata", "objective_c_runtime_abi"],
                "confidence": "high",
                "basis": "Super dispatch occurs inside one exact recovered Objective-C method context",
            })
            return {
                "status": "resolved", "receiver_kind": "super", "class_candidates": [contexts[0][0]],
                "static_type": contexts[0][0], "dynamic_subclasses_possible": False, "evidence": evidence,
            }
    if pseudo_context and pseudo_context["receiver_kind"] != "unknown":
        evidence.append({
            "kind": "pseudocode_receiver",
            "receiver_expression": pseudo_context["receiver_expression"],
            "source": pseudocode["path"] if pseudocode else None,
            "sha256": pseudocode["sha256"] if pseudocode else None,
            "provenance": ["ghidra_pseudocode"],
            "confidence": "high" if pseudo_context["receiver_kind"] in {"class_object", "self"} else "medium",
            "basis": "Every matching pseudocode call has the same mechanically recognized receiver context",
        })
        receiver_kind = pseudo_context["receiver_kind"]
        return {
            "status": "resolved" if receiver_kind in {"class_object", "self"} else "candidate_set",
            "receiver_kind": receiver_kind,
            "class_candidates": pseudo_context["class_names"],
            "static_type": pseudo_context.get("static_type"),
            "dynamic_subclasses_possible": receiver_kind in {"self", "typed_instance"},
            "evidence": evidence,
        }
    class_candidates = sorted({name for item in class_references for name in item["class_names"]})
    for item in class_references:
        evidence.append({
            "kind": "class_reference",
            "class_names": item["class_names"],
            "from_address": item["from_address"],
            "to_address": item["to_address"],
            "reference_type": item["reference_type"],
            "source": "analysis/functions.json",
            "provenance": ["ghidra", "objective_c_metadata"],
            "confidence": "medium",
            "basis": "Class reference is in the bounded callsite evidence window, but its Objective-C argument position is not proven",
        })
    return {
        "status": "candidate_set" if class_candidates else "unresolved",
        "receiver_kind": "unknown",
        "class_candidates": class_candidates,
        "static_type": None,
        "dynamic_subclasses_possible": True,
        "evidence": evidence,
    }


def _failure_reasons(
    selector: dict[str, Any], receiver: dict[str, Any], targets: list[dict[str, Any]],
    classification: str,
) -> list[str]:
    reasons: list[str] = []
    if selector["status"] == "unresolved":
        reasons.append("selector_not_recovered_at_callsite")
    elif selector["status"] == "candidate_set":
        reasons.append("multiple_selector_references_in_bounded_callsite_window")
    if receiver["status"] == "unresolved":
        reasons.append("receiver_class_not_statically_proven")
    elif receiver["status"] == "candidate_set":
        reasons.append("receiver_type_has_multiple_runtime_possibilities")
    if selector["candidates"] and not targets:
        reasons.append("no_recovered_method_implements_the_supported_selector_context")
    if classification == "candidate_set" and len(targets) > 1:
        reasons.append("multiple_recovered_target_methods_remain_possible")
    if classification == "candidate_set" and len(targets) == 1:
        reasons.append("single_local_candidate_is_not_an_exact_dynamic_receiver_proof")
    return sorted(set(reasons))


def _canonical_sha256(value: Any) -> str:
    rendered = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(rendered).hexdigest()


def _load_optional_type_flow(workspace: Path) -> tuple[dict[str, Any], Path] | None:
    path = workspace / "analysis" / "objc-type-flow.json"
    if not path.exists():
        return None
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DispatchError(f"Cannot read optional type-flow report {path}: {exc}") from exc
    if (
        report.get("schema_version") != 1
        or report.get("artifact") != "objc-type-flow"
        or not isinstance(report.get("facts"), dict)
        or not isinstance(report["facts"].get("dispatch_refinements"), list)
    ):
        raise DispatchError(f"Invalid IPALift objc-type-flow report: {path}")
    return report, path


def _apply_type_flow_refinements(
    callsites: list[dict[str, Any]],
    inferred_edges: list[dict[str, Any]],
    type_flow: dict[str, Any] | None,
    hierarchy: _Hierarchy,
    methods_by_id: dict[str, dict[str, Any]],
) -> tuple[bool, int, int, Counter, list[str]]:
    for callsite in callsites:
        callsite.update({
            "type_flow_refinement": None,
            "refined_receiver": None,
            "refined_classification": None,
            "refined_possible_targets": [],
            "refined_lookup_paths": [],
            "refinement_changed": False,
        })
    if type_flow is None:
        return False, 0, 0, Counter(), []

    expected = (
        type_flow["facts"].get("input_artifacts", {})
        .get("objc-dispatch-baseline", {})
        .get("projection_sha256")
    )
    baseline = report_envelope(
        "objc-dispatch",
        {"callsites": callsites},
        hypotheses=inferred_edges,
    )
    actual = _canonical_sha256(dispatch_baseline_projection(baseline))
    if expected != actual:
        return False, 0, 0, Counter(), ["objc_type_flow_baseline_mismatch"]

    refinements = type_flow["facts"]["dispatch_refinements"]
    refinement_by_id: dict[str, dict[str, Any]] = {}
    for refinement in refinements:
        callsite_id = str(refinement.get("callsite_id") or "")
        if not callsite_id:
            raise DispatchError("objc-type-flow contains a refinement without a callsite ID")
        if callsite_id in refinement_by_id:
            raise DispatchError(f"objc-type-flow contains a duplicate refinement: {callsite_id}")
        refinement_by_id[callsite_id] = refinement

    applied = 0
    changed_count = 0
    classifications: Counter = Counter()
    for callsite in callsites:
        refinement = refinement_by_id.get(str(callsite["id"]))
        if refinement is None:
            continue
        if refinement.get("baseline_receiver_kind") == "super":
            continue
        class_names = sorted(set(str(value) for value in refinement.get("class_candidates", []) if value))
        receiver_kind = str(refinement.get("receiver_kind") or "unknown")
        if not class_names or receiver_kind not in {"class_object", "typed_instance"}:
            continue
        refinement_classification = str(refinement.get("classification") or "candidate_set")
        exact_type = refinement_classification == "exact" and len(class_names) == 1
        refined_receiver = {
            "status": "resolved" if exact_type else "candidate_set",
            "receiver_kind": receiver_kind,
            "class_candidates": class_names,
            "static_type": class_names[0] if len(class_names) == 1 else None,
            "dynamic_subclasses_possible": not exact_type,
            "confidence": refinement.get("confidence") or "low",
            "evidence_ids": sorted(set(refinement.get("evidence_ids", []))),
            "propagation_step_ids": sorted(set(refinement.get("propagation_step_ids", []))),
            "failure_reasons": sorted(set(refinement.get("failure_reasons", []))),
        }
        targets_by_id: dict[str, dict[str, Any]] = {}
        lookup_paths: set[str] = set()
        caller_methods = [
            methods_by_id[method_id]
            for method_id in callsite["caller"].get("objective_c_method_ids", [])
            if method_id in methods_by_id
        ]
        for class_name in class_names:
            architecture = str(callsite.get("architecture") or "unknown")
            if (
                exact_type
                and receiver_kind == "typed_instance"
                and len(callsite["selector"].get("candidates", [])) == 1
                and architecture != "unknown"
            ):
                records, chain = hierarchy.lookup(
                    architecture,
                    class_name,
                    "instance",
                    callsite["selector"]["candidates"][0],
                )
                targets = [_target_record(method, chain) for method in records]
                paths = [" -> ".join(chain)] if chain else []
            else:
                receiver = {
                    "receiver_kind": receiver_kind,
                    "class_candidates": [class_name],
                }
                targets, paths, _ = _targets_for_callsite(
                    hierarchy,
                    architecture,
                    callsite["selector"],
                    receiver,
                    caller_methods,
                )
            lookup_paths.update(paths)
            for target in targets:
                targets_by_id[str(target["method_id"])] = target
        targets = sorted(targets_by_id.values(), key=lambda item: (
            str(item.get("class_name") or "").casefold(),
            str(item.get("kind") or ""),
            _address_key(_address(item.get("canonical_address"))),
            str(item["method_id"]),
        ))
        mapped_targets = [target for target in targets if target.get("function_id")]
        if (
            callsite["selector"].get("status") == "resolved"
            and exact_type
            and callsite.get("architecture") != "unknown"
            and len(targets) == 1
            and len(mapped_targets) == 1
        ):
            refined_classification = "resolved"
        elif targets:
            refined_classification = "candidate_set"
        else:
            refined_classification = "unresolved"
        baseline_target_ids = sorted(
            str(item["method_id"]) for item in callsite.get("possible_targets", [])
        )
        refined_target_ids = sorted(str(item["method_id"]) for item in targets)
        changed = (
            bool(refinement.get("changed"))
            or refined_classification != callsite.get("classification")
            or refined_target_ids != baseline_target_ids
        )
        callsite.update({
            "type_flow_refinement": refinement,
            "refined_receiver": refined_receiver,
            "refined_classification": refined_classification,
            "refined_possible_targets": targets,
            "refined_lookup_paths": sorted(lookup_paths),
            "refinement_changed": changed,
        })
        applied += 1
        changed_count += int(changed)
        classifications[refined_classification] += 1
    return True, applied, changed_count, classifications, []


def resolve_objc_dispatch(workspace: Path) -> DispatchResult:
    """Analyze every runtime message-send edge without changing the direct call graph."""
    try:
        workspace = workspace.resolve(strict=True)
    except OSError as exc:
        raise DispatchError(f"Analysis workspace does not exist: {workspace}") from exc
    if not workspace.is_dir():
        raise DispatchError(f"Analysis workspace is not a directory: {workspace}")

    reports = {name: _load_report(workspace, name) for name in REQUIRED_REPORTS}
    callgraph = reports["callgraph"]["facts"]
    function_facts = reports["functions"]["facts"]
    string_facts = reports["strings"]["facts"]
    recovered = reports["recovered-code-index"]["facts"]
    functions = list(function_facts.get("functions", []))
    if len(functions) != function_facts.get("discovered_function_count"):
        raise DispatchError("functions.json count does not match its function inventory")
    edges = list(callgraph.get("edges", []))
    if len(edges) != callgraph.get("edge_count"):
        raise DispatchError("callgraph.json count does not match its edge inventory")
    recovered_functions = list(recovered.get("functions", []))
    recovered_methods = list(recovered.get("methods", []))
    recovered_classes = list(recovered.get("classes", []))
    if len(recovered_functions) != recovered.get("function_count"):
        raise DispatchError("recovered-code-index.json function count does not match its inventory")
    if len(recovered_methods) != recovered.get("objective_c_method_count"):
        raise DispatchError("recovered-code-index.json method count does not match its inventory")

    function_by_id = {str(item["id"]): item for item in functions}
    if len(function_by_id) != len(functions):
        raise DispatchError("functions.json contains duplicate function IDs")
    recovered_function_by_id = {str(item["function_id"]): item for item in recovered_functions}
    methods_by_id = {str(item["id"]): item for item in recovered_methods}
    if len(methods_by_id) != len(recovered_methods):
        raise DispatchError("recovered-code-index.json contains duplicate method IDs")
    strings_by_address = {
        address: item for item in string_facts.get("strings", [])
        if (address := _address(item.get("address")))
    }
    hierarchy = _Hierarchy(recovered_classes, recovered_methods)
    symbol_classes = _class_symbol_map(recovered_classes)
    address_classes: dict[str, list[str]] = defaultdict(list)
    for item in recovered_classes:
        if address := _address(item.get("address")):
            address_classes[address].append(str(item["name"]))
        if address := _address(item.get("metaclass_address")):
            address_classes[address].append(str(item["name"]))
    address_classes = {key: sorted(set(value)) for key, value in address_classes.items()}

    dispatch_edges: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for edge in edges:
        runtime = _runtime_info(edge)
        if runtime:
            dispatch_edges.append((edge, runtime))
    dispatch_edges.sort(key=lambda pair: (
        str(pair[0].get("caller_id") or ""), _address_key(_address(pair[0].get("call_site"))),
        str(pair[0].get("target_function_id") or pair[0].get("target_address") or ""), pair[1]["variant"],
    ))

    grouped: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = defaultdict(list)
    for edge, runtime in dispatch_edges:
        grouped[str(edge.get("caller_id") or "")].append((edge, runtime))

    callsites: list[dict[str, Any]] = []
    inferred_edges: list[dict[str, Any]] = []
    pseudocode_artifacts: dict[str, dict[str, Any]] = {}
    seen_callsite_ids: set[str] = set()
    seen_callsite_addresses: set[tuple[str, str]] = set()
    for caller_id in sorted(grouped):
        caller = function_by_id.get(caller_id)
        recovered_function = recovered_function_by_id.get(caller_id)
        if caller is None or recovered_function is None:
            raise DispatchError(f"Dispatch caller is absent from a complete function inventory: {caller_id}")
        caller_methods = [methods_by_id[item] for item in recovered_function.get("method_ids", []) if item in methods_by_id]
        architecture = _architecture_for_caller(caller, recovered_function, methods_by_id, hierarchy.architectures)
        references = sorted(caller.get("cross_references", []), key=lambda item: (
            _address_key(_address(item.get("from_address"))), _address_key(_address(item.get("to_address"))),
            str(item.get("reference_type") or ""),
        ))
        previous_site = (int(_address(caller.get("address")) or "0x0", 16) - 1)
        pending: list[dict[str, Any]] = []
        for edge, runtime in grouped[caller_id]:
            call_site = _address(edge.get("call_site"))
            if not call_site:
                raise DispatchError(f"Objective-C dispatch edge has no valid callsite: {caller_id}")
            selector = _selector_record(references, strings_by_address, previous_site, int(call_site, 16))
            class_references: list[dict[str, Any]] = []
            for reference in references:
                from_address = _address(reference.get("from_address"))
                to_address = _address(reference.get("to_address"))
                if not from_address or not to_address or not (previous_site < int(from_address, 16) <= int(call_site, 16)):
                    continue
                names = _class_from_reference(reference, address_classes, symbol_classes)
                if names:
                    class_references.append({
                        "class_names": names, "from_address": from_address, "to_address": to_address,
                        "reference_type": str(reference.get("reference_type") or "unknown"),
                    })
            pending.append({
                "edge": edge, "runtime": runtime, "call_site": call_site, "selector": selector,
                "class_references": class_references,
            })
            previous_site = int(call_site, 16)

        pseudocode = None
        parsed_calls: list[dict[str, Any]] = []
        decompilation = recovered_function.get("decompilation") or {}
        if decompilation.get("status") == "success" and decompilation.get("output_path"):
            relative = str(decompilation["output_path"])
            path = _relative_file(workspace, relative)
            if not path.is_file():
                raise DispatchError(f"Successful decompilation file is missing: {relative}")
            try:
                code = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                raise DispatchError(f"Cannot read decompiled code {path}: {exc}") from exc
            pseudocode = {"path": relative.replace("\\", "/"), "sha256": sha256_file(path)}
            pseudocode_artifacts[pseudocode["path"]] = pseudocode
            parsed_calls = _parse_pseudocode_calls(code, caller_methods, symbol_classes)

        callsite_group_counts = Counter(
            (item["runtime"]["family"], item["selector"]["value"])
            for item in pending if item["selector"]["status"] == "resolved"
        )
        pseudo_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for item in parsed_calls:
            pseudo_groups[(item["runtime_family"], item["selector"])].append(item)

        for item in pending:
            selector = item["selector"]
            pseudo_context = None
            if selector["status"] == "resolved":
                key = (item["runtime"]["family"], selector["value"])
                contexts = pseudo_groups.get(key, [])
                identities = {
                    (context["receiver_kind"], tuple(context["class_names"]), context.get("static_type"), context["receiver_expression"])
                    for context in contexts
                }
                if (
                    len(contexts) == callsite_group_counts[key]
                    and len(identities) == 1
                    and contexts[0]["receiver_kind"] != "unknown"
                ):
                    pseudo_context = contexts[0]
            receiver = _receiver_record(
                item["runtime"], caller_methods, pseudo_context, item["class_references"], pseudocode
            )
            targets, lookup_paths, exact_receiver = _targets_for_callsite(
                hierarchy, architecture, selector, receiver, caller_methods
            )
            mapped_targets = [target for target in targets if target.get("function_id")]
            if (
                selector["status"] == "resolved"
                and exact_receiver
                and len(targets) == 1
                and len(mapped_targets) == 1
            ):
                classification = "resolved"
                confidence = "high"
            elif targets:
                classification = "candidate_set"
                confidence = "medium" if selector["status"] == "resolved" else "low"
            else:
                classification = "unresolved"
                confidence = "low"
            failure_reasons = _failure_reasons(selector, receiver, targets, classification)
            direct_edge_id = _stable_id(
                "direct-edge", caller_id, item["call_site"], item["edge"].get("target_function_id"),
                item["edge"].get("target_address"), item["runtime"]["variant"],
            )
            callsite_id = _stable_id(
                "objc-dispatch-callsite", architecture, caller_id, item["call_site"], direct_edge_id
            )
            address_identity = (caller_id, item["call_site"])
            if address_identity in seen_callsite_addresses:
                raise DispatchError(
                    f"Multiple Objective-C runtime edges occupy one callsite: {caller_id} {item['call_site']}"
                )
            if callsite_id in seen_callsite_ids:
                raise DispatchError(f"Duplicate Objective-C dispatch callsite identity: {caller_id} {item['call_site']}")
            seen_callsite_addresses.add(address_identity)
            seen_callsite_ids.add(callsite_id)
            provenance = {"ghidra_callgraph", "objective_c_runtime_abi"}
            for evidence in [*selector["evidence"], *receiver["evidence"]]:
                provenance.update(evidence.get("provenance", []))
            if targets:
                provenance.update({"objective_c_metadata", "class_hierarchy"})
            callsite = {
                "id": callsite_id,
                "architecture": architecture,
                "caller": {
                    "function_id": caller_id,
                    "address": caller.get("address"),
                    "name": caller.get("name"),
                    "full_name": caller.get("full_name"),
                    "objective_c_method_ids": sorted(str(value) for value in recovered_function.get("method_ids", [])),
                    "objective_c_exact_names": sorted(str(method.get("exact_name")) for method in caller_methods),
                },
                "call_site": item["call_site"],
                "direct_runtime_edge": {
                    "id": direct_edge_id,
                    "target_function_id": item["edge"].get("target_function_id"),
                    "target_address": item["edge"].get("target_address"),
                    "target_name": item["edge"].get("target_name"),
                    "thunk_target_name": item["edge"].get("thunk_target_name"),
                    "reference_type": item["edge"].get("reference_type"),
                    "runtime_variant": item["runtime"]["variant"],
                    "super_dispatch": item["runtime"]["super_dispatch"],
                },
                "selector": selector,
                "receiver": receiver,
                "classification": classification,
                "possible_targets": targets,
                "lookup_paths": lookup_paths,
                "confidence": confidence,
                "confidence_basis": [
                    "Classification is bounded to recovered runtime metadata and explicit static evidence",
                    "A resolved classification requires one selector, an exact class-object or super context, and one mapped lookup result",
                ],
                "provenance": sorted(provenance),
                "failure_reasons": failure_reasons,
            }
            callsites.append(callsite)
            for target in mapped_targets:
                edge_id = _stable_id("objc-dispatch-edge", callsite_id, target["method_id"], target["function_id"])
                inferred_edges.append({
                    "id": edge_id,
                    "edge_kind": "objective_c_dynamic_dispatch_inference",
                    "callsite_id": callsite_id,
                    "direct_runtime_edge_id": direct_edge_id,
                    "caller_function_id": caller_id,
                    "call_site": item["call_site"],
                    "target_method_id": target["method_id"],
                    "target_function_id": target["function_id"],
                    "selector": target["selector"],
                    "resolution": classification,
                    "confidence": confidence,
                    "provenance": sorted(provenance),
                    "basis": "Possible Objective-C runtime target under the callsite's supported selector and receiver evidence",
                })

    callsites.sort(key=lambda item: (
        str(item["caller"]["function_id"]), _address_key(item["call_site"]), item["id"]
    ))
    inferred_edges.sort(key=lambda item: (
        str(item["caller_function_id"]), _address_key(item["call_site"]),
        str(item["target_function_id"]), str(item["target_method_id"]), item["id"],
    ))
    if len(callsites) != len(dispatch_edges):
        raise DispatchError("Not every discovered Objective-C runtime dispatch edge received one analysis record")
    if len({item["id"] for item in inferred_edges}) != len(inferred_edges):
        raise DispatchError("Inferred Objective-C call graph contains duplicate edge identities")

    optional_type_flow = _load_optional_type_flow(workspace)
    type_flow_document = optional_type_flow[0] if optional_type_flow else None
    (
        type_flow_available,
        type_flow_refinement_count,
        type_flow_changed_count,
        refined_classifications,
        type_flow_failure_reasons,
    ) = _apply_type_flow_refinements(
        callsites,
        inferred_edges,
        type_flow_document,
        hierarchy,
        methods_by_id,
    )

    classifications = Counter(item["classification"] for item in callsites)
    selector_statuses = Counter(item["selector"]["status"] for item in callsites)
    receiver_statuses = Counter(item["receiver"]["status"] for item in callsites)
    runtime_variants = Counter(item["direct_runtime_edge"]["runtime_variant"] for item in callsites)
    unresolved_reasons = Counter(reason for item in callsites for reason in item["failure_reasons"])
    input_paths = {name: f"analysis/{name}.json" for name in REQUIRED_REPORTS}
    input_artifacts = {
            name: {"path": relative, "sha256": sha256_file(_relative_file(workspace, relative))}
            for name, relative in sorted(input_paths.items())
    }
    if optional_type_flow:
        input_artifacts["objc-type-flow"] = {
            "path": "analysis/objc-type-flow.json",
            "sha256": sha256_file(optional_type_flow[1]),
        }
    facts = {
        "input_artifacts": input_artifacts,
        "pseudocode_artifact_count": len(pseudocode_artifacts),
        "pseudocode_artifacts": [pseudocode_artifacts[key] for key in sorted(pseudocode_artifacts)],
        "direct_callgraph_preserved": True,
        "direct_callgraph_edge_count": len(edges),
        "dispatch_callsite_count": len(callsites),
        "classification_counts": {name: classifications.get(name, 0) for name in CLASSIFICATIONS},
        "selector_status_counts": {name: selector_statuses.get(name, 0) for name in SELECTOR_STATUSES},
        "receiver_status_counts": {name: receiver_statuses.get(name, 0) for name in RECEIVER_STATUSES},
        "runtime_variant_counts": dict(sorted(runtime_variants.items())),
        "inferred_edge_count": len(inferred_edges),
        "resolved_inferred_edge_count": sum(item["resolution"] == "resolved" for item in inferred_edges),
        "candidate_inferred_edge_count": sum(item["resolution"] == "candidate_set" for item in inferred_edges),
        "type_flow_refinement_available": type_flow_available,
        "type_flow_refinement_count": type_flow_refinement_count,
        "type_flow_changed_count": type_flow_changed_count,
        "refined_classification_counts": {
            name: refined_classifications.get(name, 0) for name in CLASSIFICATIONS
        },
        "type_flow_failure_reasons": type_flow_failure_reasons,
        "unresolved_reason_counts": dict(sorted(unresolved_reasons.items())),
        "callsites": callsites,
    }
    errors = [
        {
            "code": reason,
            "count": count,
            "message": reason.replace("_", " ").capitalize(),
        }
        for reason, count in sorted(unresolved_reasons.items())
    ]
    dispatch = report_envelope("objc-dispatch", facts, hypotheses=inferred_edges, errors=errors)
    dispatch_path = workspace / "analysis" / "objc-dispatch.json"
    report_path = workspace / "reports" / "objc-dispatch-report.md"
    write_json_atomic(dispatch_path, dispatch)
    write_text_atomic(report_path, render_objc_dispatch_report(facts))
    return DispatchResult(workspace, dispatch, dispatch_path, report_path)
