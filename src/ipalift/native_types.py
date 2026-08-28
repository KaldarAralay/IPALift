"""Deterministic native/C++ type flow and numeric data-layout recovery."""

from __future__ import annotations

import hashlib
import heapq
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .errors import IPALiftError
from .macho import MachOSlice, parse_macho_file
from .report import render_native_type_flow_report
from .typeflow import _assignments, _local_declarations, _signature, _split_arguments, _strip_casts
from .util import report_envelope, sha256_file, write_json_atomic, write_text_atomic


class NativeTypeFlowError(IPALiftError):
    """A workspace cannot support trustworthy native type-flow recovery."""


@dataclass(frozen=True)
class NativeTypeFlowResult:
    workspace: Path
    native_type_flow: dict[str, Any]
    native_type_flow_path: Path
    report_path: Path


@dataclass(frozen=True, order=True)
class NativeAtom:
    kind: str
    name: str
    cpp_class_id: str | None = None
    objc_class_name: str | None = None
    pointer_depth: int = 0
    width: int | None = None


LOADED_REPORTS = (
    "application",
    "architectures",
    "functions",
    "callgraph",
    "recovered-code-index",
    "objc-dispatch",
    "objc-type-flow",
    "cpp-object-model",
)
FINGERPRINT_REPORTS = (*LOADED_REPORTS, "platform-api-map")
PRESERVED_REPORTS = (
    "functions",
    "callgraph",
    "objc-dispatch",
    "objc-type-flow",
    "platform-api-map",
    "cpp-object-model",
)
CLASSIFICATIONS = ("exact", "candidate_set", "unresolved")
SUPPORTED_CPP_ABIS = frozenset({"itanium-cxx-abi"})
CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}
RANK_CONFIDENCE = {value: key for key, value in CONFIDENCE_RANK.items()}
_ADDRESS_RE = re.compile(r"^0x[0-9a-f]+$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")
_GLOBAL_RE = re.compile(r"\b(?P<label>[A-Za-z_$][A-Za-z0-9_$]*_(?P<address>[0-9A-Fa-f]{8,16}))\b")
_FIELD_POINTER_RE = re.compile(
    r"\*\s*\(\s*(?P<type>[A-Za-z_$][A-Za-z0-9_$:\s]*?)\s*\*\s*\)\s*"
    r"\(\s*(?:\([^)]*\)\s*)?(?P<base>[A-Za-z_$][A-Za-z0-9_$]*)\s*"
    r"(?P<sign>[+-])\s*(?P<offset>0x[0-9A-Fa-f]+|[0-9]+)\s*\)"
)
_FIELD_MEMBER_RE = re.compile(
    r"(?P<base>[A-Za-z_$][A-Za-z0-9_$]*)\s*->\s*field(?:0)?_0x(?P<offset>[0-9A-Fa-f]+)"
)
_FIELD_ARRAY_RE = re.compile(
    r"(?P<base>[A-Za-z_$][A-Za-z0-9_$]*)\s*->\s*field0_0x0\s*\[\s*(?P<index>[0-9]+)\s*\]"
)
_VIRTUAL_OFFSET_RE = re.compile(
    r"\*\*\s*\(\s*code\s*\*\*\s*\)\s*\(\s*"
    r"(?:\*\s*\([^)]*\)\s*)?(?P<receiver>[A-Za-z_$][A-Za-z0-9_$]*)"
    r"[^;\n]{0,100}?\+\s*(?P<offset>0x[0-9A-Fa-f]+|[0-9]+)\s*\)"
)
_VIRTUAL_ARRAY_RE = re.compile(
    r"(?P<receiver>[A-Za-z_$][A-Za-z0-9_$]*)\s*->\s*field0_0x0\s*"
    r"\[\s*(?P<index>[0-9]+)\s*\]"
)
_VIRTUAL_ZERO_RE = re.compile(
    r"\*\*\s*\(\s*code\s*\*\*\s*\)\s*\*\s*(?P<receiver>[A-Za-z_$][A-Za-z0-9_$]*)"
)
_CALL_RE = re.compile(
    r"(?<![A-Za-z0-9_$])(?P<callee>[~A-Za-z_$][A-Za-z0-9_$]*(?:::[~A-Za-z_$][A-Za-z0-9_$]*)*)\s*\("
)
_CONTROL_CALLEES = {"if", "for", "while", "switch", "return", "sizeof"}
_SCALAR_WIDTHS = {
    "bool": 1,
    "byte": 1,
    "char": 1,
    "signed char": 1,
    "unsigned char": 1,
    "short": 2,
    "short int": 2,
    "unsigned short": 2,
    "ushort": 2,
    "int": 4,
    "unsigned": 4,
    "unsigned int": 4,
    "uint": 4,
    "float": 4,
    "undefined1": 1,
    "undefined2": 2,
    "undefined4": 4,
    "undefined8": 8,
    "long long": 8,
    "unsigned long long": 8,
    "double": 8,
    "bool": 1,
    "boolean": 1,
    "bool32": 4,
}


def _load_report(workspace: Path, name: str) -> dict[str, Any]:
    path = workspace / "analysis" / f"{name}.json"
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise NativeTypeFlowError(f"Analysis workspace is missing analysis/{name}.json") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise NativeTypeFlowError(f"Cannot read {path}: {exc}") from exc
    if (
        not isinstance(report, dict)
        or report.get("schema_version") != 1
        or report.get("artifact") != name
        or not isinstance(report.get("facts"), dict)
    ):
        raise NativeTypeFlowError(f"Invalid IPALift {name} report: {path}")
    return report


def _relative_file(workspace: Path, relative: str) -> Path:
    portable = str(relative).replace("\\", "/")
    parts = portable.split("/")
    if (
        not portable
        or portable.startswith("/")
        or re.match(r"^[A-Za-z]:", portable)
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise NativeTypeFlowError(f"Artifact path escapes the analysis workspace: {relative}")
    candidate = (workspace / Path(*parts)).resolve()
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise NativeTypeFlowError(f"Artifact path escapes the analysis workspace: {relative}") from exc
    return candidate


def _address(value: Any, width: int = 8) -> str | None:
    if value is None:
        return None
    try:
        number = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return None
    return f"0x{number:0{width}x}"


def _address_key(value: str | None) -> tuple[int, str]:
    if value and _ADDRESS_RE.match(value):
        return (0, f"{int(value, 16):016x}")
    return (1, value or "")


def _stable_id(kind: str, *parts: Any) -> str:
    identity = "\0".join([kind, *(str(part) for part in parts)])
    return f"{kind}:{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:20]}"


def _confidence(classification: str) -> str:
    return {"exact": "high", "candidate_set": "medium", "unresolved": "low"}[classification]


def _balanced_close(value: str, opening: int) -> int | None:
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(opening, len(value)):
        char = value[index]
        if quote:
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


def _normalize_type(value: str | None, pointer_size: int) -> tuple[NativeAtom | None, bool]:
    if not value:
        return None, True
    rendered = re.sub(r"\s+", " ", value.strip())
    rendered = re.sub(r"\b(?:const|volatile|register|restrict|struct|class)\b", "", rendered)
    rendered = re.sub(r"\s+", " ", rendered).strip()
    pointer_depth = rendered.count("*")
    base = re.sub(r"\s*\*+\s*$", "", rendered).strip()
    if not base or base in {"unknown", "undefined", "void"} and not pointer_depth:
        return None, True
    if base == "code" and pointer_depth:
        return NativeAtom("function_pointer", "code *", pointer_depth=pointer_depth, width=pointer_size), True
    if pointer_depth:
        return NativeAtom("native_pointer", rendered, pointer_depth=pointer_depth, width=pointer_size), True
    width = _SCALAR_WIDTHS.get(base.casefold())
    if base.casefold() in {"long", "unsigned long", "ulong", "size_t", "intptr_t", "uintptr_t"}:
        width = pointer_size
    if width is not None:
        return NativeAtom("scalar", base, width=width), True
    if base == "SEL":
        return NativeAtom("selector", "SEL", width=pointer_size), True
    if base == "Class":
        return NativeAtom("objective_c_class_object", "Class", pointer_depth=1, width=pointer_size), True
    if base in {"ID", "id"}:
        return NativeAtom("objective_c_id", "id", pointer_depth=1, width=pointer_size), True
    if base == "code":
        return NativeAtom("function_pointer", "code *", pointer_depth=1, width=pointer_size), True
    return NativeAtom("named_native_type", base, width=None), True


def _simple_variable(expression: str) -> str | None:
    rendered, _cast = _strip_casts(expression.strip())
    rendered = rendered.strip()
    while rendered.startswith("&") or rendered.startswith("*"):
        rendered = rendered[1:].strip()
    match = re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", rendered)
    return match.group(0) if match else None


def _expression_variable(expression: str, known: Iterable[str]) -> str | None:
    known_set = set(known)
    simple = _simple_variable(expression)
    if simple in known_set:
        return simple
    identifiers = re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*", expression)
    matches = [value for value in identifiers if value in known_set]
    return matches[-1] if len(set(matches)) == 1 else None


def _type_atom_from_objc(candidate: dict[str, Any], pointer_size: int) -> NativeAtom:
    kind = str(candidate.get("kind") or "unknown")
    name = str(candidate.get("name") or "unknown")
    class_name = candidate.get("class_name")
    width = _SCALAR_WIDTHS.get(name.casefold())
    if kind in {
        "objective_c_instance", "objective_c_class_object", "objective_c_id",
        "objective_c_protocol", "objective_c_block", "selector", "native_pointer",
    }:
        width = pointer_size
    return NativeAtom(
        kind,
        name,
        objc_class_name=str(class_name) if class_name else None,
        pointer_depth=1 if kind.endswith("pointer") or kind.startswith("objective_c") else 0,
        width=width,
    )


class _NativeGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.evidence: dict[str, dict[str, Any]] = {}
        self.edges: dict[str, dict[str, Any]] = {}
        self.roots: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.outgoing: dict[str, list[str]] = defaultdict(list)

    def add_node(self, node_id: str, **values: Any) -> str:
        record = {
            "id": node_id,
            "kind": values.pop("kind"),
            "architecture": values.pop("architecture", "unknown"),
            "function_id": values.pop("function_id", None),
            "name": values.pop("name", None),
            "index": values.pop("index", None),
            "source_path": values.pop("source_path", None),
            "source_address": values.pop("source_address", None),
            "declared_type": values.pop("declared_type", None),
            "original_objc_value_ids": sorted(set(values.pop("original_objc_value_ids", []))),
            **values,
        }
        if node_id in self.nodes and self.nodes[node_id] != record:
            raise NativeTypeFlowError(f"Conflicting native value identity: {node_id}")
        self.nodes[node_id] = record
        return node_id

    def add_evidence(
        self,
        kind: str,
        source: str,
        *,
        source_address: str | None,
        confidence: str,
        provenance: Iterable[str],
        basis: str,
        details: dict[str, Any] | None = None,
    ) -> str:
        detail = details or {}
        evidence_id = _stable_id(
            "native-evidence", kind, source, source_address, confidence, basis,
            json.dumps(detail, sort_keys=True, ensure_ascii=False),
        )
        record = {
            "id": evidence_id,
            "kind": kind,
            "source": source,
            "source_address": source_address,
            "confidence": confidence,
            "provenance": sorted(set(provenance)),
            "basis": basis,
            "details": detail,
        }
        if evidence_id in self.evidence and self.evidence[evidence_id] != record:
            raise NativeTypeFlowError(f"Conflicting native evidence identity: {evidence_id}")
        self.evidence[evidence_id] = record
        return evidence_id

    def add_root(
        self,
        node_id: str,
        atom: NativeAtom,
        evidence_id: str,
        *,
        confidence: str,
        hypothesis: bool,
    ) -> None:
        if node_id not in self.nodes:
            raise NativeTypeFlowError(f"Native root references unknown value: {node_id}")
        self.roots[node_id].append({
            "atom": atom,
            "evidence_ids": (evidence_id,),
            "confidence": CONFIDENCE_RANK[confidence],
            "hypothesis": hypothesis,
            "path": (),
        })

    def add_edge(
        self,
        source: str,
        target: str,
        kind: str,
        *,
        confidence: str,
        hypothesis: bool,
        basis: str,
        source_path: str | None = None,
        source_address: str | None = None,
    ) -> str:
        if source not in self.nodes or target not in self.nodes:
            raise NativeTypeFlowError(f"Native step references unknown values: {source} -> {target}")
        edge_id = _stable_id(
            "native-step", source, target, kind, confidence, hypothesis,
            source_path, source_address, basis,
        )
        record = {
            "id": edge_id,
            "source_value_id": source,
            "target_value_id": target,
            "kind": kind,
            "confidence": confidence,
            "hypothesis": hypothesis,
            "basis": basis,
            "source_path": source_path,
            "source_address": source_address,
        }
        if edge_id in self.edges and self.edges[edge_id] != record:
            raise NativeTypeFlowError(f"Conflicting native propagation identity: {edge_id}")
        if edge_id not in self.edges:
            self.edges[edge_id] = record
            self.outgoing[source].append(edge_id)
        return edge_id

    @staticmethod
    def _better(candidate: dict[str, Any], existing: dict[str, Any] | None) -> bool:
        if existing is None:
            return True
        candidate_key = (
            candidate["confidence"], not candidate["hypothesis"],
            -len(candidate["path"]), candidate["evidence_ids"], candidate["path"],
        )
        existing_key = (
            existing["confidence"], not existing["hypothesis"],
            -len(existing["path"]), existing["evidence_ids"], existing["path"],
        )
        return candidate_key > existing_key

    def solve(self) -> tuple[dict[str, dict[NativeAtom, dict[str, Any]]], dict[str, int]]:
        state: dict[str, dict[NativeAtom, dict[str, Any]]] = {
            node_id: {} for node_id in self.nodes
        }
        queue: list[str] = []
        queued: set[str] = set()
        for node_id in sorted(self.roots):
            changed = False
            for root in sorted(
                self.roots[node_id],
                key=lambda item: (item["atom"], -item["confidence"], item["hypothesis"], item["evidence_ids"]),
            ):
                if self._better(root, state[node_id].get(root["atom"])):
                    state[node_id][root["atom"]] = root
                    changed = True
            if changed:
                heapq.heappush(queue, node_id)
                queued.add(node_id)
        pop_count = 0
        relaxation_count = 0
        maximum_path = 0
        while queue:
            source = heapq.heappop(queue)
            queued.remove(source)
            pop_count += 1
            for edge_id in sorted(self.outgoing.get(source, [])):
                edge = self.edges[edge_id]
                target = edge["target_value_id"]
                edge_confidence = CONFIDENCE_RANK[edge["confidence"]]
                target_changed = False
                for atom, source_state in sorted(state[source].items()):
                    if edge_id in source_state["path"]:
                        continue
                    path = (*source_state["path"], edge_id)
                    candidate = {
                        "atom": atom,
                        "evidence_ids": source_state["evidence_ids"],
                        "confidence": min(source_state["confidence"], edge_confidence),
                        "hypothesis": source_state["hypothesis"] or edge["hypothesis"],
                        "path": path,
                    }
                    if self._better(candidate, state[target].get(atom)):
                        state[target][atom] = candidate
                        target_changed = True
                        relaxation_count += 1
                        maximum_path = max(maximum_path, len(path))
                if target_changed and target not in queued:
                    heapq.heappush(queue, target)
                    queued.add(target)
        return state, {
            "worklist_pop_count": pop_count,
            "successful_relaxation_count": relaxation_count,
            "maximum_evidence_path_length": maximum_path,
        }

    def cyclic_components(self) -> list[list[str]]:
        index = 0
        indexes: dict[str, int] = {}
        lowlinks: dict[str, int] = {}
        stack: list[str] = []
        on_stack: set[str] = set()
        components: list[list[str]] = []

        def visit(node: str) -> None:
            nonlocal index
            indexes[node] = index
            lowlinks[node] = index
            index += 1
            stack.append(node)
            on_stack.add(node)
            targets = sorted({
                self.edges[edge_id]["target_value_id"]
                for edge_id in self.outgoing.get(node, [])
            })
            for target in targets:
                if target not in indexes:
                    visit(target)
                    lowlinks[node] = min(lowlinks[node], lowlinks[target])
                elif target in on_stack:
                    lowlinks[node] = min(lowlinks[node], indexes[target])
            if lowlinks[node] == indexes[node]:
                component: list[str] = []
                while True:
                    member = stack.pop()
                    on_stack.remove(member)
                    component.append(member)
                    if member == node:
                        break
                component.sort()
                if len(component) > 1 or any(
                    self.edges[edge_id]["target_value_id"] == component[0]
                    for edge_id in self.outgoing.get(component[0], [])
                ):
                    components.append(component)

        for node in sorted(self.nodes):
            if node not in indexes:
                visit(node)
        return sorted(components, key=lambda values: (values[0], len(values), values))


def _calls(code: str) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    for match in _CALL_RE.finditer(code):
        callee = match.group("callee")
        if callee in _CONTROL_CALLEES or callee.startswith("objc_msg"):
            continue
        opening = match.end() - 1
        closing = _balanced_close(code, opening)
        if closing is None:
            continue
        statement_start = max(code.rfind(";", 0, match.start()), code.rfind("{", 0, match.start()), code.rfind("}", 0, match.start())) + 1
        prefix = code[statement_start:match.start()]
        lhs_match = re.search(r"(?:^|\n)\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*$", prefix)
        calls.append({
            "callee": callee,
            "arguments": _split_arguments(code[opening + 1:closing]),
            "lhs": lhs_match.group(1) if lhs_match else None,
            "start": match.start(),
            "line": code.count("\n", 0, match.start()) + 1,
        })
    return calls


def _field_accesses(code: str, pointer_size: int) -> list[dict[str, Any]]:
    records: dict[tuple[int, str, int], dict[str, Any]] = {}
    patterns = (
        (_FIELD_POINTER_RE, "pointer_arithmetic"),
        (_FIELD_ARRAY_RE, "decompiler_field_array"),
        (_FIELD_MEMBER_RE, "decompiler_field_member"),
    )
    occupied: list[tuple[int, int]] = []
    for pattern, form in patterns:
        for match in pattern.finditer(code):
            if any(start <= match.start() < end for start, end in occupied):
                continue
            if form == "pointer_arithmetic":
                offset = int(match.group("offset"), 0)
                if match.group("sign") == "-":
                    offset = -offset
                type_name = match.group("type").strip()
                atom, _ = _normalize_type(type_name, pointer_size)
                width = atom.width if atom else None
            elif form == "decompiler_field_array":
                offset = int(match.group("index")) * pointer_size
                type_name = None
                width = pointer_size
            else:
                offset = int(match.group("offset"), 16)
                type_name = None
                width = None
            line_start = code.rfind("\n", 0, match.start()) + 1
            line_end = code.find("\n", match.end())
            if line_end < 0:
                line_end = len(code)
            line_text = code[line_start:line_end]
            equals = line_text.find("=")
            within = match.start() - line_start
            access_kind = "write" if equals >= 0 and within < equals else "read"
            record = {
                "base": match.group("base"),
                "offset": offset,
                "width": width,
                "declared_type": type_name,
                "form": form,
                "access_kind": access_kind,
                "start": match.start(),
                "line": code.count("\n", 0, match.start()) + 1,
                "expression": match.group(0)[:240],
                "line_text": line_text.strip()[:500],
            }
            records[(match.start(), record["base"], offset)] = record
            occupied.append(match.span())
    return [records[key] for key in sorted(records)]


def _virtual_forms(code: str, pointer_size: int) -> list[dict[str, Any]]:
    records: dict[tuple[int, str, int], dict[str, Any]] = {}
    occupied: list[tuple[int, int]] = []
    for pattern, form in (
        (_VIRTUAL_OFFSET_RE, "byte_offset"),
        (_VIRTUAL_ARRAY_RE, "array_index"),
        (_VIRTUAL_ZERO_RE, "zero_offset"),
    ):
        for match in pattern.finditer(code):
            if any(start <= match.start() < end for start, end in occupied):
                continue
            if form == "byte_offset":
                offset = int(match.group("offset"), 0)
                if offset % pointer_size:
                    continue
                index = offset // pointer_size
            elif form == "array_index":
                index = int(match.group("index"))
                offset = index * pointer_size
            else:
                index = 0
                offset = 0
            record = {
                "receiver": match.group("receiver"),
                "slot_index": index,
                "slot_offset": offset,
                "start": match.start(),
                "line": code.count("\n", 0, match.start()) + 1,
                "form": form,
                "expression": match.group(0)[:240],
            }
            records[(match.start(), record["receiver"], index)] = record
            occupied.append(match.span())
    return [records[key] for key in sorted(records)]


def _slice_for_architecture(slices: Iterable[MachOSlice], architecture: str) -> MachOSlice | None:
    return next((item for item in slices if item.architecture_name == architecture), None)


def _architecture_for_function(function: dict[str, Any], architectures: list[str]) -> str:
    explicit = function.get("architecture")
    if explicit:
        return str(explicit)
    return architectures[0] if len(architectures) == 1 else "unknown"


def _atom_record(atom: NativeAtom, state: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": atom.kind,
        "name": atom.name,
        "cpp_class_id": atom.cpp_class_id,
        "objc_class_name": atom.objc_class_name,
        "pointer_depth": atom.pointer_depth,
        "width": atom.width,
        "confidence": RANK_CONFIDENCE[state["confidence"]],
        "hypothesis": state["hypothesis"],
        "evidence_ids": list(state["evidence_ids"]),
        "propagation_step_ids": list(state["path"]),
    }


def _effective_states(
    states: dict[NativeAtom, dict[str, Any]],
    evidence: dict[str, dict[str, Any]],
) -> dict[NativeAtom, dict[str, Any]]:
    """Remove compatible generic/static atoms without discarding evidence."""
    result = dict(states)
    dynamic_classes = {
        atom.cpp_class_id
        for atom in result
        if atom.kind == "cpp_dynamic_object" and atom.cpp_class_id
    }
    for atom in list(result):
        if atom.kind == "cpp_object_pointer" and atom.cpp_class_id in dynamic_classes:
            result.pop(atom)
    specific_pointer_kinds = {
        "cpp_dynamic_object", "cpp_object_pointer", "vtable_pointer",
        "function_pointer", "objective_c_instance", "objective_c_class_object",
        "objective_c_id", "objective_c_protocol", "objective_c_block",
    }
    if any(atom.kind in specific_pointer_kinds for atom in result):
        for atom in list(result):
            pointer_base = re.sub(r"\s*\*+\s*$", "", atom.name).strip().casefold()
            evidence_kinds = {
                str(evidence[evidence_id].get("kind") or "")
                for evidence_id in result[atom].get("evidence_ids", ())
                if evidence_id in evidence
            }
            declaration_only = bool(evidence_kinds) and evidence_kinds <= {
                "ghidra_native_return_declaration",
                "ghidra_native_parameter_declaration",
                "ghidra_native_local_declaration",
            }
            if atom.kind == "native_pointer" and (
                pointer_base == "void"
                or pointer_base == "unknown"
                or pointer_base.startswith("undefined")
                or declaration_only
            ):
                result.pop(atom)
    specific_objc = {
        atom.objc_class_name
        for atom in result
        if atom.kind in {"objective_c_instance", "objective_c_class_object"}
        and atom.objc_class_name
    }
    if specific_objc:
        for atom in list(result):
            if atom.kind == "objective_c_id":
                result.pop(atom)
            elif atom.kind == "objective_c_class_object" and not atom.objc_class_name:
                result.pop(atom)
    return result


def _classified_state(states: dict[NativeAtom, dict[str, Any]]) -> tuple[str, str, list[str]]:
    if not states:
        return "unresolved", "low", ["no_supported_native_type_evidence_reaches_value"]
    exact = len(states) == 1 and all(
        item["confidence"] == CONFIDENCE_RANK["high"] and not item["hypothesis"]
        for item in states.values()
    )
    if exact:
        return "exact", "high", []
    reasons: list[str] = []
    if len(states) > 1:
        reasons.append("multiple_native_types_reach_value")
    if any(item["hypothesis"] or item["confidence"] < CONFIDENCE_RANK["high"] for item in states.values()):
        reasons.append("type_depends_on_candidate_or_analysis_evidence")
    return "candidate_set", "medium", reasons


def _freeze_index(values: dict[str, dict[str, set[str]]], key_name: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for key in sorted(values, key=lambda value: (_address_key(value), value)):
        record: dict[str, Any] = {key_name: key}
        for field, members in sorted(values[key].items()):
            record[field] = sorted(members, key=lambda value: (_address_key(value), value))
        result.append(record)
    return result


def infer_native_types(workspace: Path) -> NativeTypeFlowResult:
    """Build additive native type, layout, global, and C++ dispatch evidence."""
    try:
        workspace = workspace.resolve(strict=True)
    except OSError as exc:
        raise NativeTypeFlowError(f"Analysis workspace does not exist: {workspace}") from exc
    if not workspace.is_dir():
        raise NativeTypeFlowError(f"Analysis workspace is not a directory: {workspace}")

    reports = {name: _load_report(workspace, name) for name in LOADED_REPORTS}
    for name in FINGERPRINT_REPORTS:
        path = workspace / "analysis" / f"{name}.json"
        if not path.is_file():
            raise NativeTypeFlowError(f"Analysis workspace is missing analysis/{name}.json")
    preserved_before = {
        name: sha256_file(workspace / "analysis" / f"{name}.json")
        for name in PRESERVED_REPORTS
    }

    application = reports["application"]["facts"]
    executable_record = application.get("executable") or {}
    archive_path = str(executable_record.get("archive_path") or "")
    executable = _relative_file(workspace, f"evidence/extracted/{archive_path}")
    if not executable.is_file():
        raise NativeTypeFlowError(f"Extracted executable is missing: {executable}")
    executable_hash = sha256_file(executable)
    if executable_hash != executable_record.get("sha256") or executable.stat().st_size != executable_record.get("size"):
        raise NativeTypeFlowError("Extracted executable identity does not match application.json")
    macho = parse_macho_file(executable)
    architecture_facts = reports["architectures"]["facts"]
    architectures = sorted(str(item.get("architecture")) for item in architecture_facts.get("architectures") or [])
    if architectures != sorted(item.architecture_name for item in macho.slices):
        raise NativeTypeFlowError("Executable architectures do not match architectures.json")

    raw_functions = list(reports["functions"]["facts"].get("functions") or [])
    raw_by_id = {str(item.get("id")): item for item in raw_functions}
    if len(raw_by_id) != len(raw_functions):
        raise NativeTypeFlowError("functions.json contains duplicate function IDs")
    call_edges = list(reports["callgraph"]["facts"].get("edges") or [])
    recovered = reports["recovered-code-index"]["facts"]
    recovered_functions = list(recovered.get("functions") or [])
    recovered_by_id = {str(item.get("function_id")): item for item in recovered_functions}
    if len(recovered_by_id) != len(recovered_functions):
        raise NativeTypeFlowError("recovered-code-index.json contains duplicate function IDs")
    methods_by_id = {
        str(item.get("id")): item for item in recovered.get("methods") or []
    }
    method_ids_by_function = {
        function_id: sorted(str(value) for value in item.get("method_ids") or [])
        for function_id, item in recovered_by_id.items()
    }
    objc_classes_by_function = {
        function_id: sorted({
            str(methods_by_id[method_id].get("class_name"))
            for method_id in method_ids
            if method_id in methods_by_id and methods_by_id[method_id].get("class_name")
        })
        for function_id, method_ids in method_ids_by_function.items()
    }
    objc_flow = reports["objc-type-flow"]["facts"]
    cpp = reports["cpp-object-model"]["facts"]
    cpp_class_records = list(cpp.get("classes") or [])
    cpp_classes = {str(item["id"]): item for item in cpp_class_records}
    if len(cpp_classes) != len(cpp_class_records):
        raise NativeTypeFlowError("cpp-object-model.json contains duplicate class IDs")
    supported_cpp_class_ids = {
        class_id
        for class_id, item in cpp_classes.items()
        if str(item.get("abi") or "") in SUPPORTED_CPP_ABIS
    }
    unsupported_cpp_classes = [
        {
            "class_id": class_id,
            "architecture": str(item.get("architecture") or "unknown"),
            "abi": str(item.get("abi") or "unknown"),
            "failure_reason": "unsupported_cpp_abi",
        }
        for class_id, item in sorted(cpp_classes.items())
        if class_id not in supported_cpp_class_ids
    ]

    pseudocode: dict[str, str] = {}
    pseudocode_artifacts: list[dict[str, Any]] = []
    for item in sorted(recovered_functions, key=lambda value: str(value.get("function_id"))):
        decompilation = item.get("decompilation") or {}
        if decompilation.get("status") != "success" or not decompilation.get("output_path"):
            continue
        relative = str(decompilation["output_path"]).replace("\\", "/")
        path = _relative_file(workspace, relative)
        if not path.is_file():
            raise NativeTypeFlowError(f"Successful pseudocode is missing: {relative}")
        digest = sha256_file(path)
        if digest != decompilation.get("sha256"):
            raise NativeTypeFlowError(f"Pseudocode hash mismatch: {relative}")
        try:
            code = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise NativeTypeFlowError(f"Cannot read pseudocode {path}: {exc}") from exc
        function_id = str(item.get("function_id"))
        pseudocode[function_id] = code
        pseudocode_artifacts.append({"function_id": function_id, "path": relative, "sha256": digest})

    graph = _NativeGraph()
    variables_by_function: dict[str, dict[str, str]] = defaultdict(dict)
    parameters_by_function: dict[str, dict[int, str]] = defaultdict(dict)
    returns_by_function: dict[str, str] = {}
    original_to_native: dict[str, str] = {}

    supported_objc_kinds = {"function_return", "function_parameter", "local"}
    for original in sorted(objc_flow.get("values") or [], key=lambda item: str(item.get("id"))):
        if original.get("kind") not in supported_objc_kinds:
            continue
        function_id = str(original.get("function_id") or "")
        if not function_id:
            continue
        original_id = str(original["id"])
        native_id = _stable_id("native-value", "objc", original_id)
        original_to_native[original_id] = native_id
        graph.add_node(
            native_id,
            kind=str(original["kind"]),
            architecture=str(original.get("architecture") or "unknown"),
            function_id=function_id,
            name=original.get("name"),
            index=original.get("index"),
            source_path=original.get("source_path"),
            source_address=original.get("source_address"),
            declared_type=original.get("declared_type"),
            original_objc_value_ids=[original_id],
        )
        if original["kind"] == "function_return":
            returns_by_function[function_id] = native_id
        elif original["kind"] == "function_parameter" and original.get("index") is not None:
            parameters_by_function[function_id][int(original["index"])] = native_id
            if original.get("name"):
                variables_by_function[function_id][str(original["name"])] = native_id
        elif original.get("name"):
            variables_by_function[function_id][str(original["name"])] = native_id
        architecture = str(original.get("architecture") or "unknown")
        macho_slice = _slice_for_architecture(macho.slices, architecture)
        pointer_size = macho_slice.pointer_size if macho_slice else 4
        for candidate in original.get("type_candidates") or []:
            evidence_id = graph.add_evidence(
                "objective_c_type_flow_value",
                "analysis/objc-type-flow.json",
                source_address=original.get("source_address"),
                confidence=str(candidate.get("confidence") or original.get("confidence") or "low"),
                provenance=["objective_c_type_flow"],
                basis="An existing solved Objective-C/native value is retained as an additive native-flow root",
                details={
                    "original_value_id": original_id,
                    "original_evidence_ids": candidate.get("evidence_ids") or [],
                    "original_propagation_step_ids": candidate.get("propagation_step_ids") or [],
                },
            )
            graph.add_root(
                native_id,
                _type_atom_from_objc(candidate, pointer_size),
                evidence_id,
                confidence=str(candidate.get("confidence") or "low"),
                hypothesis=bool(candidate.get("hypothesis")) or original.get("classification") != "exact",
            )

    # Ensure every discovered function has a return and every parsed declaration has a value.
    for function_id, raw in sorted(raw_by_id.items()):
        architecture = _architecture_for_function(raw, architectures)
        if function_id not in returns_by_function:
            return_id = _stable_id("native-value", "function-return", architecture, function_id)
            graph.add_node(
                return_id, kind="function_return", architecture=architecture,
                function_id=function_id, source_path=None,
                source_address=_address(raw.get("address")),
            )
            returns_by_function[function_id] = return_id
        code = pseudocode.get(function_id)
        if not code:
            continue
        recovered_function = recovered_by_id.get(function_id) or {}
        relative = str((recovered_function.get("decompilation") or {}).get("output_path") or "").replace("\\", "/")
        macho_slice = _slice_for_architecture(macho.slices, architecture)
        pointer_size = macho_slice.pointer_size if macho_slice else 4
        signature = _signature(code)
        if signature:
            return_type, parameters = signature
            graph.nodes[returns_by_function[function_id]]["declared_type"] = return_type
            atom, hypothesis = _normalize_type(return_type, pointer_size)
            if atom:
                evidence_id = graph.add_evidence(
                    "ghidra_native_return_declaration", relative,
                    source_address=_address(raw.get("address")), confidence="medium",
                    provenance=["ghidra_pseudocode"],
                    basis="Ghidra pseudocode supplies an analysis-derived native return declaration",
                    details={"function_id": function_id, "declared_type": return_type},
                )
                graph.add_root(returns_by_function[function_id], atom, evidence_id, confidence="medium", hypothesis=hypothesis)
            for index, (name, type_name) in enumerate(parameters):
                parameter_id = parameters_by_function[function_id].get(index)
                if parameter_id is None:
                    parameter_id = _stable_id("native-value", "function-parameter", architecture, function_id, index)
                    graph.add_node(
                        parameter_id, kind="function_parameter", architecture=architecture,
                        function_id=function_id, name=name, index=index,
                        source_path=relative, source_address=_address(raw.get("address")),
                        declared_type=type_name,
                    )
                    parameters_by_function[function_id][index] = parameter_id
                variables_by_function[function_id][name] = parameter_id
                atom, hypothesis = _normalize_type(type_name, pointer_size)
                if atom:
                    evidence_id = graph.add_evidence(
                        "ghidra_native_parameter_declaration", relative,
                        source_address=_address(raw.get("address")), confidence="medium",
                        provenance=["ghidra_pseudocode"],
                        basis="Ghidra pseudocode supplies an analysis-derived native parameter declaration",
                        details={"function_id": function_id, "index": index, "declared_type": type_name},
                    )
                    graph.add_root(parameter_id, atom, evidence_id, confidence="medium", hypothesis=hypothesis)
        for name, type_name in _local_declarations(code):
            if name in variables_by_function[function_id]:
                continue
            local_id = _stable_id("native-value", "local", architecture, function_id, name)
            graph.add_node(
                local_id, kind="local", architecture=architecture, function_id=function_id,
                name=name, source_path=relative, source_address=None, declared_type=type_name,
            )
            variables_by_function[function_id][name] = local_id
            atom, hypothesis = _normalize_type(type_name, pointer_size)
            if atom:
                evidence_id = graph.add_evidence(
                    "ghidra_native_local_declaration", relative,
                    source_address=None, confidence="medium", provenance=["ghidra_pseudocode"],
                    basis="Ghidra pseudocode supplies an analysis-derived native local declaration",
                    details={"function_id": function_id, "name": name, "declared_type": type_name},
                )
                graph.add_root(local_id, atom, evidence_id, confidence="medium", hypothesis=hypothesis)

    # Preserve native assignment, cast, return, and cycles independently of prior type flow.
    for function_id, code in sorted(pseudocode.items()):
        variables = variables_by_function[function_id]
        raw = raw_by_id.get(function_id) or {}
        architecture = _architecture_for_function(raw, architectures)
        macho_slice = _slice_for_architecture(macho.slices, architecture)
        pointer_size = macho_slice.pointer_size if macho_slice else 4
        relative = str((recovered_by_id.get(function_id, {}).get("decompilation") or {}).get("output_path") or "").replace("\\", "/")
        for lhs, rhs in _assignments(code):
            target = variables.get(lhs)
            if target is None:
                continue
            rendered, cast_type = _strip_casts(rhs)
            source_name = _simple_variable(rendered)
            if source_name in variables:
                graph.add_edge(
                    variables[source_name], target, "native_assignment",
                    confidence="high", hypothesis=False,
                    basis="Pseudocode contains a direct whole-value assignment",
                    source_path=relative,
                )
            if cast_type:
                atom, _ = _normalize_type(cast_type, pointer_size)
                if atom:
                    evidence_id = graph.add_evidence(
                        "explicit_native_cast", relative, source_address=None,
                        confidence="medium", provenance=["ghidra_pseudocode"],
                        basis="An explicit cast proves only a static candidate type, not runtime identity",
                        details={"function_id": function_id, "target": lhs, "cast": cast_type},
                    )
                    graph.add_root(target, atom, evidence_id, confidence="medium", hypothesis=True)
        for match in re.finditer(r"(?m)^\s*return\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*;", code):
            source = variables.get(match.group(1))
            if source:
                graph.add_edge(
                    source, returns_by_function[function_id], "native_return",
                    confidence="high", hypothesis=False,
                    basis="Pseudocode returns this exact value", source_path=relative,
                )

    # C++ ABI roots: exact special-member receivers and explicit vptr assignments.
    specials_by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for special in cpp.get("special_member_functions") or []:
        for function_id in special.get("function_ids") or []:
            specials_by_function[str(function_id)].append(special)
    for function_id, specials in sorted(specials_by_function.items()):
        variables = variables_by_function.get(function_id, {})
        receiver_id = variables.get("this") or parameters_by_function.get(function_id, {}).get(0)
        if receiver_id is None:
            continue
        for special in sorted(specials, key=lambda item: str(item.get("id"))):
            for class_id in special.get("class_ids") or []:
                if str(class_id) not in supported_cpp_class_ids:
                    continue
                cpp_class = cpp_classes.get(str(class_id)) or {}
                exact = special.get("classification") == "exact"
                evidence_id = graph.add_evidence(
                    "cpp_special_member_receiver", "analysis/cpp-object-model.json",
                    source_address=special.get("address"),
                    confidence="high" if exact else "medium",
                    provenance=["itanium_name_mangling", "cpp_object_model"],
                    basis="An ABI constructor/destructor variant binds its receiver to its recovered C++ class",
                    details={"special_member_id": special.get("id"), "class_id": class_id, "kind": special.get("kind"), "abi_variant": special.get("abi_variant")},
                )
                graph.add_root(
                    receiver_id,
                    NativeAtom("cpp_object_pointer", str(cpp_class.get("display_name") or cpp_class.get("mangled_type_encoding") or class_id), cpp_class_id=str(class_id), pointer_depth=1),
                    evidence_id, confidence="high" if exact else "medium", hypothesis=not exact,
                )

    assignment_receiver: dict[str, str] = {}
    exact_assignment_lines: dict[tuple[str, str], list[tuple[int, str]]] = defaultdict(list)
    for assignment in cpp.get("vtable_assignments") or []:
        function_id = str(assignment.get("function_id") or "")
        variables = variables_by_function.get(function_id, {})
        variable = _expression_variable(str(assignment.get("object_expression") or ""), variables)
        if variable:
            receiver_id = variables[variable]
        else:
            receiver_id = _stable_id("native-value", "vptr-object", assignment.get("id"))
            raw = raw_by_id.get(function_id) or {}
            graph.add_node(
                receiver_id, kind="vptr_object", architecture=str(assignment.get("architecture") or "unknown"),
                function_id=function_id, name=None,
                source_path=(recovered_by_id.get(function_id, {}).get("decompilation") or {}).get("output_path"),
                source_address=None, declared_type=None,
                object_expression=assignment.get("object_expression"),
            )
        assignment_receiver[str(assignment["id"])] = receiver_id
        for class_id in assignment.get("class_ids") or []:
            if str(class_id) not in supported_cpp_class_ids:
                continue
            cpp_class = cpp_classes.get(str(class_id)) or {}
            exact = assignment.get("classification") == "exact"
            evidence_id = graph.add_evidence(
                "cpp_vptr_assignment", "analysis/cpp-object-model.json",
                source_address=None, confidence="high" if exact else "medium",
                provenance=["cpp_object_model", "ghidra_pseudocode", "itanium_virtual_table"],
                basis="A mechanically verified object store writes a recovered virtual-table address point",
                details={"assignment_id": assignment.get("id"), "class_id": class_id, "address_point_id": assignment.get("address_point_id"), "pseudocode_line": assignment.get("pseudocode_line")},
            )
            graph.add_root(
                receiver_id,
                NativeAtom("cpp_dynamic_object", str(cpp_class.get("display_name") or cpp_class.get("mangled_type_encoding") or class_id), cpp_class_id=str(class_id), pointer_depth=1),
                evidence_id, confidence="high" if exact else "medium", hypothesis=not exact,
            )
            if exact and variable:
                exact_assignment_lines[(function_id, variable)].append((int(assignment.get("pseudocode_line") or 0), str(class_id)))

    # A virtual slot proves only a candidate receiver-class relationship for its implementation.
    vtable_by_id = {str(item["id"]): item for item in cpp.get("vtables") or []}
    for slot in cpp.get("vtable_slots") or []:
        vtable = vtable_by_id.get(str(slot.get("vtable_id"))) or {}
        class_id = vtable.get("class_id")
        if not class_id or class_id not in supported_cpp_class_ids:
            continue
        cpp_class = cpp_classes[str(class_id)]
        for function_id in slot.get("target_function_ids") or []:
            receiver_id = variables_by_function.get(str(function_id), {}).get("this") or parameters_by_function.get(str(function_id), {}).get(0)
            if receiver_id is None:
                continue
            evidence_id = graph.add_evidence(
                "cpp_vtable_slot_receiver_candidate", "analysis/cpp-object-model.json",
                source_address=slot.get("slot_address"), confidence="medium",
                provenance=["cpp_object_model", "itanium_virtual_table"],
                basis="A vtable slot implementation accepts a receiver compatible with the table class, but inheritance may reuse the implementation",
                details={"slot_id": slot.get("id"), "class_id": class_id},
            )
            graph.add_root(
                receiver_id,
                NativeAtom("cpp_object_pointer", str(cpp_class.get("display_name") or cpp_class.get("mangled_type_encoding") or class_id), cpp_class_id=str(class_id), pointer_depth=1),
                evidence_id, confidence="medium", hypothesis=True,
            )

    # Exact Ghidra direct-call identities bind simple arguments and returns.
    direct_targets_by_caller: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for edge in call_edges:
        if (
            edge.get("semantic_target_resolved")
            and edge.get("target_function_id")
            and not edge.get("indirect")
            and not edge.get("objective_c_dispatch")
        ):
            caller = str(edge.get("caller_id") or "")
            target = str(edge.get("target_function_id"))
            target_record = raw_by_id.get(target) or {}
            aliases = {
                str(edge.get("target_name") or ""),
                str(target_record.get("name") or ""),
                str(target_record.get("full_name") or ""),
            }
            for alias in aliases:
                if alias:
                    direct_targets_by_caller[caller][alias].add(target)
                    direct_targets_by_caller[caller][alias.removeprefix("_")].add(target)
    special_exact_classes_by_function = {
        function_id: sorted({
            str(class_id)
            for special in specials
            if special.get("classification") == "exact" and special.get("kind") == "constructor"
            for class_id in special.get("class_ids") or []
            if str(class_id) in supported_cpp_class_ids
        })
        for function_id, specials in specials_by_function.items()
    }
    for caller, code in sorted(pseudocode.items()):
        variables = variables_by_function[caller]
        aliases = direct_targets_by_caller.get(caller, {})
        relative = str((recovered_by_id.get(caller, {}).get("decompilation") or {}).get("output_path") or "").replace("\\", "/")
        for call in _calls(code):
            candidates = set(aliases.get(call["callee"], set()))
            candidates.update(aliases.get(call["callee"].removeprefix("_"), set()))
            if len(candidates) != 1:
                continue
            target_function = next(iter(candidates))
            for index, argument in enumerate(call["arguments"]):
                source_name = _simple_variable(argument)
                source_id = variables.get(source_name or "")
                target_id = parameters_by_function.get(target_function, {}).get(index)
                if source_id and target_id:
                    graph.add_edge(
                        source_id, target_id, "direct_call_argument_binding",
                        confidence="high", hypothesis=False,
                        basis="An exact direct call and a simple pseudocode argument bind the same ABI position",
                        source_path=relative,
                    )
                    for class_id in special_exact_classes_by_function.get(target_function, []):
                        if index != 0:
                            continue
                        cpp_class = cpp_classes.get(class_id) or {}
                        evidence_id = graph.add_evidence(
                            "exact_constructor_call_receiver", relative,
                            source_address=None, confidence="high",
                            provenance=["ghidra_callgraph", "ghidra_pseudocode", "cpp_object_model"],
                            basis="An exact direct call passes this value as the receiver of an exact ABI constructor",
                            details={"caller_function_id": caller, "constructor_function_id": target_function, "class_id": class_id, "pseudocode_line": call["line"]},
                        )
                        graph.add_root(
                            source_id,
                            NativeAtom("cpp_dynamic_object", str(cpp_class.get("display_name") or cpp_class.get("mangled_type_encoding") or class_id), cpp_class_id=class_id, pointer_depth=1),
                            evidence_id, confidence="high", hypothesis=False,
                        )
            lhs = variables.get(str(call.get("lhs") or ""))
            target_return = returns_by_function.get(target_function)
            if lhs and target_return:
                graph.add_edge(
                    target_return, lhs, "direct_call_return_binding",
                    confidence="high", hypothesis=False,
                    basis="An exact direct call assigns its return to this simple value",
                    source_path=relative,
                )

    # Globals and pointer-cell types are keyed by exact in-image addresses.
    global_nodes: dict[tuple[str, int], str] = {}
    global_references: dict[str, list[dict[str, Any]]] = defaultdict(list)
    exact_symbols_by_arch_address: dict[tuple[str, int], set[str]] = defaultdict(set)
    for macho_slice in macho.slices:
        for symbol in macho_slice.symbols_by_index:
            if symbol and int(symbol.get("value") or 0):
                exact_symbols_by_arch_address[(macho_slice.architecture_name, int(symbol["value"]))].add(str(symbol["name"]))
    for function_id, code in sorted(pseudocode.items()):
        raw = raw_by_id.get(function_id) or {}
        architecture = _architecture_for_function(raw, architectures)
        macho_slice = _slice_for_architecture(macho.slices, architecture)
        if macho_slice is None:
            continue
        relative = str((recovered_by_id.get(function_id, {}).get("decompilation") or {}).get("output_path") or "").replace("\\", "/")
        for match in _GLOBAL_RE.finditer(code):
            label = match.group("label")
            if label.startswith(("FUN_", "LAB_")):
                continue
            address_value = int(match.group("address"), 16)
            if macho_slice.vm_to_offset(address_value) is None:
                continue
            key = (architecture, address_value)
            global_id = global_nodes.get(key)
            if global_id is None:
                global_id = _stable_id("native-value", "global", architecture, address_value)
                graph.add_node(
                    global_id, kind="global", architecture=architecture,
                    function_id=None, name=None, source_path="executable",
                    source_address=_address(address_value), declared_type=None,
                    global_address=_address(address_value),
                )
                global_nodes[key] = global_id
            global_references[global_id].append({
                "function_id": function_id,
                "path": relative,
                "pseudocode_line": code.count("\n", 0, match.start()) + 1,
                "label": label,
            })
            before = code[max(0, match.start() - 100):match.start()]
            cast_match = re.search(r"\*\s*\(\s*([^()]{1,70}?)\s*\*\s*\)\s*$", before)
            if cast_match:
                atom, _ = _normalize_type(cast_match.group(1), macho_slice.pointer_size)
                if atom:
                    evidence_id = graph.add_evidence(
                        "global_dereference_type", relative, source_address=None,
                        confidence="medium", provenance=["ghidra_pseudocode"],
                        basis="A typed pseudocode dereference supplies a candidate storage type for an exact global address",
                        details={"global_address": _address(address_value), "label": label, "declared_type": cast_match.group(1).strip()},
                    )
                    graph.add_root(global_id, atom, evidence_id, confidence="medium", hypothesis=True)
    for assignment in cpp.get("vtable_assignments") or []:
        architecture = str(assignment.get("architecture") or "unknown")
        cell = assignment.get("pointer_cell_address")
        if not cell:
            continue
        key = (architecture, int(str(cell), 16))
        global_id = global_nodes.get(key)
        if global_id is None:
            global_id = _stable_id("native-value", "global", architecture, key[1])
            graph.add_node(
                global_id, kind="global", architecture=architecture, function_id=None,
                name=None, source_path="executable", source_address=_address(key[1]),
                declared_type=None, global_address=_address(key[1]),
            )
            global_nodes[key] = global_id
        for class_id in assignment.get("class_ids") or []:
            if str(class_id) not in supported_cpp_class_ids:
                continue
            cpp_class = cpp_classes.get(str(class_id)) or {}
            exact = assignment.get("classification") == "exact"
            evidence_id = graph.add_evidence(
                "vtable_pointer_cell", "analysis/cpp-object-model.json",
                source_address=_address(key[1]), confidence="high" if exact else "medium",
                provenance=["macho_pointer", "cpp_object_model"],
                basis="This exact global pointer cell supplies a validated virtual-table address point",
                details={"assignment_id": assignment.get("id"), "class_id": class_id},
            )
            graph.add_root(
                global_id,
                NativeAtom("vtable_pointer", str(cpp_class.get("display_name") or cpp_class.get("mangled_type_encoding") or class_id), cpp_class_id=str(class_id), pointer_depth=1),
                evidence_id, confidence="high" if exact else "medium", hypothesis=not exact,
            )

    # Numeric field accesses and field-value flow.
    field_access_records: list[dict[str, Any]] = []
    field_nodes: dict[tuple[str, int], str] = {}
    for function_id, code in sorted(pseudocode.items()):
        raw = raw_by_id.get(function_id) or {}
        architecture = _architecture_for_function(raw, architectures)
        macho_slice = _slice_for_architecture(macho.slices, architecture)
        pointer_size = macho_slice.pointer_size if macho_slice else 4
        variables = variables_by_function[function_id]
        relative = str((recovered_by_id.get(function_id, {}).get("decompilation") or {}).get("output_path") or "").replace("\\", "/")
        for access in _field_accesses(code, pointer_size):
            receiver_id = variables.get(access["base"])
            if receiver_id is None:
                continue
            key = (receiver_id, int(access["offset"]))
            field_id = field_nodes.get(key)
            if field_id is None:
                field_id = _stable_id("native-value", "field", receiver_id, access["offset"])
                graph.add_node(
                    field_id, kind="field", architecture=architecture, function_id=function_id,
                    name=None, source_path=relative, source_address=None, declared_type=None,
                    receiver_value_id=receiver_id, field_offset=access["offset"],
                )
                field_nodes[key] = field_id
            if access["declared_type"]:
                atom, _ = _normalize_type(access["declared_type"], pointer_size)
                if atom:
                    evidence_id = graph.add_evidence(
                        "numeric_field_access_type", relative, source_address=None,
                        confidence="medium", provenance=["ghidra_pseudocode"],
                        basis="A typed numeric-offset dereference supplies a candidate field storage type",
                        details={"function_id": function_id, "base": access["base"], "offset": access["offset"], "width": access["width"], "declared_type": access["declared_type"]},
                    )
                    graph.add_root(field_id, atom, evidence_id, confidence="medium", hypothesis=True)
            line_text = access["line_text"]
            if access["access_kind"] == "read":
                lhs = re.match(r"\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*=", line_text)
                if lhs and lhs.group(1) in variables:
                    graph.add_edge(
                        field_id, variables[lhs.group(1)], "field_read",
                        confidence="high", hypothesis=False,
                        basis="A numeric-offset field read assigns this exact simple value",
                        source_path=relative,
                    )
            else:
                rhs = line_text.split("=", 1)[1].rsplit(";", 1)[0].strip() if "=" in line_text else ""
                rhs_name = _simple_variable(rhs)
                if rhs_name in variables:
                    graph.add_edge(
                        variables[rhs_name], field_id, "field_write",
                        confidence="high", hypothesis=False,
                        basis="A numeric-offset field write stores this exact simple value",
                        source_path=relative,
                    )
            access_id = _stable_id("native-field-access", architecture, function_id, access["start"], receiver_id, access["offset"])
            field_access_records.append({
                "id": access_id,
                "architecture": architecture,
                "function_id": function_id,
                "receiver_value_id": receiver_id,
                "field_value_id": field_id,
                "offset": access["offset"],
                "width": access["width"],
                "access_kind": access["access_kind"],
                "form": access["form"],
                "declared_type": access["declared_type"],
                "pseudocode_line": access["line"],
                "expression": access["expression"],
                "source_path": relative,
                "classification": "exact" if access["width"] is not None else "candidate_set",
                "confidence": "high" if access["width"] is not None else "medium",
                "provenance": ["ghidra_pseudocode", "numeric_offset"],
                "evidence": [{"source": relative, "address": None, "basis": "mechanically parsed numeric-offset memory access"}],
                "failure_reasons": [] if access["width"] is not None else ["field_access_width_not_recovered"],
            })

    # Add callsite receiver nodes before solving.
    virtual_calls_by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for callsite in cpp.get("indirect_callsites") or []:
        if callsite.get("kind") == "virtual":
            virtual_calls_by_function[str(callsite.get("caller_function_id") or "")].append(callsite)
    virtual_form_by_callsite: dict[str, dict[str, Any]] = {}
    receiver_by_callsite: dict[str, str] = {}
    for function_id, callsites in sorted(virtual_calls_by_function.items()):
        code = pseudocode.get(function_id, "")
        raw = raw_by_id.get(function_id) or {}
        architecture = _architecture_for_function(raw, architectures)
        macho_slice = _slice_for_architecture(macho.slices, architecture)
        pointer_size = macho_slice.pointer_size if macho_slice else 4
        forms = _virtual_forms(code, pointer_size)
        ordered_calls = sorted(callsites, key=lambda item: _address_key(_address(item.get("call_site"))))
        associated: list[dict[str, Any] | None] = [None] * len(ordered_calls)
        if len(ordered_calls) == 1 and len(forms) == 1:
            associated[0] = forms[0]
        elif (
            ordered_calls and len(ordered_calls) == len(forms) and forms
            and len({item["slot_index"] for item in forms}) == 1
            and len({item["receiver"] for item in forms}) == 1
        ):
            associated = list(forms)
        for index, callsite in enumerate(ordered_calls):
            form = associated[index]
            if form is None:
                continue
            callsite_id = str(callsite["id"])
            virtual_form_by_callsite[callsite_id] = form
            receiver_source = variables_by_function.get(function_id, {}).get(form["receiver"])
            receiver_id = _stable_id("native-value", "virtual-receiver", callsite_id)
            graph.add_node(
                receiver_id, kind="virtual_receiver", architecture=str(callsite.get("architecture") or architecture),
                function_id=function_id, name=form["receiver"], source_path=(recovered_by_id.get(function_id, {}).get("decompilation") or {}).get("output_path"),
                source_address=callsite.get("call_site"), declared_type=None,
                cpp_callsite_id=callsite_id,
            )
            receiver_by_callsite[callsite_id] = receiver_id
            if receiver_source:
                graph.add_edge(
                    receiver_source, receiver_id, "virtual_receiver_binding",
                    confidence="high", hypothesis=False,
                    basis="One mechanically associated virtual form names this exact receiver value",
                    source_path=(recovered_by_id.get(function_id, {}).get("decompilation") or {}).get("output_path"),
                    source_address=callsite.get("call_site"),
                )

    state, solve_stats = graph.solve()
    cycles = graph.cyclic_components()
    cycle_by_value = {value: _stable_id("native-cycle", *component) for component in cycles for value in component}

    values: list[dict[str, Any]] = []
    classifications = Counter()
    failure_counts = Counter()
    if unsupported_cpp_classes:
        failure_counts["unsupported_cpp_abi"] = len(unsupported_cpp_classes)
    for node_id, node in sorted(graph.nodes.items()):
        effective = _effective_states(state[node_id], graph.evidence)
        candidates = [_atom_record(atom, item) for atom, item in sorted(effective.items())]
        classification, confidence, failures = _classified_state(effective)
        if node_id in cycle_by_value and not candidates:
            failures.append("cyclic_flow_has_no_supported_incoming_evidence")
        classifications[classification] += 1
        failure_counts.update(failures)
        evidence_ids = sorted({value for item in candidates for value in item["evidence_ids"]})
        step_ids = sorted({value for item in candidates for value in item["propagation_step_ids"]})
        provenance = sorted({
            value
            for evidence_id in evidence_ids
            for value in graph.evidence[evidence_id]["provenance"]
        })
        values.append({
            **node,
            "related_objc_method_ids": method_ids_by_function.get(str(node.get("function_id") or ""), []),
            "related_objc_class_names": objc_classes_by_function.get(str(node.get("function_id") or ""), []),
            "classification": classification,
            "confidence": confidence,
            "type_candidates": candidates,
            "evidence_ids": evidence_ids,
            "propagation_step_ids": step_ids,
            "cycle_id": cycle_by_value.get(node_id),
            "provenance": provenance,
            "failure_reasons": sorted(set(failures)),
        })
    values_by_id = {item["id"]: item for item in values}

    globals_records: list[dict[str, Any]] = []
    for (architecture, address_value), value_id in sorted(global_nodes.items()):
        value = values_by_id[value_id]
        globals_records.append({
            "id": _stable_id("native-global", architecture, address_value),
            "architecture": architecture,
            "address": _address(address_value),
            "value_id": value_id,
            "exact_symbols": sorted(exact_symbols_by_arch_address.get((architecture, address_value), set())),
            "references": sorted(global_references.get(value_id, []), key=lambda item: (item["function_id"], item["pseudocode_line"], item["label"])),
            "classification": value["classification"],
            "confidence": value["confidence"],
            "type_candidates": value["type_candidates"],
            "provenance": value["provenance"],
            "evidence_ids": value["evidence_ids"],
            "failure_reasons": value["failure_reasons"],
        })

    # Convert accesses into class-associated or anonymous layouts without naming fields.
    layout_groups: dict[tuple[str, str], dict[str, Any]] = {}
    access_by_field: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for access in field_access_records:
        access_by_field[access["field_value_id"]].append(access)
    for access in field_access_records:
        receiver = values_by_id[access["receiver_value_id"]]
        cpp_candidates = sorted({
            str(item["cpp_class_id"])
            for item in receiver["type_candidates"]
            if item.get("cpp_class_id")
        })
        exact_class = receiver["classification"] == "exact" and len(cpp_candidates) == 1
        if exact_class:
            group_key = (access["architecture"], f"class:{cpp_candidates[0]}")
        else:
            group_key = (access["architecture"], f"anonymous:{access['function_id']}:{access['receiver_value_id']}")
        group = layout_groups.setdefault(group_key, {
            "architecture": access["architecture"],
            "class_ids": set(cpp_candidates),
            "receiver_value_ids": set(),
            "access_ids": set(),
            "offsets": defaultdict(lambda: {"access_ids": set(), "widths": set(), "field_value_ids": set()}),
            "exact_class": exact_class,
        })
        group["receiver_value_ids"].add(access["receiver_value_id"])
        group["access_ids"].add(access["id"])
        offset_group = group["offsets"][int(access["offset"])]
        offset_group["access_ids"].add(access["id"])
        offset_group["field_value_ids"].add(access["field_value_id"])
        if access["width"] is not None:
            offset_group["widths"].add(int(access["width"]))

    layouts: list[dict[str, Any]] = []
    fields: list[dict[str, Any]] = []
    for (architecture, identity), group in sorted(layout_groups.items()):
        layout_id = _stable_id("native-layout", architecture, identity)
        field_ids: list[str] = []
        for offset, offset_group in sorted(group["offsets"].items()):
            field_id = _stable_id("native-field", layout_id, offset)
            field_ids.append(field_id)
            candidate_records = [
                candidate
                for value_id in sorted(offset_group["field_value_ids"])
                for candidate in values_by_id[value_id]["type_candidates"]
            ]
            unique_candidates = {
                json.dumps(item, sort_keys=True, ensure_ascii=False): item
                for item in candidate_records
            }
            widths = sorted(offset_group["widths"])
            if group["exact_class"] and len(widths) == 1 and len(unique_candidates) == 1:
                field_classification = "exact"
            elif widths or unique_candidates:
                field_classification = "candidate_set"
            else:
                field_classification = "unresolved"
            field_failures: list[str] = []
            if not widths:
                field_failures.append("field_width_not_recovered")
            if len(widths) > 1:
                field_failures.append("conflicting_field_access_widths")
            if not unique_candidates:
                field_failures.append("field_type_not_recovered")
            if len(unique_candidates) > 1:
                field_failures.append("multiple_field_type_candidates")
            if not group["exact_class"]:
                field_failures.append("field_owner_class_not_exact")
            failure_counts.update(field_failures)
            fields.append({
                "id": field_id,
                "layout_id": layout_id,
                "architecture": architecture,
                "offset": offset,
                "width_candidates": widths,
                "type_candidates": [unique_candidates[key] for key in sorted(unique_candidates)],
                "field_value_ids": sorted(offset_group["field_value_ids"]),
                "access_ids": sorted(offset_group["access_ids"]),
                "classification": field_classification,
                "confidence": _confidence(field_classification),
                "provenance": ["ghidra_pseudocode", "numeric_offset"],
                "failure_reasons": sorted(set(field_failures)),
            })
        layout_classification = "exact" if group["exact_class"] else ("candidate_set" if group["class_ids"] else "unresolved")
        layout_failures = [] if group["exact_class"] else (["multiple_layout_owner_candidates"] if group["class_ids"] else ["layout_owner_class_unresolved"])
        failure_counts.update(layout_failures)
        layouts.append({
            "id": layout_id,
            "architecture": architecture,
            "class_ids": sorted(group["class_ids"]),
            "receiver_value_ids": sorted(group["receiver_value_ids"]),
            "field_ids": field_ids,
            "access_ids": sorted(group["access_ids"]),
            "classification": layout_classification,
            "confidence": _confidence(layout_classification),
            "provenance": ["native_type_flow", "numeric_offset"],
            "failure_reasons": layout_failures,
        })

    # Receiver-aware virtual dispatch refinements remain additive.
    descendants: dict[str, set[str]] = defaultdict(set)
    for class_id in supported_cpp_class_ids:
        descendants[class_id].add(class_id)
    changed = True
    relationships = [
        item
        for item in cpp.get("inheritance_relationships") or []
        if item.get("classification") == "exact"
        and str(item.get("base_class_id") or "") in supported_cpp_class_ids
        and str(item.get("derived_class_id") or "") in supported_cpp_class_ids
    ]
    while changed:
        changed = False
        for relationship in relationships:
            derived = str(relationship["derived_class_id"])
            base = str(relationship["base_class_id"])
            before = len(descendants[base])
            descendants[base].update(descendants.get(derived, {derived}))
            changed = changed or len(descendants[base]) != before
    slots_by_class_index: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for slot in cpp.get("vtable_slots") or []:
        vtable = vtable_by_id.get(str(slot.get("vtable_id"))) or {}
        if str(vtable.get("class_id") or "") in supported_cpp_class_ids:
            slots_by_class_index[(str(vtable["class_id"]), int(slot.get("slot_index") or 0))].append(slot)

    refinements: list[dict[str, Any]] = []
    hypotheses: list[dict[str, Any]] = [
        {
            "id": _stable_id("native-flow-hypothesis", edge["id"]),
            "kind": "native_type_propagation",
            "propagation_step_id": edge["id"],
            "confidence": edge["confidence"],
            "basis": edge["basis"],
        }
        for edge in graph.edges.values()
        if edge["hypothesis"]
    ]
    cpp_callsites = list(cpp.get("indirect_callsites") or [])
    for callsite in sorted(cpp_callsites, key=lambda item: (str(item.get("architecture")), _address_key(_address(item.get("call_site"))), str(item.get("id")))):
        callsite_id = str(callsite["id"])
        receiver_id = receiver_by_callsite.get(callsite_id)
        receiver = values_by_id.get(receiver_id) if receiver_id else None
        form = virtual_form_by_callsite.get(callsite_id)
        class_ids = sorted({
            str(item["cpp_class_id"])
            for item in (receiver.get("type_candidates") if receiver else [])
            if item.get("cpp_class_id")
        })
        exact_dynamic_classes: set[str] = set()
        if form:
            for line, class_id in exact_assignment_lines.get((str(callsite.get("caller_function_id")), form["receiver"]), []):
                if 0 < line <= int(form["line"]):
                    exact_dynamic_classes.add(class_id)
        exact_dynamic = len(exact_dynamic_classes) == 1
        effective_classes: set[str] = set(exact_dynamic_classes)
        if not effective_classes:
            for class_id in class_ids:
                effective_classes.update(descendants.get(class_id, {class_id}))
        target_ids: set[str] = set()
        slot_ids: set[str] = set()
        if form:
            for class_id in sorted(effective_classes):
                for slot in slots_by_class_index.get((class_id, int(form["slot_index"])), []):
                    slot_ids.add(str(slot["id"]))
                    target_ids.update(str(value) for value in slot.get("target_function_ids") or [])
        failures: list[str] = []
        if exact_dynamic and len(target_ids) == 1:
            classification = "exact"
        elif target_ids:
            classification = "candidate_set"
            if not exact_dynamic:
                failures.append("runtime_vtable_not_exact_at_callsite")
            if len(target_ids) > 1:
                failures.append("multiple_refined_virtual_targets")
            elif not exact_dynamic:
                failures.append("unique_target_not_promoted_without_exact_runtime_vtable")
        else:
            classification = "unresolved"
            failures.append("native_flow_did_not_recover_virtual_targets")
            if not receiver_id:
                failures.append("virtual_receiver_not_mechanically_associated")
            elif not class_ids:
                failures.append("virtual_receiver_has_no_cpp_class_evidence")
        original_targets = sorted(str(value) for value in callsite.get("possible_target_function_ids") or [])
        changed_record = bool(target_ids) and (
            classification != callsite.get("classification")
            or sorted(target_ids) != original_targets
        )
        refinement_id = _stable_id("native-virtual-refinement", callsite_id)
        refinement = {
            "id": refinement_id,
            "cpp_callsite_id": callsite_id,
            "architecture": str(callsite.get("architecture") or "unknown"),
            "call_site": _address(callsite.get("call_site")),
            "caller_function_id": str(callsite.get("caller_function_id") or ""),
            "receiver_value_id": receiver_id,
            "slot_index": form.get("slot_index") if form else callsite.get("slot_index"),
            "original_classification": str(callsite.get("classification") or "unresolved"),
            "original_target_function_ids": original_targets,
            "receiver_class_ids": class_ids,
            "exact_dynamic_class_ids": sorted(exact_dynamic_classes),
            "effective_runtime_class_ids": sorted(effective_classes),
            "supporting_slot_ids": sorted(slot_ids),
            "refined_target_function_ids": sorted(target_ids),
            "classification": classification,
            "confidence": _confidence(classification),
            "changed": changed_record,
            "provenance": sorted({"cpp_object_model", *( ["native_type_flow", "ghidra_pseudocode"] if receiver_id else [])}),
            "evidence_ids": receiver.get("evidence_ids", []) if receiver else [],
            "failure_reasons": sorted(set(failures)),
        }
        refinements.append(refinement)
        failure_counts.update(failures)
        for target_id in sorted(target_ids):
            hypotheses.append({
                "id": _stable_id("native-virtual-edge", refinement_id, target_id),
                "kind": "native_virtual_dispatch_target",
                "refinement_id": refinement_id,
                "target_function_id": target_id,
                "classification": classification,
                "confidence": _confidence(classification),
                "basis": "Receiver-aware native flow retains this target separately from the unchanged C++ and direct-call artifacts",
            })

    function_index: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    class_index: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    global_index: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    layout_index: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    callsite_index: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for function_id in sorted(raw_by_id):
        function_index[function_id]["method_ids"].update(method_ids_by_function.get(function_id, []))
        function_index[function_id]["objc_class_names"].update(objc_classes_by_function.get(function_id, []))
    for class_id, cpp_class in sorted(cpp_classes.items()):
        class_index[class_id]["method_ids"].update(
            str(value) for value in cpp_class.get("related_objc_method_ids") or []
        )
        class_index[class_id]["objc_class_names"].update(
            str(value) for value in cpp_class.get("related_objc_class_names") or []
        )
    for value in values:
        if value.get("function_id"):
            function_index[str(value["function_id"])]["value_ids"].add(value["id"])
        for candidate in value["type_candidates"]:
            class_id = candidate.get("cpp_class_id")
            if class_id:
                class_index[str(class_id)]["value_ids"].add(value["id"])
                if value.get("function_id"):
                    class_index[str(class_id)]["function_ids"].add(str(value["function_id"]))
    for record in globals_records:
        global_index[record["address"]]["global_ids"].add(record["id"])
        global_index[record["address"]]["value_ids"].add(record["value_id"])
        for reference in record["references"]:
            global_index[record["address"]]["function_ids"].add(reference["function_id"])
    for layout in layouts:
        layout_index[layout["id"]]["field_ids"].update(layout["field_ids"])
        layout_index[layout["id"]]["access_ids"].update(layout["access_ids"])
        layout_index[layout["id"]]["class_ids"].update(layout["class_ids"])
        for class_id in layout["class_ids"]:
            class_index[class_id]["layout_ids"].add(layout["id"])
    for access in field_access_records:
        function_index[access["function_id"]]["field_access_ids"].add(access["id"])
    for refinement in refinements:
        callsite_index[refinement["cpp_callsite_id"]]["refinement_ids"].add(refinement["id"])
        callsite_index[refinement["cpp_callsite_id"]]["receiver_value_ids"].update([refinement["receiver_value_id"]] if refinement["receiver_value_id"] else [])
        callsite_index[refinement["cpp_callsite_id"]]["target_function_ids"].update(refinement["refined_target_function_ids"])
        function_index[refinement["caller_function_id"]]["virtual_refinement_ids"].add(refinement["id"])

    refinement_counts = Counter(item["classification"] for item in refinements)
    changed_refinements = sum(bool(item["changed"]) for item in refinements)
    layout_counts = Counter(item["classification"] for item in layouts)
    field_counts = Counter(item["classification"] for item in fields)
    global_counts = Counter(item["classification"] for item in globals_records)
    input_artifacts = [{
        "artifact": name,
        "path": f"analysis/{name}.json",
        "sha256": sha256_file(workspace / "analysis" / f"{name}.json"),
    } for name in FINGERPRINT_REPORTS]
    input_artifacts.append({
        "artifact": "executable",
        "path": f"evidence/extracted/{archive_path}".replace("\\", "/"),
        "sha256": executable_hash,
    })
    architecture_records = [{
        "name": item.architecture_name,
        "bits": item.bits,
        "pointer_size": item.pointer_size,
        "endianness": "little" if item.endian == "<" else "big",
        "cpp_abi": "itanium-cxx-abi",
        "assumptions": [
            "Ghidra pseudocode declarations, casts, and field widths are analysis evidence rather than original source facts.",
            "Only exact numeric addresses, offsets, ABI relationships, and normalized artifact identities create exact structural links.",
            "A static C++ class type includes exact recovered descendants unless an explicit preceding vptr store proves one runtime table.",
            "Interprocedural bindings require an exact direct call identity and simple argument or assignment expressions.",
        ],
    } for item in sorted(macho.slices, key=lambda value: value.architecture_name)]
    facts = {
        "architecture_records": architecture_records,
        "input_artifacts": input_artifacts,
        "summary": {
            "value_count": len(values),
            "global_count": len(globals_records),
            "field_access_count": len(field_access_records),
            "field_count": len(fields),
            "layout_count": len(layouts),
            "virtual_refinement_count": len(refinements),
            "changed_virtual_refinement_count": changed_refinements,
            "evidence_count": len(graph.evidence),
            "propagation_step_count": len(graph.edges),
            "unsupported_cpp_class_count": len(unsupported_cpp_classes),
            "classification_counts": {name: classifications.get(name, 0) for name in CLASSIFICATIONS},
            "global_classification_counts": {name: global_counts.get(name, 0) for name in CLASSIFICATIONS},
            "layout_classification_counts": {name: layout_counts.get(name, 0) for name in CLASSIFICATIONS},
            "field_classification_counts": {name: field_counts.get(name, 0) for name in CLASSIFICATIONS},
            "virtual_refinement_classification_counts": {name: refinement_counts.get(name, 0) for name in CLASSIFICATIONS},
            "failure_reason_counts": {name: failure_counts[name] for name in sorted(failure_counts)},
        },
        "values": values,
        "unsupported_cpp_classes": unsupported_cpp_classes,
        "globals": globals_records,
        "field_accesses": sorted(field_access_records, key=lambda item: (item["architecture"], item["function_id"], item["pseudocode_line"], item["id"])),
        "fields": sorted(fields, key=lambda item: (item["architecture"], item["layout_id"], item["offset"], item["id"])),
        "layouts": sorted(layouts, key=lambda item: (item["architecture"], item["id"])),
        "virtual_dispatch_refinements": refinements,
        "evidence": [graph.evidence[key] for key in sorted(graph.evidence)],
        "propagation_steps": [graph.edges[key] for key in sorted(graph.edges)],
        "fixed_point": {
            "converged": True,
            **solve_stats,
            "cyclic_component_count": len(cycles),
            "cyclic_components": [{"id": _stable_id("native-cycle", *component), "value_ids": component} for component in cycles],
        },
        "pseudocode_artifacts": pseudocode_artifacts,
        "indexes": {
            "functions": _freeze_index(function_index, "function_id"),
            "classes": _freeze_index(class_index, "class_id"),
            "globals": _freeze_index(global_index, "address"),
            "layouts": _freeze_index(layout_index, "layout_id"),
            "callsites": _freeze_index(callsite_index, "cpp_callsite_id"),
        },
        "evidence_boundary": {
            "behavior_or_semantics_inferred": False,
            "field_names_invented": False,
            "names_strings_selectors_or_proximity_used_as_class_evidence": False,
            "functions_preserved": True,
            "direct_callgraph_preserved": True,
            "objc_dispatch_preserved": True,
            "objc_type_flow_preserved": True,
            "platform_api_map_preserved": True,
            "cpp_object_model_preserved": True,
            "virtual_refinements_additive": True,
            "unsupported_cpp_abi_promoted": False,
        },
    }
    errors = [{
        "code": reason,
        "count": count,
        "message": "One or more native type/layout records retain this uncertainty or unresolved reason",
    } for reason, count in sorted(failure_counts.items())]
    native_type_flow = report_envelope("native-type-flow", facts, hypotheses=sorted(hypotheses, key=lambda item: item["id"]), errors=errors)
    native_type_flow_path = workspace / "analysis" / "native-type-flow.json"
    report_path = workspace / "reports" / "native-type-flow-report.md"
    write_json_atomic(native_type_flow_path, native_type_flow)
    write_text_atomic(report_path, render_native_type_flow_report(facts))
    preserved_after = {
        name: sha256_file(workspace / "analysis" / f"{name}.json")
        for name in PRESERVED_REPORTS
    }
    if preserved_before != preserved_after:
        raise NativeTypeFlowError("A preserved upstream artifact changed during native type flow")
    return NativeTypeFlowResult(workspace, native_type_flow, native_type_flow_path, report_path)
