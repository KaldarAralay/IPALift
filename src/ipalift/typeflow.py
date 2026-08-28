"""Deterministic Objective-C and native type-flow analysis."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .errors import IPALiftError
from .report import render_objc_type_flow_report
from .util import report_envelope, sha256_file, write_json_atomic, write_text_atomic


class TypeFlowError(IPALiftError):
    """A workspace cannot support evidence-preserving type-flow analysis."""


@dataclass(frozen=True)
class TypeFlowResult:
    workspace: Path
    type_flow: dict[str, Any]
    type_flow_path: Path
    report_path: Path


@dataclass(frozen=True, order=True)
class TypeAtom:
    kind: str
    name: str
    class_name: str | None = None
    protocols: tuple[str, ...] = ()


@dataclass(frozen=True)
class EncodingType:
    raw: str
    display: str
    kind: str
    class_name: str | None = None
    protocols: tuple[str, ...] = ()
    supported: bool = True


REQUIRED_REPORTS = (
    "callgraph",
    "functions",
    "objc-dispatch",
    "recovered-code-index",
    "strings",
)
CLASSIFICATIONS = ("exact", "candidate_set", "unresolved")
CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}
RANK_CONFIDENCE = {value: key for key, value in CONFIDENCE_RANK.items()}
_ADDRESS_PATTERN = re.compile(r"^0x[0-9a-f]+$")
_PSEUDO_CALL_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_$])(?P<callee>_?objc_msg(?:send|lookup)[A-Za-z0-9_$]*)\s*\(",
    re.IGNORECASE,
)
_CLASS_EXPRESSION = re.compile(r"&?\s*objc::class_t::([A-Za-z_$][A-Za-z0-9_$]*)")
_QUALIFIERS = set("rnNoORV")
_SCALAR_NAMES = {
    "c": "char",
    "i": "int",
    "s": "short",
    "l": "long",
    "q": "long long",
    "C": "unsigned char",
    "I": "unsigned int",
    "S": "unsigned short",
    "L": "unsigned long",
    "Q": "unsigned long long",
    "f": "float",
    "d": "double",
    "B": "BOOL",
    "v": "void",
    "*": "char *",
    "#": "Class",
    ":": "SEL",
}
_C_EXACT_TYPES = {
    "bool",
    "byte",
    "char",
    "double",
    "float",
    "int",
    "long",
    "long long",
    "short",
    "size_t",
    "uint",
    "ulong",
    "unsigned",
    "unsigned char",
    "unsigned int",
    "unsigned long",
    "unsigned long long",
    "unsigned short",
    "ushort",
    "void",
}


def _load_report(workspace: Path, name: str) -> dict[str, Any]:
    path = workspace / "analysis" / f"{name}.json"
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise TypeFlowError(f"Analysis workspace is missing analysis/{name}.json") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise TypeFlowError(f"Cannot read {path}: {exc}") from exc
    if (
        report.get("schema_version") != 1
        or report.get("artifact") != name
        or not isinstance(report.get("facts"), dict)
    ):
        raise TypeFlowError(f"Invalid IPALift {name} report: {path}")
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
        raise TypeFlowError(f"Artifact path escapes the analysis workspace: {relative}")
    candidate = (workspace / Path(*parts)).resolve()
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise TypeFlowError(f"Artifact path escapes the analysis workspace: {relative}") from exc
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


def _canonical_sha256(value: Any) -> str:
    data = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def dispatch_baseline_projection(report: dict[str, Any]) -> dict[str, Any]:
    """Return the stable, non-type-flow portion of a dispatch artifact."""
    callsite_fields = (
        "id",
        "architecture",
        "caller",
        "call_site",
        "direct_runtime_edge",
        "selector",
        "receiver",
        "classification",
        "possible_targets",
        "lookup_paths",
        "confidence",
        "confidence_basis",
        "provenance",
        "failure_reasons",
    )
    return {
        "artifact": "objc-dispatch-baseline",
        "callsites": [
            {key: callsite.get(key) for key in callsite_fields}
            for callsite in report.get("facts", {}).get("callsites", [])
        ],
        "inferred_edges": [
            item
            for item in report.get("hypotheses", [])
            if item.get("edge_kind") == "objective_c_dynamic_dispatch_inference"
        ],
    }


def _balanced_end(value: str, start: int, opening: str, closing: str) -> int:
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(start, len(value)):
        char = value[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char == '"':
            quote = char
        elif char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return index + 1
    return len(value)


def _parse_encoding_token(value: str, start: int = 0) -> tuple[EncodingType, int]:
    index = start
    while index < len(value) and value[index] in _QUALIFIERS:
        index += 1
    if index >= len(value):
        return EncodingType(value[start:index], "unknown", "unknown", supported=False), index
    token_start = index
    char = value[index]
    index += 1
    if char == "@":
        if index < len(value) and value[index] == "?":
            index += 1
            return EncodingType(value[token_start:index], "block", "objective_c_block"), index
        class_name = None
        protocols: tuple[str, ...] = ()
        if index < len(value) and value[index] == '"':
            end = index + 1
            escaped = False
            while end < len(value):
                if escaped:
                    escaped = False
                elif value[end] == "\\":
                    escaped = True
                elif value[end] == '"':
                    break
                end += 1
            contents = value[index + 1:end]
            index = min(end + 1, len(value))
            protocol_names = tuple(sorted(set(re.findall(r"<([^>]+)>", contents))))
            base = contents.split("<", 1)[0] or None
            class_name = base
            protocols = protocol_names
            display = contents or "id"
            return EncodingType(
                value[token_start:index],
                display,
                "objective_c_instance",
                class_name,
                protocols,
            ), index
        return EncodingType(value[token_start:index], "id", "objective_c_id"), index
    if char in _SCALAR_NAMES:
        kind = "objective_c_class" if char == "#" else ("selector" if char == ":" else "native")
        return EncodingType(value[token_start:index], _SCALAR_NAMES[char], kind), index
    if char == "^":
        child, index = _parse_encoding_token(value, index)
        display = f"{child.display} *"
        return EncodingType(value[token_start:index], display, "native_pointer"), index
    if char == "[":
        end = _balanced_end(value, token_start, "[", "]")
        raw = value[token_start:end]
        count_match = re.match(r"\[(\d+)", raw)
        display = f"array[{count_match.group(1)}]" if count_match else "array"
        return EncodingType(raw, display, "native"), end
    if char in "{(":
        closing = "}" if char == "{" else ")"
        end = _balanced_end(value, token_start, char, closing)
        raw = value[token_start:end]
        name_match = re.match(r"[{(]([^=})]+)", raw)
        name = name_match.group(1) if name_match else ("struct" if char == "{" else "union")
        return EncodingType(raw, name, "native"), end
    if char == "b":
        while index < len(value) and value[index].isdigit():
            index += 1
        return EncodingType(value[token_start:index], "bitfield", "native"), index
    if char == "?":
        return EncodingType(value[token_start:index], "unknown", "unknown", supported=False), index
    return EncodingType(value[token_start:index], char, "unknown", supported=False), index


def _skip_offset(value: str, index: int) -> int:
    if index < len(value) and value[index] in "+-":
        index += 1
    while index < len(value) and value[index].isdigit():
        index += 1
    return index


def _method_encoding(value: str | None) -> list[EncodingType]:
    if not value:
        return []
    result: list[EncodingType] = []
    index = 0
    while index < len(value):
        item, new_index = _parse_encoding_token(value, index)
        if new_index <= index:
            break
        result.append(item)
        index = _skip_offset(value, new_index)
    return result


def _selector_has_method_family(selector: str, family: str) -> bool:
    """Apply the Objective-C method-family lexical boundary conservatively."""
    head = selector.split(":", 1)[0]
    if not head.startswith(family):
        return False
    return len(head) == len(family) or not head[len(family)].islower()


def _property_encoding(attributes: str | None) -> str | None:
    if not attributes or not attributes.startswith("T"):
        return None
    value = attributes[1:]
    quote = False
    depth = 0
    for index, char in enumerate(value):
        if char == '"' and (index == 0 or value[index - 1] != "\\"):
            quote = not quote
        elif not quote and char in "{[(":
            depth += 1
        elif not quote and char in "}])" and depth:
            depth -= 1
        elif char == "," and not quote and depth == 0:
            return value[:index]
    return value


def _c_type(value: str) -> EncodingType:
    normalized = re.sub(r"\s+", " ", value.strip())
    normalized = re.sub(r"\b(const|volatile|register)\b", "", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    if normalized in {"ID", "id"}:
        return EncodingType(value, "id", "objective_c_id")
    if normalized == "SEL":
        return EncodingType(value, "SEL", "selector")
    if normalized in {"CLASS", "Class"}:
        return EncodingType(value, "Class", "objective_c_class")
    if re.fullmatch(r"undefined\d*|undefined(?:\s*\*)+", normalized):
        return EncodingType(value, "unknown", "unknown", supported=False)
    base = normalized.rstrip("* ").strip()
    if base in _C_EXACT_TYPES:
        return EncodingType(value, normalized, "native")
    if normalized:
        kind = "native_pointer" if "*" in normalized else "native"
        return EncodingType(value, normalized, kind)
    return EncodingType(value, "unknown", "unknown", supported=False)


def _split_arguments(value: str) -> list[str]:
    result: list[str] = []
    start = 0
    stack: list[str] = []
    quote: str | None = None
    escaped = False
    pairs = {")": "(", "]": "[", "}": "{"}
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
            stack.append(char)
        elif char in ")]}" and stack and stack[-1] == pairs[char]:
            stack.pop()
        elif char == "," and not stack:
            result.append(value[start:index].strip())
            start = index + 1
    result.append(value[start:].strip())
    return result


def _matching_paren(value: str, opening: int) -> int | None:
    end = _balanced_end(value, opening, "(", ")")
    return end - 1 if end <= len(value) and end > opening and value[end - 1] == ")" else None


def _string_literal(value: str) -> str | None:
    match = re.fullmatch(r'\s*"((?:\\.|[^"\\])*)"\s*', value, re.DOTALL)
    if not match:
        return None
    raw = match.group(1)
    try:
        return bytes(raw, "utf-8").decode("unicode_escape")
    except UnicodeDecodeError:
        return None


def _strip_casts(value: str) -> tuple[str, str | None]:
    rendered = value.strip()
    first_cast = None
    cast = re.compile(r"^\(([A-Za-z_$][A-Za-z0-9_$ :<>*]*)\)\s*(.+)$", re.DOTALL)
    while True:
        match = cast.match(rendered)
        if not match:
            return rendered, first_cast
        first_cast = first_cast or match.group(1).strip()
        rendered = match.group(2).strip()


def _symbol_fragment(value: str) -> str:
    rendered = re.sub(r"[^A-Za-z0-9_$]", "_", value)
    rendered = re.sub(r"_+", "_", rendered).strip("_") or "anonymous"
    if rendered[0].isdigit():
        rendered = "n_" + rendered
    return rendered[:180]


class _ClassIndex:
    def __init__(
        self,
        classes: list[dict[str, Any]],
        categories: list[dict[str, Any]],
    ):
        self.classes = {
            (str(item.get("architecture") or "unknown"), str(item["name"])): item
            for item in classes
        }
        self.architectures = sorted({key[0] for key in self.classes})
        self.children: dict[tuple[str, str], set[str]] = defaultdict(set)
        self.protocols: dict[tuple[str, str], set[str]] = defaultdict(set)
        for (architecture, name), item in self.classes.items():
            superclass = item.get("superclass") or {}
            super_name = superclass.get("name") if isinstance(superclass, dict) else superclass
            if super_name:
                self.children[(architecture, str(super_name))].add(name)
            for protocol in item.get("protocols", []):
                protocol_name = protocol.get("name") if isinstance(protocol, dict) else protocol
                if protocol_name:
                    self.protocols[(architecture, name)].add(str(protocol_name))
        for item in categories:
            architecture = str(item.get("architecture") or "unknown")
            target = item.get("target_class") or {}
            class_name = target.get("name") if isinstance(target, dict) else target
            if class_name:
                for protocol in item.get("protocols", []):
                    protocol_name = protocol.get("name") if isinstance(protocol, dict) else protocol
                    if protocol_name:
                        self.protocols[(architecture, str(class_name))].add(str(protocol_name))
        self.symbol_classes: dict[str, list[str]] = defaultdict(list)
        for _, name in self.classes:
            self.symbol_classes[_symbol_fragment(name)].append(name)
        self.symbol_classes = {
            key: sorted(set(values)) for key, values in self.symbol_classes.items()
        }

    def superclass(self, architecture: str, class_name: str) -> str | None:
        item = self.classes.get((architecture, class_name))
        if not item:
            return None
        superclass = item.get("superclass") or {}
        name = superclass.get("name") if isinstance(superclass, dict) else superclass
        return str(name) if name else None

    def descendants(self, architecture: str, class_name: str) -> list[str]:
        result = {class_name}
        pending = [class_name]
        while pending:
            current = pending.pop()
            for child in sorted(self.children.get((architecture, current), set())):
                if child not in result:
                    result.add(child)
                    pending.append(child)
        return sorted(result)

    def conformers(self, architecture: str, protocols: Iterable[str]) -> list[str]:
        required = set(protocols)
        direct = {
            name
            for (candidate_architecture, name), values in self.protocols.items()
            if candidate_architecture == architecture and required.issubset(values)
        }
        result = set(direct)
        for name in direct:
            result.update(self.descendants(architecture, name))
        return sorted(result)

    def classes_for_spec(
        self,
        architecture: str,
        class_name: str | None,
        protocols: Iterable[str],
        *,
        exact_runtime_class: bool = False,
    ) -> tuple[list[str], bool]:
        protocol_names = tuple(sorted(set(protocols)))
        if exact_runtime_class and class_name:
            return [class_name], False
        candidates: set[str] = set()
        dynamic = False
        if protocol_names:
            candidates.update(self.conformers(architecture, protocol_names))
            dynamic = True
        if class_name and (architecture, class_name) in self.classes:
            by_base = set(self.descendants(architecture, class_name))
            candidates = candidates & by_base if candidates else by_base
            dynamic = True
        elif class_name and not candidates:
            candidates.add(class_name)
            dynamic = True
        return sorted(candidates), dynamic


class _FlowGraph:
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
            "method_id": values.pop("method_id", None),
            "entity_id": values.pop("entity_id", None),
            "callsite_id": values.pop("callsite_id", None),
            "name": values.pop("name", None),
            "index": values.pop("index", None),
            "source_path": values.pop("source_path", None),
            "source_address": values.pop("source_address", None),
            "declared_encoding": values.pop("declared_encoding", None),
            "declared_type": values.pop("declared_type", None),
            **values,
        }
        if node_id in self.nodes and self.nodes[node_id] != record:
            raise TypeFlowError(f"Conflicting type-flow value identity: {node_id}")
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
        details = details or {}
        evidence_id = _stable_id(
            "type-evidence",
            kind,
            source,
            source_address,
            confidence,
            basis,
            json.dumps(details, sort_keys=True, ensure_ascii=False),
        )
        record = {
            "id": evidence_id,
            "kind": kind,
            "source": source,
            "source_address": source_address,
            "confidence": confidence,
            "provenance": sorted(set(provenance)),
            "basis": basis,
            "details": details,
        }
        if evidence_id in self.evidence and self.evidence[evidence_id] != record:
            raise TypeFlowError(f"Conflicting type evidence identity: {evidence_id}")
        self.evidence[evidence_id] = record
        return evidence_id

    def add_root(
        self,
        node_id: str,
        atom: TypeAtom,
        evidence_id: str,
        *,
        confidence: str,
        hypothesis: bool,
    ) -> None:
        if node_id not in self.nodes:
            raise TypeFlowError(f"Type root references an unknown value: {node_id}")
        self.roots[node_id].append(
            {
                "atom": atom,
                "evidence_ids": (evidence_id,),
                "confidence": CONFIDENCE_RANK[confidence],
                "hypothesis": hypothesis,
                "path": (),
            }
        )

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
            raise TypeFlowError(f"Propagation edge references an unknown value: {source} -> {target}")
        edge_id = _stable_id(
            "type-step",
            source,
            target,
            kind,
            confidence,
            hypothesis,
            source_path,
            source_address,
            basis,
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
            raise TypeFlowError(f"Conflicting propagation edge identity: {edge_id}")
        if edge_id not in self.edges:
            self.edges[edge_id] = record
            self.outgoing[source].append(edge_id)
        return edge_id

    @staticmethod
    def _better(candidate: dict[str, Any], existing: dict[str, Any] | None) -> bool:
        if existing is None:
            return True
        candidate_key = (
            candidate["confidence"],
            not candidate["hypothesis"],
            -len(candidate["path"]),
            tuple(candidate["evidence_ids"]),
            tuple(candidate["path"]),
        )
        existing_key = (
            existing["confidence"],
            not existing["hypothesis"],
            -len(existing["path"]),
            tuple(existing["evidence_ids"]),
            tuple(existing["path"]),
        )
        return candidate_key > existing_key

    def solve(self) -> tuple[dict[str, dict[TypeAtom, dict[str, Any]]], int]:
        state: dict[str, dict[TypeAtom, dict[str, Any]]] = {
            node_id: {} for node_id in self.nodes
        }
        for node_id in sorted(self.roots):
            for root in sorted(
                self.roots[node_id],
                key=lambda item: (
                    item["atom"],
                    -item["confidence"],
                    item["hypothesis"],
                    item["evidence_ids"],
                ),
            ):
                atom = root["atom"]
                if self._better(root, state[node_id].get(atom)):
                    state[node_id][atom] = root
        maximum = max(1, len(self.nodes) + 1)
        for iteration in range(1, maximum + 1):
            changed = False
            for source in sorted(self.nodes):
                for edge_id in sorted(self.outgoing.get(source, [])):
                    edge = self.edges[edge_id]
                    target = edge["target_value_id"]
                    edge_confidence = CONFIDENCE_RANK[edge["confidence"]]
                    for atom, source_state in sorted(state[source].items()):
                        if edge_id in source_state["path"]:
                            continue
                        candidate = {
                            "atom": atom,
                            "evidence_ids": source_state["evidence_ids"],
                            "confidence": min(source_state["confidence"], edge_confidence),
                            "hypothesis": source_state["hypothesis"] or edge["hypothesis"],
                            "path": (*source_state["path"], edge_id),
                        }
                        if self._better(candidate, state[target].get(atom)):
                            state[target][atom] = candidate
                            changed = True
            if not changed:
                return state, iteration
        raise TypeFlowError("Type propagation did not converge within the deterministic node bound")

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
                self_loop = any(
                    self.edges[edge_id]["target_value_id"] == node
                    for edge_id in self.outgoing.get(node, [])
                )
                if len(component) > 1 or self_loop:
                    components.append(component)

        for node in sorted(self.nodes):
            if node not in indexes:
                visit(node)
        components.sort(key=lambda item: (item[0], len(item)))
        return components


def _add_spec_roots(
    graph: _FlowGraph,
    node_id: str,
    spec: EncodingType,
    class_index: _ClassIndex,
    architecture: str,
    evidence_id: str,
    *,
    confidence: str = "high",
    exact_runtime_class: bool = False,
) -> None:
    if not spec.supported:
        return
    if spec.kind == "objective_c_instance":
        classes, dynamic = class_index.classes_for_spec(
            architecture,
            spec.class_name,
            spec.protocols,
            exact_runtime_class=exact_runtime_class,
        )
        if classes:
            for class_name in classes:
                graph.add_root(
                    node_id,
                    TypeAtom("objective_c_instance", class_name, class_name, spec.protocols),
                    evidence_id,
                    confidence=confidence,
                    hypothesis=dynamic,
                )
        elif spec.protocols:
            graph.add_root(
                node_id,
                TypeAtom(
                    "objective_c_protocol",
                    "id<" + ",".join(spec.protocols) + ">",
                    None,
                    spec.protocols,
                ),
                evidence_id,
                confidence=confidence,
                hypothesis=True,
            )
        return
    atom_kind = spec.kind
    graph.add_root(
        node_id,
        TypeAtom(atom_kind, spec.display, spec.class_name, spec.protocols),
        evidence_id,
        confidence=confidence,
        hypothesis=False,
    )


def _signature(code: str) -> tuple[str, list[tuple[str, str]]] | None:
    opening_body = code.find("{")
    if opening_body < 0:
        return None
    header = re.sub(r"/\*.*?\*/", "", code[:opening_body], flags=re.DOTALL).strip()
    header = re.sub(r"\s*::\s*", "::", header)
    closing = header.rfind(")")
    if closing < 0:
        return None
    depth = 0
    opening = None
    for index in range(closing, -1, -1):
        char = header[index]
        if char == ")":
            depth += 1
        elif char == "(":
            depth -= 1
            if depth == 0:
                opening = index
                break
    if opening is None:
        return None
    prefix = header[:opening].strip()
    name_match = re.search(r"([~A-Za-z_$][A-Za-z0-9_$]*(?:::[~A-Za-z_$][A-Za-z0-9_$]*)*)\s*$", prefix)
    return_type = prefix[:name_match.start()].strip() if name_match else "unknown"
    parameters: list[tuple[str, str]] = []
    for argument in _split_arguments(header[opening + 1:closing]):
        if not argument or argument == "void":
            continue
        name_match = re.search(r"([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:\[[^]]*\])?\s*$", argument)
        if not name_match:
            continue
        parameters.append((name_match.group(1), argument[:name_match.start()].strip()))
    return return_type, parameters


def _local_declarations(code: str) -> list[tuple[str, str]]:
    opening = code.find("{")
    if opening < 0:
        return []
    result: list[tuple[str, str]] = []
    for raw_line in code[opening + 1:].splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("/*") or line.startswith("*") or line.startswith("//"):
            continue
        if not line.endswith(";") or "=" in line:
            break
        match = re.fullmatch(
            r"(.+?\S)\s+(\*+\s*)?([A-Za-z_$][A-Za-z0-9_$]*)"
            r"\s*(?:\[[^]]*\])?\s*;",
            line,
        )
        if not match:
            break
        pointer = (match.group(2) or "").strip()
        type_name = " ".join(
            part for part in (match.group(1).strip(), pointer) if part
        )
        variable = match.group(3)
        if type_name in {"return", "goto"}:
            break
        result.append((variable, type_name))
    return result


def _assignments(code: str) -> list[tuple[str, str]]:
    pattern = re.compile(
        r"(?ms)^\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?![=])(.*?);\s*(?=\r?$)"
    )
    return [(match.group(1), match.group(2).strip()) for match in pattern.finditer(code)]


def _message_calls(code: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
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
        statement_start = max(
            code.rfind(";", 0, match.start()),
            code.rfind("{", 0, match.start()),
            code.rfind("}", 0, match.start()),
        ) + 1
        prefix = code[statement_start:match.start()]
        lhs_match = re.search(r"(?:^|\n)\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*$", prefix)
        result.append(
            {
                "start": match.start(),
                "callee": match.group("callee"),
                "family": "super" if "super" in match.group("callee").lower() else "normal",
                "selector": selector,
                "receiver_expression": arguments[0].strip(),
                "arguments": arguments[2:],
                "lhs": lhs_match.group(1) if lhs_match else None,
            }
        )
    return result


def _architecture_for_function(
    recovered_function: dict[str, Any],
    methods_by_id: dict[str, dict[str, Any]],
    architectures: list[str],
) -> str:
    values = {
        str(methods_by_id[method_id].get("architecture"))
        for method_id in recovered_function.get("method_ids", [])
        if method_id in methods_by_id and methods_by_id[method_id].get("architecture")
    }
    if len(values) == 1:
        return next(iter(values))
    if not values and len(architectures) == 1:
        return architectures[0]
    return "unknown"


def _value_sort_key(item: dict[str, Any]) -> tuple[str, str, tuple[int, str], str, int, str]:
    return (
        str(item.get("architecture") or "unknown"),
        str(item.get("function_id") or ""),
        _address_key(_address(item.get("source_address"))),
        str(item.get("kind") or ""),
        int(item.get("index") if item.get("index") is not None else -1),
        str(item["id"]),
    )


def _state_record(
    atom: TypeAtom,
    state: dict[str, Any],
) -> dict[str, Any]:
    return {
        "kind": atom.kind,
        "name": atom.name,
        "class_name": atom.class_name,
        "protocols": list(atom.protocols),
        "confidence": RANK_CONFIDENCE[state["confidence"]],
        "hypothesis": bool(state["hypothesis"]),
        "evidence_ids": list(state["evidence_ids"]),
        "propagation_step_ids": list(state["path"]),
    }


def _classification(types: list[dict[str, Any]]) -> tuple[str, str, list[str]]:
    if not types:
        return "unresolved", "low", ["no_supported_type_evidence_reaches_value"]
    hypothetical = any(item["hypothesis"] for item in types)
    confidence = min((CONFIDENCE_RANK[item["confidence"]] for item in types), default=1)
    reasons: list[str] = []
    if len(types) > 1:
        reasons.append("multiple_types_reach_value")
    if hypothetical:
        reasons.append("type_depends_on_candidate_or_convention_evidence")
    classification = "candidate_set" if len(types) > 1 or hypothetical else "exact"
    return classification, RANK_CONFIDENCE[confidence], reasons


def infer_objc_types(workspace: Path) -> TypeFlowResult:
    """Build and solve the workspace's deterministic static type-flow graph."""
    try:
        workspace = workspace.resolve(strict=True)
    except OSError as exc:
        raise TypeFlowError(f"Analysis workspace does not exist: {workspace}") from exc
    if not workspace.is_dir():
        raise TypeFlowError(f"Analysis workspace is not a directory: {workspace}")

    reports = {name: _load_report(workspace, name) for name in REQUIRED_REPORTS}
    function_facts = reports["functions"]["facts"]
    raw_functions = list(function_facts.get("functions", []))
    if len(raw_functions) != function_facts.get("discovered_function_count"):
        raise TypeFlowError("functions.json count does not match its function inventory")
    recovered = reports["recovered-code-index"]["facts"]
    recovered_functions = list(recovered.get("functions", []))
    methods = list(recovered.get("methods", []))
    classes = list(recovered.get("classes", []))
    categories = list(recovered.get("categories", []))
    if len(recovered_functions) != recovered.get("function_count"):
        raise TypeFlowError("recovered-code-index.json function count does not match its inventory")
    if len(methods) != recovered.get("objective_c_method_count"):
        raise TypeFlowError("recovered-code-index.json method count does not match its inventory")
    dispatch_report = reports["objc-dispatch"]
    dispatch_callsites = list(dispatch_report["facts"].get("callsites", []))
    if len(dispatch_callsites) != dispatch_report["facts"].get("dispatch_callsite_count"):
        raise TypeFlowError("objc-dispatch.json count does not match its callsite inventory")

    graph = _FlowGraph()
    class_index = _ClassIndex(classes, categories)
    methods_by_id = {str(item["id"]): item for item in methods}
    raw_function_by_id = {str(item["id"]): item for item in raw_functions}
    recovered_function_by_id = {
        str(item["function_id"]): item for item in recovered_functions
    }
    if len(raw_function_by_id) != len(raw_functions):
        raise TypeFlowError("functions.json contains duplicate function IDs")
    if len(recovered_function_by_id) != len(recovered_functions):
        raise TypeFlowError("recovered-code-index.json contains duplicate function IDs")
    if len(methods_by_id) != len(methods):
        raise TypeFlowError("recovered-code-index.json contains duplicate method IDs")

    method_return_ids: dict[str, str] = {}
    method_parameter_ids: dict[tuple[str, int], str] = {}
    for method in sorted(methods, key=lambda item: str(item["id"])):
        method_id = str(method["id"])
        architecture = str(method.get("architecture") or "unknown")
        encoding = str(method.get("type_encoding") or "")
        parsed = _method_encoding(encoding)
        return_spec = parsed[0] if parsed else EncodingType("", "unknown", "unknown", supported=False)
        return_id = _stable_id("type-value", "method-return", method_id)
        method_return_ids[method_id] = graph.add_node(
            return_id,
            kind="method_return",
            architecture=architecture,
            function_id=method.get("function_id"),
            method_id=method_id,
            entity_id=method.get("entity_id"),
            name="return",
            index=0,
            source_path="analysis/recovered-code-index.json",
            source_address=_address(method.get("metadata_address")),
            declared_encoding=return_spec.raw or None,
            declared_type=return_spec.display,
        )
        evidence_id = graph.add_evidence(
            "objective_c_method_return_encoding",
            "analysis/recovered-code-index.json",
            source_address=_address(method.get("metadata_address")),
            confidence="high",
            provenance=["objective_c_metadata"],
            basis="Objective-C runtime method encoding declares the return type",
            details={"method_id": method_id, "encoding": encoding, "type": return_spec.display},
        )
        _add_spec_roots(graph, return_id, return_spec, class_index, architecture, evidence_id)

        parameters = parsed[1:] if parsed else []
        for index, spec in enumerate(parameters):
            parameter_id = _stable_id("type-value", "method-parameter", method_id, index)
            method_parameter_ids[(method_id, index)] = graph.add_node(
                parameter_id,
                kind="method_parameter",
                architecture=architecture,
                function_id=method.get("function_id"),
                method_id=method_id,
                entity_id=method.get("entity_id"),
                name="self" if index == 0 else ("_cmd" if index == 1 else f"arg{index - 1}"),
                index=index,
                source_path="analysis/recovered-code-index.json",
                source_address=_address(method.get("metadata_address")),
                declared_encoding=spec.raw,
                declared_type=spec.display,
            )
            self_kind = None
            if index == 0 and method.get("class_name"):
                self_kind = "objective_c_class" if method.get("kind") == "class" else "objective_c_instance"
                self_spec = EncodingType(
                    spec.raw,
                    str(method["class_name"]),
                    self_kind,
                    str(method["class_name"]),
                )
                evidence_kind = "objective_c_self_context"
                basis = "Exact Objective-C method metadata declares the static self class"
            else:
                self_spec = spec
                evidence_kind = "objective_c_method_parameter_encoding"
                basis = "Objective-C runtime method encoding declares the parameter type"
            evidence_id = graph.add_evidence(
                evidence_kind,
                "analysis/recovered-code-index.json",
                source_address=_address(method.get("metadata_address")),
                confidence="high",
                provenance=["objective_c_metadata"],
                basis=basis,
                details={
                    "method_id": method_id,
                    "parameter_index": index,
                    "encoding": encoding,
                    "type": self_spec.display,
                },
            )
            if index == 0 and self_kind == "objective_c_class":
                candidates, dynamic = class_index.classes_for_spec(
                    architecture,
                    self_spec.class_name,
                    self_spec.protocols,
                )
                for class_name in candidates:
                    graph.add_root(
                        parameter_id,
                        TypeAtom("objective_c_class", class_name, class_name),
                        evidence_id,
                        confidence="high",
                        hypothesis=dynamic,
                    )
            else:
                _add_spec_roots(
                    graph,
                    parameter_id,
                    self_spec,
                    class_index,
                    architecture,
                    evidence_id,
                )

    ivar_value_ids: dict[tuple[str, str, str], str] = {}
    ivar_symbols: dict[str, list[str]] = defaultdict(list)
    for objc_class in sorted(classes, key=lambda item: (
        str(item.get("architecture") or "unknown"),
        str(item["name"]).casefold(),
        str(item.get("id") or ""),
    )):
        architecture = str(objc_class.get("architecture") or "unknown")
        class_name = str(objc_class["name"])
        for ivar in sorted(objc_class.get("ivars", []), key=lambda item: (
            item.get("offset") is None,
            int(item.get("offset") or 0),
            str(item.get("name") or ""),
        )):
            name = str(ivar.get("name") or "unknown")
            encoding = str(ivar.get("type_encoding") or "")
            spec, _ = _parse_encoding_token(encoding)
            node_id = _stable_id("type-value", "ivar", architecture, class_name, name, ivar.get("metadata_address"))
            graph.add_node(
                node_id,
                kind="ivar",
                architecture=architecture,
                entity_id=objc_class.get("id"),
                name=name,
                source_path="analysis/recovered-code-index.json",
                source_address=_address(ivar.get("metadata_address")),
                declared_encoding=encoding or None,
                declared_type=spec.display,
                owner_class=class_name,
                ivar_offset=ivar.get("offset"),
            )
            ivar_value_ids[(architecture, class_name, name)] = node_id
            symbol = f"{_symbol_fragment(class_name)}::{_symbol_fragment(name)}"
            ivar_symbols[symbol].append(node_id)
            evidence_id = graph.add_evidence(
                "objective_c_ivar_encoding",
                "analysis/recovered-code-index.json",
                source_address=_address(ivar.get("metadata_address")),
                confidence="high",
                provenance=["objective_c_metadata"],
                basis="Objective-C ivar metadata declares the storage type and offset",
                details={
                    "class_name": class_name,
                    "ivar_name": name,
                    "offset": ivar.get("offset"),
                    "encoding": encoding,
                },
            )
            _add_spec_roots(graph, node_id, spec, class_index, architecture, evidence_id)

    for objc_class in sorted(classes, key=lambda item: (
        str(item.get("architecture") or "unknown"),
        str(item["name"]).casefold(),
        str(item.get("id") or ""),
    )):
        architecture = str(objc_class.get("architecture") or "unknown")
        class_name = str(objc_class["name"])
        for prop in sorted(objc_class.get("properties", []), key=lambda item: str(item.get("name") or "")):
            name = str(prop.get("name") or "unknown")
            attributes = str(prop.get("attributes") or "")
            encoding = _property_encoding(attributes)
            spec, _ = _parse_encoding_token(encoding or "")
            node_id = _stable_id(
                "type-value",
                "property",
                architecture,
                class_name,
                name,
                prop.get("metadata_address"),
            )
            graph.add_node(
                node_id,
                kind="property",
                architecture=architecture,
                entity_id=objc_class.get("id"),
                name=name,
                source_path="analysis/recovered-code-index.json",
                source_address=_address(prop.get("metadata_address")),
                declared_encoding=encoding,
                declared_type=spec.display,
                owner_class=class_name,
                property_attributes=attributes,
            )
            evidence_id = graph.add_evidence(
                "objective_c_property_encoding",
                "analysis/recovered-code-index.json",
                source_address=_address(prop.get("metadata_address")),
                confidence="high",
                provenance=["objective_c_metadata"],
                basis="Objective-C property attributes declare the property type",
                details={
                    "class_name": class_name,
                    "property_name": name,
                    "attributes": attributes,
                },
            )
            _add_spec_roots(graph, node_id, spec, class_index, architecture, evidence_id)

    pseudocode_artifacts: dict[str, dict[str, Any]] = {}
    function_values: dict[str, dict[str, str]] = {}
    function_return_ids: dict[str, str] = {}
    ivar_accesses_by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for function_id in sorted(recovered_function_by_id):
        recovered_function = recovered_function_by_id[function_id]
        raw_function = raw_function_by_id.get(function_id)
        if raw_function is None:
            raise TypeFlowError(f"Recovered function is absent from functions.json: {function_id}")
        architecture = _architecture_for_function(
            recovered_function,
            methods_by_id,
            class_index.architectures,
        )
        return_id = _stable_id("type-value", "function-return", function_id)
        function_return_ids[function_id] = graph.add_node(
            return_id,
            kind="function_return",
            architecture=architecture,
            function_id=function_id,
            name="return",
            index=0,
            source_path=(recovered_function.get("decompilation") or {}).get("output_path"),
            source_address=_address(raw_function.get("address")),
        )
        for method_id in recovered_function.get("method_ids", []):
            if method_id in method_return_ids:
                graph.add_edge(
                    method_return_ids[method_id],
                    return_id,
                    "method_declaration_to_function_return",
                    confidence="high",
                    hypothesis=False,
                    basis="Recovered method identity maps exactly to this function",
                    source_path="analysis/recovered-code-index.json",
                    source_address=_address(raw_function.get("address")),
                )
                graph.add_edge(
                    return_id,
                    method_return_ids[method_id],
                    "function_return_to_method_result",
                    confidence="high",
                    hypothesis=False,
                    basis="The mapped function body supplies the Objective-C method result",
                    source_path="analysis/recovered-code-index.json",
                    source_address=_address(raw_function.get("address")),
                )

        for reference in raw_function.get("cross_references", []):
            symbol = str(reference.get("target_symbol") or "")
            candidates = sorted(set(ivar_symbols.get(symbol, [])))
            from_address = _address(reference.get("from_address"))
            if len(candidates) != 1 or not from_address:
                continue
            ivar_id = candidates[0]
            access_id = _stable_id("type-value", "ivar-access", function_id, from_address, ivar_id)
            ivar_node = graph.nodes[ivar_id]
            graph.add_node(
                access_id,
                kind="ivar_access",
                architecture=architecture,
                function_id=function_id,
                entity_id=ivar_node.get("entity_id"),
                name=ivar_node.get("name"),
                source_path="analysis/functions.json",
                source_address=from_address,
                declared_encoding=ivar_node.get("declared_encoding"),
                declared_type=ivar_node.get("declared_type"),
                owner_class=ivar_node.get("owner_class"),
                ivar_value_id=ivar_id,
            )
            graph.add_edge(
                ivar_id,
                access_id,
                "ivar_metadata_to_machine_access",
                confidence="high",
                hypothesis=False,
                basis="Ghidra cross-reference names this exact class ivar at the machine instruction",
                source_path="analysis/functions.json",
                source_address=from_address,
            )
            ivar_accesses_by_function[function_id].append(
                {"id": access_id, "address": from_address}
            )

        decompilation = recovered_function.get("decompilation") or {}
        if decompilation.get("status") != "success" or not decompilation.get("output_path"):
            function_values[function_id] = {}
            continue
        relative = str(decompilation["output_path"]).replace("\\", "/")
        path = _relative_file(workspace, relative)
        if not path.is_file():
            raise TypeFlowError(f"Successful decompilation file is missing: {relative}")
        try:
            code = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise TypeFlowError(f"Cannot read decompiled code {path}: {exc}") from exc
        pseudocode_artifacts[relative] = {"path": relative, "sha256": sha256_file(path)}
        signature = _signature(code)
        variables: dict[str, str] = {}
        if signature:
            return_type, parameters = signature
            return_spec = _c_type(return_type)
            graph.nodes[return_id]["declared_type"] = return_spec.display
            evidence_id = graph.add_evidence(
                "ghidra_function_return_type",
                relative,
                source_address=_address(raw_function.get("address")),
                confidence="medium",
                provenance=["ghidra_pseudocode"],
                basis="Ghidra pseudocode declares the function return type",
                details={"function_id": function_id, "type": return_type},
            )
            _add_spec_roots(
                graph,
                return_id,
                return_spec,
                class_index,
                architecture,
                evidence_id,
                confidence="medium",
            )
            for index, (name, type_name) in enumerate(parameters):
                parameter_id = _stable_id("type-value", "function-parameter", function_id, index)
                variables[name] = graph.add_node(
                    parameter_id,
                    kind="function_parameter",
                    architecture=architecture,
                    function_id=function_id,
                    name=name,
                    index=index,
                    source_path=relative,
                    source_address=_address(raw_function.get("address")),
                    declared_type=type_name,
                )
                spec = _c_type(type_name)
                evidence_id = graph.add_evidence(
                    "ghidra_parameter_declaration",
                    relative,
                    source_address=_address(raw_function.get("address")),
                    confidence="medium",
                    provenance=["ghidra_pseudocode"],
                    basis="Ghidra pseudocode declares the function parameter type",
                    details={"function_id": function_id, "parameter_index": index, "type": type_name},
                )
                if spec.kind == "native_pointer":
                    base = re.sub(r"\s*\*+\s*$", "", spec.display)
                    class_names = class_index.symbol_classes.get(base, [])
                    if len(class_names) == 1:
                        spec = EncodingType(type_name, class_names[0], "objective_c_instance", class_names[0])
                _add_spec_roots(
                    graph,
                    parameter_id,
                    spec,
                    class_index,
                    architecture,
                    evidence_id,
                    confidence="medium",
                )
                for method_id in recovered_function.get("method_ids", []):
                    method_parameter_id = method_parameter_ids.get((method_id, index))
                    if method_parameter_id:
                        graph.add_edge(
                            method_parameter_id,
                            parameter_id,
                            "method_parameter_to_function_parameter",
                            confidence="high",
                            hypothesis=False,
                            basis="Exact recovered method identity aligns ABI parameter positions",
                            source_path="analysis/recovered-code-index.json",
                            source_address=_address(raw_function.get("address")),
                        )

        for name, type_name in _local_declarations(code):
            local_id = _stable_id("type-value", "local", function_id, name)
            variables[name] = graph.add_node(
                local_id,
                kind="local",
                architecture=architecture,
                function_id=function_id,
                name=name,
                source_path=relative,
                source_address=None,
                declared_type=type_name,
            )
            spec = _c_type(type_name)
            evidence_id = graph.add_evidence(
                "ghidra_local_declaration",
                relative,
                source_address=None,
                confidence="medium",
                provenance=["ghidra_pseudocode"],
                basis="Ghidra pseudocode declares the local storage type; no machine token address is exported",
                details={"function_id": function_id, "local": name, "type": type_name},
            )
            if spec.kind == "native_pointer":
                base = re.sub(r"\s*\*+\s*$", "", spec.display)
                class_names = class_index.symbol_classes.get(base, [])
                if len(class_names) == 1:
                    spec = EncodingType(type_name, class_names[0], "objective_c_instance", class_names[0])
            _add_spec_roots(
                graph,
                local_id,
                spec,
                class_index,
                architecture,
                evidence_id,
                confidence="medium",
            )
        function_values[function_id] = variables

        for lhs, rhs in _assignments(code):
            target = variables.get(lhs)
            if not target:
                continue
            rendered, cast_type = _strip_casts(rhs)
            if rendered in variables:
                graph.add_edge(
                    variables[rendered],
                    target,
                    "pseudocode_assignment",
                    confidence="high",
                    hypothesis=False,
                    basis="Ghidra pseudocode contains a direct value assignment",
                    source_path=relative,
                )
            if cast_type:
                cast_spec = _c_type(cast_type)
                if cast_spec.kind == "native_pointer":
                    base = re.sub(r"\s*\*+\s*$", "", cast_spec.display)
                    class_names = class_index.symbol_classes.get(base, [])
                    if len(class_names) == 1:
                        cast_spec = EncodingType(cast_type, class_names[0], "objective_c_instance", class_names[0])
                evidence_id = graph.add_evidence(
                    "ghidra_explicit_cast",
                    relative,
                    source_address=None,
                    confidence="medium",
                    provenance=["ghidra_pseudocode"],
                    basis="An explicit pseudocode cast supports only a static candidate type, not the runtime class",
                    details={"function_id": function_id, "target": lhs, "cast": cast_type},
                )
                _add_spec_roots(
                    graph,
                    target,
                    cast_spec,
                    class_index,
                    architecture,
                    evidence_id,
                    confidence="medium",
                )
        for match in re.finditer(r"(?m)^\s*return\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*;", code):
            source = variables.get(match.group(1))
            if source:
                graph.add_edge(
                    source,
                    return_id,
                    "pseudocode_return",
                    confidence="high",
                    hypothesis=False,
                    basis="Ghidra pseudocode returns this exact local or parameter value",
                    source_path=relative,
                )

    callsites_by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
    callsite_by_id: dict[str, dict[str, Any]] = {}
    receiver_value_ids: dict[str, str] = {}
    message_result_ids: dict[str, str] = {}
    for callsite in dispatch_callsites:
        callsite_id = str(callsite["id"])
        callsite_by_id[callsite_id] = callsite
        function_id = str(callsite["caller"]["function_id"])
        architecture = str(callsite.get("architecture") or "unknown")
        receiver_id = _stable_id("type-value", "message-receiver", callsite_id)
        result_id = _stable_id("type-value", "message-result", callsite_id)
        receiver_value_ids[callsite_id] = graph.add_node(
            receiver_id,
            kind="message_receiver",
            architecture=architecture,
            function_id=function_id,
            callsite_id=callsite_id,
            name="receiver",
            source_path="analysis/objc-dispatch.json",
            source_address=_address(callsite.get("call_site")),
        )
        message_result_ids[callsite_id] = graph.add_node(
            result_id,
            kind="message_result",
            architecture=architecture,
            function_id=function_id,
            callsite_id=callsite_id,
            name="result",
            source_path="analysis/objc-dispatch.json",
            source_address=_address(callsite.get("call_site")),
        )
        baseline_receiver = callsite.get("receiver") or {}
        receiver_kind = str(baseline_receiver.get("receiver_kind") or "unknown")
        class_candidates = sorted(set(baseline_receiver.get("class_candidates", [])))
        if receiver_kind == "super":
            caller_methods = [
                methods_by_id[method_id]
                for method_id in callsite["caller"].get("objective_c_method_ids", [])
                if method_id in methods_by_id
            ]
            contexts = sorted({
                (
                    str(method.get("architecture") or architecture),
                    str(method.get("class_name")),
                    str(method.get("kind")),
                )
                for method in caller_methods
                if method.get("class_name") and method.get("kind")
            })
            if len(contexts) == 1:
                context_architecture, current_class, method_kind = contexts[0]
                superclass = class_index.superclass(context_architecture, current_class)
                if superclass:
                    evidence_id = graph.add_evidence(
                        "objective_c_superclass_context",
                        "analysis/objc-dispatch.json",
                        source_address=_address(callsite.get("call_site")),
                        confidence="high",
                        provenance=["objective_c_metadata", "objective_c_runtime_abi"],
                        basis="Super dispatch begins lookup at the recovered superclass",
                        details={
                            "callsite_id": callsite_id,
                            "current_class": current_class,
                            "superclass": superclass,
                            "method_kind": method_kind,
                        },
                    )
                    atom_kind = "objective_c_class" if method_kind == "class" else "objective_c_instance"
                    graph.add_root(
                        receiver_id,
                        TypeAtom(atom_kind, superclass, superclass),
                        evidence_id,
                        confidence="high",
                        hypothesis=False,
                    )
        elif receiver_kind == "class_object" and len(class_candidates) == 1:
            evidence_id = graph.add_evidence(
                "explicit_objective_c_class_receiver",
                "analysis/objc-dispatch.json",
                source_address=_address(callsite.get("call_site")),
                confidence="high",
                provenance=["ghidra_pseudocode", "objective_c_metadata"],
                basis="Baseline dispatch proved one explicit Objective-C class-object receiver",
                details={"callsite_id": callsite_id, "class_name": class_candidates[0]},
            )
            graph.add_root(
                receiver_id,
                TypeAtom("objective_c_class", class_candidates[0], class_candidates[0]),
                evidence_id,
                confidence="high",
                hypothesis=False,
            )
        elif class_candidates:
            baseline_evidence = baseline_receiver.get("evidence") or [{}]
            evidence_id = graph.add_evidence(
                "baseline_receiver_candidates",
                "analysis/objc-dispatch.json",
                source_address=_address(callsite.get("call_site")),
                confidence="medium",
                provenance=baseline_evidence[0].get("provenance", ["ghidra"]),
                basis="Baseline dispatch retained these receiver classes without exact runtime proof",
                details={
                    "callsite_id": callsite_id,
                    "receiver_kind": receiver_kind,
                    "class_candidates": class_candidates,
                },
            )
            atom_kind = "objective_c_class" if receiver_kind == "class_object" else "objective_c_instance"
            for class_name in class_candidates:
                graph.add_root(
                    receiver_id,
                    TypeAtom(atom_kind, class_name, class_name),
                    evidence_id,
                    confidence="medium",
                    hypothesis=True,
                )

        for target in callsite.get("possible_targets", []):
            method_id = str(target.get("method_id") or "")
            method_return_id = method_return_ids.get(method_id)
            if not method_return_id:
                continue
            exact = callsite.get("classification") == "resolved"
            graph.add_edge(
                method_return_id,
                result_id,
                "dispatch_target_return",
                confidence="high" if exact else "medium",
                hypothesis=not exact,
                basis=(
                    "Exact baseline dispatch target supplies the message result type"
                    if exact
                    else "Each baseline dispatch candidate may supply the message result type"
                ),
                source_path="analysis/objc-dispatch.json",
                source_address=_address(callsite.get("call_site")),
            )
        callsites_by_function[function_id].append(callsite)

    for function_id in sorted(callsites_by_function):
        recovered_function = recovered_function_by_id[function_id]
        decompilation = recovered_function.get("decompilation") or {}
        if decompilation.get("status") != "success" or not decompilation.get("output_path"):
            continue
        relative = str(decompilation["output_path"]).replace("\\", "/")
        path = _relative_file(workspace, relative)
        code = path.read_text(encoding="utf-8", errors="replace")
        parsed = _message_calls(code)
        parsed_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for item in parsed:
            parsed_groups[(item["family"], item["selector"])].append(item)
        callsite_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for callsite in callsites_by_function[function_id]:
            selector = callsite.get("selector") or {}
            if selector.get("status") != "resolved" or not selector.get("value"):
                continue
            family = "super" if callsite["direct_runtime_edge"].get("super_dispatch") else "normal"
            callsite_groups[(family, str(selector["value"]))].append(callsite)
        variables = function_values.get(function_id, {})
        sorted_callsites = sorted(callsites_by_function[function_id], key=lambda item: _address_key(_address(item["call_site"])))
        boundaries: dict[str, tuple[int, int]] = {}
        previous = int(_address(raw_function_by_id[function_id].get("address")) or "0x0", 16) - 1
        for callsite in sorted_callsites:
            current = int(str(callsite["call_site"]), 16)
            boundaries[str(callsite["id"])] = (previous, current)
            previous = current

        for key in sorted(set(parsed_groups) & set(callsite_groups)):
            pseudo_items = parsed_groups[key]
            baseline_items = callsite_groups[key]
            if len(pseudo_items) != 1 or len(baseline_items) != 1:
                continue
            pseudo = pseudo_items[0]
            callsite = baseline_items[0]
            callsite_id = str(callsite["id"])
            receiver_id = receiver_value_ids[callsite_id]
            result_id = message_result_ids[callsite_id]
            receiver_expression, cast_type = _strip_casts(pseudo["receiver_expression"])
            receiver_source = variables.get(receiver_expression)
            if receiver_source:
                graph.add_edge(
                    receiver_source,
                    receiver_id,
                    "pseudocode_message_receiver",
                    confidence="high",
                    hypothesis=False,
                    basis="One pseudocode message and one addressed callsite share this selector and receiver variable",
                    source_path=relative,
                    source_address=_address(callsite.get("call_site")),
                )
            elif "param_1 +" in receiver_expression or receiver_expression.startswith("*"):
                lower, upper = boundaries[callsite_id]
                accesses = [
                    item
                    for item in ivar_accesses_by_function.get(function_id, [])
                    if lower < int(item["address"], 16) <= upper
                ]
                if len(accesses) == 1:
                    graph.add_edge(
                        accesses[0]["id"],
                        receiver_id,
                        "ivar_access_to_message_receiver",
                        confidence="medium",
                        hypothesis=True,
                        basis="The receiver is a memory expression and one exact ivar cross-reference occupies its bounded callsite window",
                        source_path=relative,
                        source_address=_address(callsite.get("call_site")),
                    )
            if cast_type:
                cast_spec = _c_type(cast_type)
                if cast_spec.kind == "native_pointer":
                    base = re.sub(r"\s*\*+\s*$", "", cast_spec.display)
                    names = class_index.symbol_classes.get(base, [])
                    if len(names) == 1:
                        cast_spec = EncodingType(cast_type, names[0], "objective_c_instance", names[0])
                evidence_id = graph.add_evidence(
                    "message_receiver_cast",
                    relative,
                    source_address=_address(callsite.get("call_site")),
                    confidence="medium",
                    provenance=["ghidra_pseudocode"],
                    basis="An explicit receiver cast supplies a static candidate but not an exact runtime class",
                    details={"callsite_id": callsite_id, "cast": cast_type},
                )
                _add_spec_roots(
                    graph,
                    receiver_id,
                    cast_spec,
                    class_index,
                    str(callsite.get("architecture") or "unknown"),
                    evidence_id,
                    confidence="medium",
                )

            if pseudo.get("lhs") in variables:
                graph.add_edge(
                    result_id,
                    variables[pseudo["lhs"]],
                    "message_result_assignment",
                    confidence="high",
                    hypothesis=False,
                    basis="The unique pseudocode message result is assigned to this local",
                    source_path=relative,
                    source_address=_address(callsite.get("call_site")),
                )
            selector = str(callsite["selector"]["value"])
            baseline_receiver = callsite.get("receiver") or {}
            if (
                selector == "alloc"
                and baseline_receiver.get("receiver_kind") == "class_object"
                and len(baseline_receiver.get("class_candidates", [])) == 1
            ):
                class_name = str(baseline_receiver["class_candidates"][0])
                evidence_id = graph.add_evidence(
                    "explicit_class_alloc_result",
                    relative,
                    source_address=_address(callsite.get("call_site")),
                    confidence="high",
                    provenance=["ghidra_pseudocode", "objective_c_runtime_abi", "objective_c_metadata"],
                    basis="An explicit class-object receiver proves the runtime class allocated by objc_msgSend alloc",
                    details={"callsite_id": callsite_id, "class_name": class_name},
                )
                graph.add_root(
                    result_id,
                    TypeAtom("objective_c_instance", class_name, class_name),
                    evidence_id,
                    confidence="high",
                    hypothesis=False,
                )
            elif (
                _selector_has_method_family(selector, "new")
                and baseline_receiver.get("receiver_kind") == "class_object"
                and len(baseline_receiver.get("class_candidates", [])) == 1
            ):
                class_name = str(baseline_receiver["class_candidates"][0])
                evidence_id = graph.add_evidence(
                    "objective_c_class_factory_convention",
                    relative,
                    source_address=_address(callsite.get("call_site")),
                    confidence="medium",
                    provenance=[
                        "ghidra_pseudocode",
                        "objective_c_runtime_abi",
                        "objective_c_metadata",
                    ],
                    basis=(
                        "An explicit class-object receiver and Objective-C new-family "
                        "selector support a factory-result candidate; overrides may "
                        "return a different runtime class"
                    ),
                    details={"callsite_id": callsite_id, "class_name": class_name},
                )
                graph.add_root(
                    result_id,
                    TypeAtom("objective_c_instance", class_name, class_name),
                    evidence_id,
                    confidence="medium",
                    hypothesis=True,
                )
            elif _selector_has_method_family(selector, "init"):
                graph.add_edge(
                    receiver_id,
                    result_id,
                    "objective_c_init_convention",
                    confidence="medium",
                    hypothesis=True,
                    basis="The Objective-C init-family convention suggests the result preserves the receiver class; this is not treated as exact proof",
                    source_path=relative,
                    source_address=_address(callsite.get("call_site")),
                )

            for argument_index, expression in enumerate(pseudo.get("arguments", []), start=2):
                rendered, _ = _strip_casts(expression)
                argument_source = variables.get(rendered)
                if not argument_source:
                    continue
                for target in callsite.get("possible_targets", []):
                    method_id = str(target.get("method_id") or "")
                    parameter_id = method_parameter_ids.get((method_id, argument_index))
                    if not parameter_id:
                        continue
                    exact = callsite.get("classification") == "resolved"
                    graph.add_edge(
                        argument_source,
                        parameter_id,
                        "message_argument_to_method_parameter",
                        confidence="high" if exact else "medium",
                        hypothesis=not exact,
                        basis=(
                            "Exact dispatch target aligns this message argument with the method parameter"
                            if exact
                            else "Candidate dispatch target may receive this message argument"
                        ),
                        source_path=relative,
                        source_address=_address(callsite.get("call_site")),
                    )

    state, iteration_count = graph.solve()
    cyclic_components = graph.cyclic_components()
    values: list[dict[str, Any]] = []
    for node_id, node in graph.nodes.items():
        types = [
            _state_record(atom, atom_state)
            for atom, atom_state in sorted(state[node_id].items())
        ]
        classification, confidence, failure_reasons = _classification(types)
        evidence_ids = sorted({
            evidence_id for item in types for evidence_id in item["evidence_ids"]
        })
        propagation_ids = sorted({
            edge_id for item in types for edge_id in item["propagation_step_ids"]
        })
        provenance = sorted({
            value
            for evidence_id in evidence_ids
            for value in graph.evidence[evidence_id]["provenance"]
        })
        values.append(
            {
                **node,
                "classification": classification,
                "type_candidates": types,
                "confidence": confidence,
                "evidence_ids": evidence_ids,
                "propagation_step_ids": propagation_ids,
                "provenance": provenance,
                "failure_reasons": failure_reasons,
            }
        )
    values.sort(key=_value_sort_key)
    value_by_id = {item["id"]: item for item in values}

    dispatch_refinements: list[dict[str, Any]] = []
    for callsite_id in sorted(receiver_value_ids):
        value = value_by_id[receiver_value_ids[callsite_id]]
        callsite = callsite_by_id[callsite_id]
        class_types = [
            item
            for item in value["type_candidates"]
            if item["kind"] in {"objective_c_instance", "objective_c_class"}
            and item.get("class_name")
        ]
        class_names = sorted({str(item["class_name"]) for item in class_types})
        if not class_names:
            continue
        receiver_kinds = {item["kind"] for item in class_types}
        refined_receiver_kind = (
            "class_object"
            if receiver_kinds == {"objective_c_class"}
            else ("typed_instance" if receiver_kinds == {"objective_c_instance"} else "unknown")
        )
        hypothetical = any(item["hypothesis"] for item in class_types)
        confidence_rank = min(CONFIDENCE_RANK[item["confidence"]] for item in class_types)
        classification = (
            "exact"
            if len(class_names) == 1 and not hypothetical and confidence_rank == CONFIDENCE_RANK["high"]
            else "candidate_set"
        )
        baseline = callsite.get("receiver") or {}
        baseline_classes = sorted(set(baseline.get("class_candidates", [])))
        failure_reasons = []
        if classification == "candidate_set":
            failure_reasons.append("type_flow_does_not_prove_one_exact_runtime_class")
        changed = baseline_classes != class_names or baseline.get("status") == "unresolved"
        dispatch_refinements.append(
            {
                "callsite_id": callsite_id,
                "call_site": callsite.get("call_site"),
                "caller_function_id": callsite["caller"].get("function_id"),
                "receiver_value_id": value["id"],
                "baseline_receiver_status": baseline.get("status"),
                "baseline_receiver_kind": baseline.get("receiver_kind"),
                "baseline_class_candidates": baseline_classes,
                "receiver_kind": refined_receiver_kind,
                "classification": classification,
                "class_candidates": class_names,
                "confidence": RANK_CONFIDENCE[confidence_rank],
                "evidence_ids": value["evidence_ids"],
                "propagation_step_ids": value["propagation_step_ids"],
                "failure_reasons": failure_reasons,
                "changed": changed,
            }
        )
    dispatch_refinements.sort(
        key=lambda item: (
            str(item["caller_function_id"]),
            _address_key(_address(item["call_site"])),
            item["callsite_id"],
        )
    )

    classifications = Counter(item["classification"] for item in values)
    kinds = Counter(item["kind"] for item in values)
    unresolved_reasons = Counter(
        reason for item in values for reason in item["failure_reasons"]
    )
    baseline_projection = dispatch_baseline_projection(dispatch_report)
    input_paths = {
        name: f"analysis/{name}.json"
        for name in REQUIRED_REPORTS
        if name != "objc-dispatch"
    }
    facts = {
        "input_artifacts": {
            **{
                name: {
                    "path": relative,
                    "sha256": sha256_file(_relative_file(workspace, relative)),
                }
                for name, relative in sorted(input_paths.items())
            },
            "objc-dispatch-baseline": {
                "path": "analysis/objc-dispatch.json",
                "projection_sha256": _canonical_sha256(baseline_projection),
            },
        },
        "pseudocode_artifact_count": len(pseudocode_artifacts),
        "pseudocode_artifacts": [
            pseudocode_artifacts[key] for key in sorted(pseudocode_artifacts)
        ],
        "value_count": len(values),
        "classification_counts": {
            name: classifications.get(name, 0) for name in CLASSIFICATIONS
        },
        "value_kind_counts": dict(sorted(kinds.items())),
        "evidence_count": len(graph.evidence),
        "propagation_step_count": len(graph.edges),
        "fixed_point": {
            "converged": True,
            "iteration_count": iteration_count,
            "cyclic_component_count": len(cyclic_components),
            "cyclic_value_count": sum(len(item) for item in cyclic_components),
            "cyclic_components": cyclic_components,
        },
        "dispatch_receiver_value_count": len(receiver_value_ids),
        "dispatch_refinement_count": len(dispatch_refinements),
        "changed_dispatch_refinement_count": sum(
            bool(item["changed"]) for item in dispatch_refinements
        ),
        "unresolved_reason_counts": dict(sorted(unresolved_reasons.items())),
        "values": values,
        "evidence": [graph.evidence[key] for key in sorted(graph.evidence)],
        "propagation_steps": [graph.edges[key] for key in sorted(graph.edges)],
        "dispatch_refinements": dispatch_refinements,
    }
    hypotheses = [
        {
            "kind": "type_flow_propagation_hypothesis",
            "propagation_step_id": edge["id"],
            "source_value_id": edge["source_value_id"],
            "target_value_id": edge["target_value_id"],
            "basis": edge["basis"],
        }
        for edge in facts["propagation_steps"]
        if edge["hypothesis"]
    ]
    errors = [
        {
            "code": reason,
            "count": count,
            "message": reason.replace("_", " ").capitalize(),
        }
        for reason, count in sorted(unresolved_reasons.items())
    ]
    type_flow = report_envelope(
        "objc-type-flow",
        facts,
        hypotheses=hypotheses,
        errors=errors,
    )
    type_flow_path = workspace / "analysis" / "objc-type-flow.json"
    report_path = workspace / "reports" / "objc-type-flow-report.md"
    write_json_atomic(type_flow_path, type_flow)
    write_text_atomic(report_path, render_objc_type_flow_report(facts))
    return TypeFlowResult(workspace, type_flow, type_flow_path, report_path)
