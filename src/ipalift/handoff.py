"""Deterministic reconstruction handoff assembly without behavioral invention."""

from __future__ import annotations

import hashlib
import importlib.resources
import json
import os
import re
import shutil
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .errors import IPALiftError
from .util import normalize_json, report_envelope, sha256_file, write_json_atomic, write_text_atomic


class HandoffError(IPALiftError):
    """A workspace cannot support a trustworthy reconstruction handoff."""


@dataclass(frozen=True)
class HandoffResult:
    workspace: Path
    manifest: dict[str, Any]
    manifest_path: Path
    packets_root: Path
    report_path: Path


REQUIRED_REPORTS = (
    "application",
    "assets",
    "recovered-code-index",
    "objc-type-flow",
    "native-type-flow",
    "platform-api-map",
    "ui-model",
    "interaction-model",
)
CLASSIFICATIONS = ("exact", "candidate_set", "unresolved")
RELATED_ID_KINDS = (
    "screen_ids",
    "element_ids",
    "asset_ids",
    "navigation_ids",
    "interaction_ids",
    "trigger_ids",
    "effect_ids",
    "function_ids",
    "method_ids",
    "class_names",
    "type_value_ids",
    "platform_dependency_ids",
    "pseudocode_paths",
)
EFFECT_ITEM_KIND = {
    "state_read": "state",
    "state_write": "state",
    "navigation": "navigation",
    "ui_update": "component",
    "persistence_read": "persistence",
    "persistence_write": "persistence",
    "persistence_access": "persistence",
    "network_request": "networking",
    "notification_post": "platform_dependency",
    "timer_schedule": "platform_dependency",
    "platform_api": "platform_dependency",
}


def _stable_id(kind: str, *parts: Any) -> str:
    identity = "\0".join([kind, *(str(part) for part in parts)])
    return f"{kind}:{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:20]}"


def _classification(*values: str) -> str:
    normalized = [value if value in CLASSIFICATIONS else "unresolved" for value in values]
    if not normalized or "unresolved" in normalized:
        return "unresolved"
    if "candidate_set" in normalized:
        return "candidate_set"
    return "exact"


def _record_classification(record: dict[str, Any], default: str = "exact") -> str:
    value = str(record.get("classification") or default)
    return value if value in CLASSIFICATIONS else "unresolved"


def _load_policy() -> tuple[dict[str, Any], str]:
    resource = importlib.resources.files("ipalift").joinpath("catalogs/handoff-policy-v1.json")
    try:
        data = resource.read_bytes()
        policy = json.loads(data.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HandoffError(f"Cannot load the reconstruction handoff policy: {exc}") from exc
    required = {
        "catalog_id",
        "catalog_version",
        "description",
        "bounds",
        "work_item_kinds",
        "exact_phase_by_kind",
        "phase_order",
    }
    if not isinstance(policy, dict) or set(policy) != required:
        raise HandoffError("Reconstruction handoff policy has an invalid top-level shape")
    if policy["catalog_id"] != "ipalift-reconstruction-handoff-policy":
        raise HandoffError("Reconstruction handoff policy has an unexpected identity")
    bounds = policy.get("bounds")
    expected_bounds = {
        "max_input_report_bytes",
        "max_total_input_report_bytes",
        "max_pseudocode_bytes_per_function",
        "max_total_pseudocode_bytes",
        "max_work_items_per_packet",
        "max_packet_bytes",
        "max_evidence_links_per_item",
        "max_candidate_alternatives_per_item",
        "max_candidate_ids_per_alternative",
        "max_questions_per_item",
        "max_reason_codes_per_item",
        "max_related_ids_per_kind",
        "max_inline_collection_items",
        "max_inline_string_chars",
        "max_inline_depth",
    }
    if (
        not isinstance(bounds, dict)
        or set(bounds) != expected_bounds
        or any(not isinstance(bounds[key], int) or bounds[key] <= 0 for key in expected_bounds)
    ):
        raise HandoffError("Reconstruction handoff policy has invalid resource bounds")
    kinds = policy.get("work_item_kinds")
    phases = policy.get("phase_order")
    mapping = policy.get("exact_phase_by_kind")
    if (
        not isinstance(kinds, list)
        or not kinds
        or len(kinds) != len(set(kinds))
        or not all(isinstance(value, str) and value for value in kinds)
        or not isinstance(phases, list)
        or len(phases) != len(set(phases))
        or set(phases) != {
            "exact_foundation",
            "exact_behavior",
            "exact_integration",
            "candidate_validation",
            "unresolved_research",
        }
        or not isinstance(mapping, dict)
        or set(mapping) != set(kinds)
        or any(value not in phases for value in mapping.values())
    ):
        raise HandoffError("Reconstruction handoff policy has invalid kinds or phase ordering")
    return policy, hashlib.sha256(data).hexdigest()


def _load_reports(
    workspace: Path,
    names: Iterable[str],
    bounds: dict[str, int],
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    reports: dict[str, dict[str, Any]] = {}
    inputs: list[dict[str, Any]] = []
    total_size = 0
    for name in sorted(names):
        path = workspace / "analysis" / f"{name}.json"
        try:
            size = path.stat().st_size
        except FileNotFoundError as exc:
            raise HandoffError(f"Analysis workspace is missing analysis/{name}.json") from exc
        except OSError as exc:
            raise HandoffError(f"Cannot stat {path}: {exc}") from exc
        if size > bounds["max_input_report_bytes"]:
            raise HandoffError(
                f"Input report analysis/{name}.json is {size} bytes; limit is "
                f"{bounds['max_input_report_bytes']}"
            )
        total_size += size
        if total_size > bounds["max_total_input_report_bytes"]:
            raise HandoffError(
                f"Input reports total more than {bounds['max_total_input_report_bytes']} bytes"
            )
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HandoffError(f"Cannot read {path}: {exc}") from exc
        if (
            document.get("schema_version") != 1
            or document.get("artifact") != name
            or not isinstance(document.get("facts"), dict)
            or not isinstance(document.get("hypotheses"), list)
            or not isinstance(document.get("errors"), list)
        ):
            raise HandoffError(f"Invalid IPALift {name} report: {path}")
        digest = sha256_file(path)
        reports[name] = document
        inputs.append({
            "artifact": name,
            "path": f"analysis/{name}.json",
            "sha256": digest,
            "size": size,
        })
    return reports, inputs


def _validate_input_coherence(
    reports: dict[str, dict[str, Any]],
    input_hashes: dict[str, str],
) -> None:
    for consumer, report in sorted(reports.items()):
        references = report.get("facts", {}).get("input_artifacts", [])
        if isinstance(references, dict):
            normalized_references = [
                {"artifact": artifact, **reference}
                for artifact, reference in sorted(references.items())
                if isinstance(reference, dict)
            ]
            if len(normalized_references) != len(references):
                raise HandoffError(f"Invalid input_artifacts in analysis/{consumer}.json")
        elif isinstance(references, list):
            normalized_references = references
        else:
            raise HandoffError(f"Invalid input_artifacts in analysis/{consumer}.json")
        for reference in normalized_references:
            if not isinstance(reference, dict):
                raise HandoffError(f"Invalid input artifact reference in analysis/{consumer}.json")
            artifact = str(reference.get("artifact") or "")
            expected = str(reference.get("sha256") or "")
            if artifact in input_hashes and expected and expected != input_hashes[artifact]:
                raise HandoffError(
                    f"analysis/{consumer}.json was built from a different {artifact} artifact"
                )

def _assert_inputs_unchanged(
    workspace: Path,
    input_artifacts: Iterable[dict[str, Any]],
) -> None:
    for artifact in input_artifacts:
        path = workspace / Path(*str(artifact["path"]).split("/"))
        try:
            current = sha256_file(path)
        except OSError as exc:
            raise HandoffError(f"Cannot revalidate upstream artifact {artifact['path']}: {exc}") from exc
        if current != artifact["sha256"]:
            raise HandoffError(f"Upstream artifact changed while building handoff: {artifact['path']}")

def _relative_file(workspace: Path, relative: str) -> Path:
    portable = relative.replace("\\", "/")
    parts = portable.split("/")
    if (
        not portable
        or portable.startswith("/")
        or re.match(r"^[A-Za-z]:", portable)
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise HandoffError(f"Artifact path escapes the analysis workspace: {relative}")
    candidate = (workspace / Path(*parts)).resolve()
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise HandoffError(f"Artifact path escapes the analysis workspace: {relative}") from exc
    return candidate


def _verify_pseudocode(
    workspace: Path,
    functions: list[dict[str, Any]],
    bounds: dict[str, int],
) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    seen_functions: set[str] = set()
    total_size = 0
    for function in sorted(functions, key=lambda item: str(item.get("function_id") or "")):
        function_id = str(function.get("function_id") or "")
        if not function_id:
            raise HandoffError("Recovered-code index contains a function without function_id")
        if function_id in seen_functions:
            raise HandoffError(f"Recovered-code index contains duplicate function {function_id}")
        seen_functions.add(function_id)
        decompilation = function.get("decompilation") or {}
        if decompilation.get("status") != "success" or not decompilation.get("output_path"):
            continue
        relative = str(decompilation["output_path"])
        path = _relative_file(workspace, relative)
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise HandoffError(f"Cannot stat pseudocode artifact {relative}: {exc}") from exc
        if size > bounds["max_pseudocode_bytes_per_function"]:
            raise HandoffError(
                f"Pseudocode artifact {relative} is {size} bytes; limit is "
                f"{bounds['max_pseudocode_bytes_per_function']}"
            )
        total_size += size
        if total_size > bounds["max_total_pseudocode_bytes"]:
            raise HandoffError(
                f"Pseudocode artifacts total more than {bounds['max_total_pseudocode_bytes']} bytes"
            )
        digest = sha256_file(path)
        expected = decompilation.get("sha256")
        if expected and str(expected) != digest:
            raise HandoffError(f"Pseudocode hash mismatch for {relative}")
        artifacts.append({
            "function_id": function_id,
            "path": relative.replace("\\", "/"),
            "sha256": digest,
            "size": size,
        })
    return artifacts


def _unique_records(
    records: Iterable[dict[str, Any]],
    key: str,
    source: str,
) -> tuple[dict[str, dict[str, Any]], dict[str, int]]:
    by_id: dict[str, dict[str, Any]] = {}
    positions: dict[str, int] = {}
    for index, record in enumerate(records):
        identity = str(record.get(key) or "")
        if not identity:
            continue
        if identity in by_id:
            raise HandoffError(f"Duplicate {key} {identity!r} in {source}")
        by_id[identity] = record
        positions[identity] = index
    return by_id, positions


def _bounded_json(value: Any, bounds: dict[str, int], depth: int = 0) -> Any:
    if depth >= bounds["max_inline_depth"] and isinstance(value, (dict, list, tuple)):
        rendered = json.dumps(normalize_json(value), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return {
            "$truncated": "depth",
            "sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
        }
    if isinstance(value, str):
        limit = bounds["max_inline_string_chars"]
        if len(value) <= limit:
            return value
        return {
            "$truncated": "text",
            "prefix": value[:limit],
            "original_char_count": len(value),
            "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
        }
    if isinstance(value, dict):
        keys = sorted(value, key=str)
        limit = bounds["max_inline_collection_items"]
        result = {
            str(key): _bounded_json(value[key], bounds, depth + 1)
            for key in keys[:limit]
        }
        if len(keys) > limit:
            result["$omitted_key_count"] = len(keys) - limit
        return result
    if isinstance(value, (list, tuple)):
        limit = bounds["max_inline_collection_items"]
        result = [_bounded_json(item, bounds, depth + 1) for item in value[:limit]]
        if len(value) > limit:
            return {"items": result, "$omitted_item_count": len(value) - limit}
        return result
    return normalize_json(value)


def _short_text(value: Any, bounds: dict[str, int], limit: int = 240) -> str:
    text = str(value or "")
    maximum = min(limit, bounds["max_inline_string_chars"])
    return text if len(text) <= maximum else text[:maximum] + "…"


def _record_link(
    artifact: str,
    collection: str,
    position: int,
    record_id: str,
    classification: str,
    input_hashes: dict[str, str],
) -> dict[str, Any]:
    return {
        "kind": "artifact_record",
        "artifact": artifact,
        "path": f"analysis/{artifact}.json",
        "json_pointer": f"/facts/{collection}/{position}",
        "record_id": record_id,
        "classification": classification,
        "sha256": input_hashes[artifact],
    }


def _document_link(
    artifact: str,
    pointer: str,
    record_id: str,
    classification: str,
    input_hashes: dict[str, str],
) -> dict[str, Any]:
    return {
        "kind": "artifact_record",
        "artifact": artifact,
        "path": f"analysis/{artifact}.json",
        "json_pointer": pointer,
        "record_id": record_id,
        "classification": classification,
        "sha256": input_hashes[artifact],
    }


def _pseudocode_link(artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": "pseudocode",
        "artifact": "pseudocode",
        "path": artifact["path"],
        "json_pointer": None,
        "record_id": artifact["function_id"],
        "classification": "exact",
        "sha256": artifact["sha256"],
    }


def _deduplicate_dicts(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        identity = json.dumps(normalize_json(record), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        if identity not in seen:
            seen.add(identity)
            result.append(record)
    return result


def _bounded_ids(values: Iterable[Any], limit: int) -> tuple[list[str], int]:
    unique = sorted({str(value) for value in values if value is not None and str(value)})
    return unique[:limit], max(0, len(unique) - limit)


def _candidate_identity(record: Any, bounds: dict[str, int]) -> str:
    if isinstance(record, dict):
        for key in ("id", "candidate_id", "class_name", "type_name", "class_id", "name", "type"):
            if record.get(key) is not None:
                return _short_text(record[key], bounds, 512)
        rendered = json.dumps(normalize_json(record), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return _short_text(rendered, bounds, 512)
    return _short_text(record, bounds, 512)


def _alternative(
    *,
    item_identity: str,
    kind: str,
    source_record_id: str,
    candidates: Iterable[Any],
    basis: str,
    evidence_links: list[dict[str, Any]],
    bounds: dict[str, int],
) -> dict[str, Any] | None:
    identities = sorted({_candidate_identity(value, bounds) for value in candidates if value is not None})
    identities = [value for value in identities if value]
    if not identities:
        return None
    limit = bounds["max_candidate_ids_per_alternative"]
    return {
        "id": _stable_id("handoff-alternative", item_identity, kind, source_record_id),
        "kind": kind,
        "source_record_id": source_record_id,
        "candidate_ids": identities[:limit],
        "omitted_candidate_count": max(0, len(identities) - limit),
        "basis": basis,
        "evidence_links": evidence_links[: bounds["max_evidence_links_per_item"]],
    }


def _question(
    *,
    item_identity: str,
    kind: str,
    subject_id: str,
    classification: str,
    prompt: str,
    reason_codes: Iterable[str],
    evidence_links: list[dict[str, Any]],
    bounds: dict[str, int],
) -> dict[str, Any]:
    reasons, omitted = _bounded_ids(reason_codes, bounds["max_reason_codes_per_item"])
    return {
        "id": _stable_id("handoff-question", item_identity, kind, subject_id, *reasons),
        "kind": kind,
        "subject_id": subject_id,
        "classification": classification,
        "prompt": prompt,
        "reason_codes": reasons,
        "omitted_reason_count": omitted,
        "evidence_links": evidence_links[: bounds["max_evidence_links_per_item"]],
    }


def _work_item(
    *,
    scope: str | None,
    kind: str,
    subject_id: str,
    classification: str,
    title: str,
    details: dict[str, Any],
    related_ids: dict[str, Iterable[Any]],
    evidence_links: Iterable[dict[str, Any]],
    candidate_alternatives: Iterable[dict[str, Any] | None],
    failure_reasons: Iterable[str],
    bounds: dict[str, int],
) -> dict[str, Any]:
    item_id = _stable_id("handoff-work-item", scope or "application", kind, subject_id)
    evidence = _deduplicate_dicts(evidence_links)
    evidence_limit = bounds["max_evidence_links_per_item"]
    evidence_overflow = max(0, len(evidence) - evidence_limit)
    alternatives = _deduplicate_dicts(item for item in candidate_alternatives if item is not None)
    alternative_limit = bounds["max_candidate_alternatives_per_item"]
    alternative_overflow = max(0, len(alternatives) - alternative_limit)
    reasons, reason_overflow = _bounded_ids(failure_reasons, bounds["max_reason_codes_per_item"])
    related: dict[str, list[str]] = {}
    related_overflow: dict[str, int] = {}
    for related_kind in RELATED_ID_KINDS:
        values, overflow = _bounded_ids(
            related_ids.get(related_kind, []),
            bounds["max_related_ids_per_kind"],
        )
        related[related_kind] = values
        related_overflow[related_kind] = overflow
    questions: list[dict[str, Any]] = []
    if classification == "candidate_set":
        questions.append(_question(
            item_identity=item_id,
            kind="validate_candidate_set",
            subject_id=subject_id,
            classification=classification,
            prompt="Validate which upstream candidate applies before implementing this work item.",
            reason_codes=reasons or ["candidate_target_not_proven"],
            evidence_links=evidence,
            bounds=bounds,
        ))
    elif classification == "unresolved":
        questions.append(_question(
            item_identity=item_id,
            kind="recover_missing_evidence",
            subject_id=subject_id,
            classification=classification,
            prompt="Recover or supply the missing evidence before implementing this work item.",
            reason_codes=reasons or ["subject_not_resolved"],
            evidence_links=evidence,
            bounds=bounds,
        ))
    elif reasons:
        questions.append(_question(
            item_identity=item_id,
            kind="review_evidence_limitation",
            subject_id=subject_id,
            classification=classification,
            prompt="Review the recorded evidence limitation while implementing this exact work item.",
            reason_codes=reasons,
            evidence_links=evidence,
            bounds=bounds,
        ))
    question_limit = bounds["max_questions_per_item"]
    return {
        "id": item_id,
        "kind": kind,
        "subject_id": subject_id,
        "screen_id": scope,
        "classification": classification,
        "title": _short_text(title, bounds),
        "implementation_rank": 0,
        "implementation_phase": "unresolved_research",
        "priority_basis": "pending deterministic evidence ordering",
        "details": _bounded_json(details, bounds),
        "related_ids": related,
        "related_id_overflow_counts": related_overflow,
        "evidence_links": evidence[:evidence_limit],
        "omitted_evidence_link_count": evidence_overflow,
        "candidate_alternatives": alternatives[:alternative_limit],
        "omitted_candidate_alternative_count": alternative_overflow,
        "unresolved_questions": questions[:question_limit],
        "omitted_question_count": max(0, len(questions) - question_limit),
        "failure_reasons": reasons,
        "omitted_failure_reason_count": reason_overflow,
    }


def _type_alternatives(
    item_identity: str,
    records: Iterable[dict[str, Any]],
    evidence_links: list[dict[str, Any]],
    bounds: dict[str, int],
) -> list[dict[str, Any] | None]:
    result: list[dict[str, Any] | None] = []
    for record in records:
        candidates = list(record.get("type_candidates") or [])
        if not candidates:
            continue
        result.append(_alternative(
            item_identity=item_identity,
            kind="type_candidate",
            source_record_id=str(record.get("id") or "type-value"),
            candidates=candidates,
            basis="The authoritative type-flow artifact retains multiple possible types.",
            evidence_links=evidence_links,
            bounds=bounds,
        ))
    return result


def _rendered_json(value: Any) -> bytes:
    rendered = json.dumps(normalize_json(value), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    return rendered.encode("utf-8")


def _packet_document(
    *,
    scope: str | None,
    screen_name: str,
    sequence: int,
    total_sequences: int,
    items: list[dict[str, Any]],
    policy: dict[str, Any],
    policy_sha256: str,
    input_fingerprint: str,
) -> dict[str, Any]:
    packet_id = _stable_id("reconstruction-packet", scope or "application", sequence)
    classifications = Counter(str(item["classification"]) for item in items)
    kinds = Counter(str(item["kind"]) for item in items)
    return {
        "schema_version": 1,
        "artifact": "reconstruction-work-packet",
        "id": packet_id,
        "policy": {
            "catalog_id": policy["catalog_id"],
            "catalog_version": policy["catalog_version"],
            "sha256": policy_sha256,
        },
        "input_fingerprint": input_fingerprint,
        "scope": "screen" if scope is not None else "application",
        "screen_id": scope,
        "screen_name": screen_name,
        "sequence": sequence,
        "total_sequences": total_sequences,
        "summary": {
            "work_item_count": len(items),
            "classification_counts": {name: classifications.get(name, 0) for name in CLASSIFICATIONS},
            "work_item_kind_counts": dict(sorted(kinds.items())),
            "candidate_alternative_count": sum(len(item["candidate_alternatives"]) for item in items),
            "unresolved_question_count": sum(len(item["unresolved_questions"]) for item in items),
        },
        "work_items": items,
    }


def _pack_scope(
    *,
    scope: str | None,
    screen_name: str,
    items: list[dict[str, Any]],
    policy: dict[str, Any],
    policy_sha256: str,
    input_fingerprint: str,
    bounds: dict[str, int],
) -> list[dict[str, Any]]:
    chunks: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    max_items = bounds["max_work_items_per_packet"]
    max_bytes = bounds["max_packet_bytes"]
    for item in sorted(items, key=lambda value: (int(value["implementation_rank"]), value["id"])):
        candidate = [*current, item]
        provisional = _packet_document(
            scope=scope,
            screen_name=screen_name,
            sequence=len(chunks) + 1,
            total_sequences=999999,
            items=candidate,
            policy=policy,
            policy_sha256=policy_sha256,
            input_fingerprint=input_fingerprint,
        )
        if current and (len(candidate) > max_items or len(_rendered_json(provisional)) > max_bytes):
            chunks.append(current)
            current = [item]
        else:
            current = candidate
        single = _packet_document(
            scope=scope,
            screen_name=screen_name,
            sequence=len(chunks) + 1,
            total_sequences=999999,
            items=current,
            policy=policy,
            policy_sha256=policy_sha256,
            input_fingerprint=input_fingerprint,
        )
        if len(current) > max_items or len(_rendered_json(single)) > max_bytes:
            raise HandoffError(
                f"Work item {item['id']} cannot fit within the configured packet bounds"
            )
    if current or not chunks:
        chunks.append(current)
    packets = [
        _packet_document(
            scope=scope,
            screen_name=screen_name,
            sequence=index,
            total_sequences=len(chunks),
            items=chunk,
            policy=policy,
            policy_sha256=policy_sha256,
            input_fingerprint=input_fingerprint,
        )
        for index, chunk in enumerate(chunks, 1)
    ]
    for packet in packets:
        size = len(_rendered_json(packet))
        if size > max_bytes:
            raise HandoffError(f"Packet {packet['id']} exceeds the configured byte bound")
    return packets


def _packet_filename(packet: dict[str, Any]) -> str:
    if packet["scope"] == "application":
        prefix = "application"
    else:
        screen_id = str(packet["screen_id"])
        prefix = "screen-" + hashlib.sha256(screen_id.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}-{int(packet['sequence']):04d}.json"


def _write_packets_atomic(workspace: Path, packets: list[dict[str, Any]]) -> Path:
    handoff_root = workspace / "handoff"
    handoff_root.mkdir(parents=True, exist_ok=True)
    packets_root = handoff_root / "work-packets"
    temporary = Path(tempfile.mkdtemp(prefix=".work-packets-", dir=handoff_root))
    try:
        for packet in packets:
            write_json_atomic(temporary / _packet_filename(packet), packet)
        if packets_root.exists():
            resolved = packets_root.resolve()
            try:
                resolved.relative_to(handoff_root.resolve())
            except ValueError as exc:
                raise HandoffError(f"Refusing to replace packet directory outside {handoff_root}") from exc
            if resolved == handoff_root.resolve():
                raise HandoffError("Refusing to replace the handoff root as a packet directory")
            shutil.rmtree(resolved)
        os.replace(temporary, packets_root)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return packets_root


def _render_report(facts: dict[str, Any]) -> str:
    summary = facts["summary"]
    lines = [
        "# IPALift reconstruction handoff report",
        "",
        "> Evidence-prioritized implementation guidance. This report introduces no new behavioral inference.",
        "",
        "## Summary",
        "",
        f"- Screens: {summary['screen_plan_count']}",
        f"- Work packets: {summary['packet_count']}",
        f"- Work items: {summary['work_item_count']}",
        f"- Candidate alternatives: {summary['candidate_alternative_count']}",
        f"- Unresolved questions: {summary['unresolved_question_count']}",
        f"- Verified pseudocode artifacts: {summary['pseudocode_artifact_count']}",
        "",
        "## Screen work packets",
        "",
    ]
    for screen in facts["screen_plans"]:
        lines.extend([
            f"### {screen['screen_name']}",
            "",
            f"- Screen ID: `{screen['screen_id']}`",
            f"- Classification: {screen['classification']}",
            f"- Work items: {screen['work_item_count']}",
            f"- Packets: {', '.join(f'`{value}`' for value in screen['packet_paths']) or 'none'}",
            f"- Candidate alternatives: {screen['candidate_alternative_count']}",
            f"- Unresolved questions: {screen['unresolved_question_count']}",
            "",
        ])
    application = facts["application_plan"]
    lines.extend([
        "## Application-wide work packets",
        "",
        f"- Work items: {application['work_item_count']}",
        f"- Packets: {', '.join(f'`{value}`' for value in application['packet_paths']) or 'none'}",
        f"- Candidate alternatives: {application['candidate_alternative_count']}",
        f"- Unresolved questions: {application['unresolved_question_count']}",
        "",
        "## Evidence-prioritized implementation order",
        "",
    ])
    order = facts["implementation_order"]
    for record in order[:200]:
        scope = record["screen_id"] or "application"
        lines.append(
            f"{record['rank']}. [{record['classification']}] {record['kind']} "
            f"`{record['work_item_id']}` ({scope})"
        )
    if len(order) > 200:
        lines.extend([
            "",
            f"The machine-readable manifest contains all {len(order)} ordered work items; this report shows the first 200.",
        ])
    lines.extend([
        "",
        "## Evidence boundary",
        "",
        "- Exact records are ordered ahead of candidate validation and unresolved research.",
        "- Candidate alternatives and unresolved questions are retained, never promoted to facts.",
        "- Packet details are bounded; complete evidence remains linked in immutable upstream artifacts.",
        "- Work packets are reconstruction guidance, not original source code or proof of runtime behavior.",
        "",
    ])
    return "\n".join(lines)


def build_handoff(workspace: Path) -> HandoffResult:
    """Build a bounded, evidence-linked reconstruction handoff from completed reports."""
    workspace = workspace.resolve()
    policy, policy_sha256 = _load_policy()
    bounds = {key: int(value) for key, value in policy["bounds"].items()}
    reports, input_artifacts = _load_reports(workspace, REQUIRED_REPORTS, bounds)
    input_hashes = {item["artifact"]: item["sha256"] for item in input_artifacts}
    _validate_input_coherence(reports, input_hashes)
    input_fingerprint = hashlib.sha256(
        json.dumps(input_artifacts, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    ui = reports["ui-model"]["facts"]
    interaction = reports["interaction-model"]["facts"]
    recovered = reports["recovered-code-index"]["facts"]
    platform = reports["platform-api-map"]["facts"]
    objc_types = reports["objc-type-flow"]["facts"]
    native_types = reports["native-type-flow"]["facts"]
    assets_report = reports["assets"]["facts"]

    screens = list(ui.get("screens") or [])
    elements = list(ui.get("elements") or [])
    resource_references = list(ui.get("resource_references") or [])
    ui_assets = list(ui.get("assets") or [])
    navigation_edges = list(ui.get("navigation_edges") or [])
    interactions = list(interaction.get("interactions") or [])
    triggers = list(interaction.get("triggers") or [])
    effects = list(interaction.get("effects") or [])
    call_slices = list(interaction.get("call_slices") or [])
    recovered_functions = list(recovered.get("functions") or [])
    recovered_methods = list(recovered.get("methods") or [])
    recovered_classes = list(recovered.get("classes") or [])
    platform_dependencies = list(platform.get("dependencies") or [])
    objc_values = list(objc_types.get("values") or [])
    native_values = list(native_types.get("values") or [])
    native_globals = list(native_types.get("globals") or [])
    native_layouts = list(native_types.get("layouts") or [])
    archive_assets = list(assets_report.get("assets") or [])

    screen_by_id, screen_pos = _unique_records(screens, "id", "ui-model screens")
    element_by_id, element_pos = _unique_records(elements, "id", "ui-model elements")
    resource_by_id, resource_pos = _unique_records(resource_references, "id", "ui-model resource references")
    ui_asset_by_id, ui_asset_pos = _unique_records(ui_assets, "id", "ui-model assets")
    navigation_by_id, navigation_pos = _unique_records(navigation_edges, "id", "ui-model navigation")
    interaction_by_id, interaction_pos = _unique_records(interactions, "id", "interaction-model interactions")
    trigger_by_id, trigger_pos = _unique_records(triggers, "id", "interaction-model triggers")
    effect_by_id, effect_pos = _unique_records(effects, "id", "interaction-model effects")
    slice_by_id, slice_pos = _unique_records(call_slices, "id", "interaction-model call slices")
    function_by_id, function_pos = _unique_records(recovered_functions, "function_id", "recovered-code functions")
    method_by_id, method_pos = _unique_records(recovered_methods, "id", "recovered-code methods")
    class_by_name, class_pos = _unique_records(recovered_classes, "name", "recovered-code classes")
    dependency_by_id, dependency_pos = _unique_records(platform_dependencies, "id", "platform dependencies")
    objc_value_by_id, objc_value_pos = _unique_records(objc_values, "id", "Objective-C type values")
    native_value_by_id, native_value_pos = _unique_records(native_values, "id", "native type values")
    native_global_by_id, native_global_pos = _unique_records(native_globals, "id", "native globals")
    native_layout_by_id, native_layout_pos = _unique_records(native_layouts, "id", "native layouts")
    archive_asset_by_bundle_path: dict[str, tuple[dict[str, Any], int, str]] = {}
    for index, asset in enumerate(archive_assets):
        bundle_path = str(asset.get("bundle_relative_path") or asset.get("path") or "")
        if not bundle_path:
            bundle_path = f"sha256:{asset.get('sha256') or index}"
        if bundle_path in archive_asset_by_bundle_path:
            raise HandoffError(f"Duplicate archive asset identity {bundle_path!r}")
        record_id = "archive-asset:" + hashlib.sha256(bundle_path.encode("utf-8")).hexdigest()[:20]
        archive_asset_by_bundle_path[bundle_path] = (asset, index, record_id)

    for element in elements:
        if str(element.get("screen_id") or "") not in screen_by_id:
            raise HandoffError(f"UI element {element.get('id')} references an unknown screen")
    for record in interactions:
        if any(str(value) not in screen_by_id for value in record.get("screen_ids", [])):
            raise HandoffError(f"Interaction {record.get('id')} references an unknown screen")
        if str(record.get("trigger_id") or "") not in trigger_by_id:
            raise HandoffError(f"Interaction {record.get('id')} references an unknown trigger")
        if str(record.get("call_slice_id") or "") not in slice_by_id:
            raise HandoffError(f"Interaction {record.get('id')} references an unknown call slice")
        if any(str(value) not in effect_by_id for value in record.get("effect_ids", [])):
            raise HandoffError(f"Interaction {record.get('id')} references an unknown effect")

    pseudocode_artifacts = _verify_pseudocode(workspace, recovered_functions, bounds)
    pseudocode_by_function = {item["function_id"]: item for item in pseudocode_artifacts}

    methods_by_class: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for method in recovered_methods:
        methods_by_class[str(method.get("class_name") or "")].append(method)
    methods_by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for method in recovered_methods:
        if method.get("function_id"):
            methods_by_function[str(method["function_id"])].append(method)
    objc_values_by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
    native_values_by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for value in objc_values:
        if value.get("function_id"):
            objc_values_by_function[str(value["function_id"])].append(value)
    for value in native_values:
        if value.get("function_id"):
            native_values_by_function[str(value["function_id"])].append(value)

    function_scopes: dict[str, set[str]] = defaultdict(set)
    for screen in screens:
        class_name = str(screen.get("controller_class_name") or "")
        for method in methods_by_class.get(class_name, []):
            if method.get("function_id"):
                function_scopes[str(method["function_id"])].add(str(screen["id"]))
    for record in interactions:
        scope_ids = {str(value) for value in record.get("screen_ids", [])}
        call_slice = slice_by_id.get(str(record.get("call_slice_id") or ""), {})
        function_ids = {
            *(str(value) for value in record.get("handler_function_ids", [])),
            *(str(node.get("function_id")) for node in call_slice.get("nodes", []) if node.get("function_id")),
        }
        for function_id in function_ids:
            function_scopes[function_id].update(scope_ids)

    items_by_scope: dict[str | None, list[dict[str, Any]]] = defaultdict(list)
    seen_item_ids: set[str] = set()

    def add_item(item: dict[str, Any]) -> None:
        if item["kind"] not in policy["work_item_kinds"]:
            raise HandoffError(f"Internal unsupported handoff work item kind: {item['kind']}")
        if item["id"] in seen_item_ids:
            return
        seen_item_ids.add(item["id"])
        items_by_scope[item["screen_id"]].append(item)

    interactions_by_screen: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in interactions:
        for screen_id in record.get("screen_ids", []):
            interactions_by_screen[str(screen_id)].append(record)
    asset_ids_by_element: dict[str, set[str]] = defaultdict(set)
    for record in resource_references:
        element_id = str(record.get("element_id") or "")
        asset_ids_by_element[element_id].update(
            str(value) for value in record.get("asset_candidate_ids", []) if value
        )

    for screen in sorted(screens, key=lambda item: str(item.get("id") or "")):
        screen_id = str(screen["id"])
        screen_link = _record_link(
            "ui-model", "screens", screen_pos[screen_id], screen_id,
            _record_classification(screen), input_hashes,
        )
        add_item(_work_item(
            scope=screen_id,
            kind="screen",
            subject_id=screen_id,
            classification=_record_classification(screen),
            title=f"Screen {screen.get('name') or screen_id}",
            details={
                "name": screen.get("name"),
                "controller_class_name": screen.get("controller_class_name"),
                "entry_point_kind": screen.get("entry_point_kind"),
                "source_kind": screen.get("source_kind"),
                "source_path": screen.get("source_path"),
                "root_element_id": screen.get("root_element_id"),
            },
            related_ids={
                "screen_ids": [screen_id],
                "element_ids": screen.get("element_ids", []),
                "navigation_ids": screen.get("navigation_edge_ids", []),
                "interaction_ids": [value["id"] for value in interactions_by_screen.get(screen_id, [])],
                "class_names": [screen.get("controller_class_name")],
            },
            evidence_links=[screen_link],
            candidate_alternatives=[],
            failure_reasons=screen.get("failure_reasons", []),
            bounds=bounds,
        ))

    for element in sorted(elements, key=lambda item: str(item.get("id") or "")):
        element_id = str(element["id"])
        screen_id = str(element["screen_id"])
        classification = _record_classification(element)
        link = _record_link(
            "ui-model", "elements", element_pos[element_id], element_id, classification, input_hashes,
        )
        add_item(_work_item(
            scope=screen_id,
            kind="component",
            subject_id=element_id,
            classification=classification,
            title=f"Component {element.get('class_name') or element_id}",
            details={
                "class_name": element.get("class_name"),
                "base_class_name": element.get("base_class_name"),
                "custom_class": element.get("custom_class"),
                "parent_id": element.get("parent_id"),
                "child_ids": element.get("child_ids", []),
                "frame": element.get("frame"),
                "bounds": element.get("bounds"),
                "attributes": element.get("attributes", {}),
                "properties": element.get("properties", {}),
            },
            related_ids={
                "screen_ids": [screen_id],
                "element_ids": [element_id, *element.get("child_ids", [])],
                "asset_ids": asset_ids_by_element.get(element_id, set()),
                "class_names": [element.get("custom_class"), element.get("class_name")],
            },
            evidence_links=[link],
            candidate_alternatives=[],
            failure_reasons=element.get("failure_reasons", []),
            bounds=bounds,
        ))

    referenced_asset_ids: set[str] = set()
    for record in sorted(resource_references, key=lambda item: str(item.get("id") or "")):
        resource_id = str(record["id"])
        screen_id = str(record.get("screen_id") or "") or None
        classification = _record_classification(record)
        asset_ids = [str(value) for value in record.get("asset_candidate_ids", [])]
        localization_ids = [str(value) for value in record.get("localization_entry_ids", [])]
        referenced_asset_ids.update(asset_ids)
        link = _record_link(
            "ui-model", "resource_references", resource_pos[resource_id], resource_id,
            classification, input_hashes,
        )
        alternatives = [_alternative(
            item_identity=resource_id,
            kind="resource_candidate",
            source_record_id=resource_id,
            candidates=[*asset_ids, *localization_ids],
            basis="The UI model retains these asset or localization candidates for the serialized resource reference.",
            evidence_links=[link],
            bounds=bounds,
        )] if classification != "exact" or len(asset_ids) + len(localization_ids) > 1 else []
        asset_links = [
            _record_link(
                "ui-model", "assets", ui_asset_pos[asset_id], asset_id,
                _record_classification(ui_asset_by_id[asset_id]), input_hashes,
            )
            for asset_id in asset_ids if asset_id in ui_asset_by_id
        ]
        for asset_id in asset_ids:
            ui_asset = ui_asset_by_id.get(asset_id)
            bundle_path = str((ui_asset or {}).get("bundle_relative_path") or "")
            if bundle_path in archive_asset_by_bundle_path:
                _, archive_position, archive_record_id = archive_asset_by_bundle_path[bundle_path]
                asset_links.append(_record_link(
                    "assets", "assets", archive_position, archive_record_id,
                    "exact", input_hashes,
                ))
        add_item(_work_item(
            scope=screen_id,
            kind="asset",
            subject_id=resource_id,
            classification=classification,
            title=f"{record.get('kind') or 'resource'} for {record.get('element_id') or resource_id}",
            details={
                "kind": record.get("kind"),
                "field": record.get("field"),
                "requested_value": record.get("requested_value"),
            },
            related_ids={
                "screen_ids": [screen_id],
                "element_ids": [record.get("element_id")],
                "asset_ids": asset_ids,
            },
            evidence_links=[link, *asset_links],
            candidate_alternatives=alternatives,
            failure_reasons=record.get("failure_reasons", []),
            bounds=bounds,
        ))

    for asset in sorted(ui_assets, key=lambda item: str(item.get("id") or "")):
        asset_id = str(asset["id"])
        if asset_id in referenced_asset_ids:
            continue
        classification = "exact"
        link = _record_link(
            "ui-model", "assets", ui_asset_pos[asset_id], asset_id, classification, input_hashes,
        )
        archive_links: list[dict[str, Any]] = []
        bundle_path = str(asset.get("bundle_relative_path") or "")
        if bundle_path in archive_asset_by_bundle_path:
            _, archive_position, archive_record_id = archive_asset_by_bundle_path[bundle_path]
            archive_links.append(_record_link(
                "assets", "assets", archive_position, archive_record_id, "exact", input_hashes,
            ))
        add_item(_work_item(
            scope=None,
            kind="asset",
            subject_id=asset_id,
            classification=classification,
            title=f"Unassigned asset {asset.get('logical_name') or asset_id}",
            details={
                "logical_name": asset.get("logical_name"),
                "category": asset.get("category"),
                "bundle_relative_path": asset.get("bundle_relative_path"),
                "size": asset.get("size"),
            },
            related_ids={"asset_ids": [asset_id]},
            evidence_links=[link, *archive_links],
            candidate_alternatives=[],
            failure_reasons=["asset_not_linked_to_recovered_screen"],
            bounds=bounds,
        ))

    ui_asset_bundle_paths = {
        str(asset.get("bundle_relative_path") or "") for asset in ui_assets
        if asset.get("bundle_relative_path")
    }
    for bundle_path, (asset, archive_position, record_id) in sorted(archive_asset_by_bundle_path.items()):
        if bundle_path in ui_asset_bundle_paths:
            continue
        link = _record_link(
            "assets", "assets", archive_position, record_id, "exact", input_hashes,
        )
        add_item(_work_item(
            scope=None,
            kind="asset",
            subject_id=record_id,
            classification="exact",
            title=f"Archive asset {bundle_path}",
            details={
                "bundle_relative_path": asset.get("bundle_relative_path"),
                "asset_category": asset.get("asset_category"),
                "extension": asset.get("extension"),
                "size": asset.get("size"),
            },
            related_ids={"asset_ids": [record_id]},
            evidence_links=[link],
            candidate_alternatives=[],
            failure_reasons=["archive_asset_not_linked_to_ui_model"],
            bounds=bounds,
        ))

    for record in sorted(navigation_edges, key=lambda item: str(item.get("id") or "")):
        navigation_id = str(record["id"])
        screen_id = str(record.get("source_screen_id") or "") or None
        classification = _record_classification(record)
        link = _record_link(
            "ui-model", "navigation_edges", navigation_pos[navigation_id], navigation_id,
            classification, input_hashes,
        )
        add_item(_work_item(
            scope=screen_id,
            kind="navigation",
            subject_id=navigation_id,
            classification=classification,
            title=f"Navigation {record.get('subkind') or navigation_id}",
            details={
                "subkind": record.get("subkind"),
                "identifier": record.get("identifier"),
                "source_screen_id": record.get("source_screen_id"),
                "destination_screen_id": record.get("destination_screen_id"),
            },
            related_ids={
                "screen_ids": [record.get("source_screen_id"), record.get("destination_screen_id")],
                "navigation_ids": [navigation_id],
            },
            evidence_links=[link],
            candidate_alternatives=[],
            failure_reasons=record.get("failure_reasons", []),
            bounds=bounds,
        ))

    effect_to_interaction: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in interactions:
        for effect_id in record.get("effect_ids", []):
            effect_to_interaction[str(effect_id)].append(record)

    for record in sorted(interactions, key=lambda item: str(item.get("id") or "")):
        interaction_id = str(record["id"])
        trigger_id = str(record["trigger_id"])
        call_slice_id = str(record["call_slice_id"])
        trigger = trigger_by_id[trigger_id]
        call_slice = slice_by_id[call_slice_id]
        classification = _record_classification(record)
        base_links = [
            _record_link(
                "interaction-model", "interactions", interaction_pos[interaction_id], interaction_id,
                classification, input_hashes,
            ),
            _record_link(
                "interaction-model", "triggers", trigger_pos[trigger_id], trigger_id,
                _record_classification(trigger), input_hashes,
            ),
            _record_link(
                "interaction-model", "call_slices", slice_pos[call_slice_id], call_slice_id,
                classification, input_hashes,
            ),
        ]
        candidates: list[dict[str, Any] | None] = []
        if classification == "candidate_set":
            candidates.append(_alternative(
                item_identity=interaction_id,
                kind="handler_candidate",
                source_record_id=trigger_id,
                candidates=[
                    *trigger.get("handler_method_ids", []),
                    *trigger.get("handler_function_ids", []),
                ],
                basis="The interaction trigger retains multiple possible handler identities.",
                evidence_links=base_links,
                bounds=bounds,
            ))
        dynamic_targets = [
            edge.get("target_function_id")
            for edge in call_slice.get("edges", [])
            if edge.get("classification") == "candidate_set" and edge.get("target_function_id")
        ]
        if dynamic_targets:
            candidates.append(_alternative(
                item_identity=interaction_id,
                kind="call_target_candidate",
                source_record_id=call_slice_id,
                candidates=dynamic_targets,
                basis="The bounded call slice retains Objective-C dynamic-dispatch target candidates.",
                evidence_links=base_links,
                bounds=bounds,
            ))
        scopes = [str(value) for value in record.get("screen_ids", [])] or [None]
        for scope in scopes:
            add_item(_work_item(
                scope=scope,
                kind="interaction",
                subject_id=interaction_id,
                classification=classification,
                title=f"Interaction {trigger.get('event') or trigger.get('selector') or trigger.get('kind')}",
                details={
                    "trigger_kind": trigger.get("kind"),
                    "event": trigger.get("event"),
                    "selector": trigger.get("selector"),
                    "callback_contract": trigger.get("callback_contract"),
                    "call_slice_truncated": call_slice.get("truncated"),
                },
                related_ids={
                    "screen_ids": record.get("screen_ids", []),
                    "interaction_ids": [interaction_id],
                    "trigger_ids": [trigger_id],
                    "effect_ids": record.get("effect_ids", []),
                    "function_ids": record.get("handler_function_ids", []),
                    "method_ids": record.get("handler_method_ids", []),
                },
                evidence_links=base_links,
                candidate_alternatives=candidates,
                failure_reasons=[
                    *record.get("failure_reasons", []),
                    *call_slice.get("failure_reasons", []),
                ],
                bounds=bounds,
            ))

    for effect in sorted(effects, key=lambda item: str(item.get("id") or "")):
        effect_id = str(effect["id"])
        parent_records = effect_to_interaction.get(effect_id, [])
        parent_classifications = [_record_classification(value) for value in parent_records]
        classification = _classification(
            _record_classification(effect),
            *(parent_classifications or ["unresolved"]),
        )
        kind = EFFECT_ITEM_KIND.get(str(effect.get("kind") or ""), "platform_dependency")
        effect_link = _record_link(
            "interaction-model", "effects", effect_pos[effect_id], effect_id,
            _record_classification(effect), input_hashes,
        )
        dependency_ids = [str(value) for value in effect.get("platform_dependency_ids", [])]
        dependency_links = [
            _record_link(
                "platform-api-map", "dependencies", dependency_pos[value], value,
                _record_classification(dependency_by_id[value]), input_hashes,
            )
            for value in dependency_ids if value in dependency_by_id
        ]
        resources = list((effect.get("details") or {}).get("resource_candidates") or [])
        resource_candidates: list[Any] = []
        for resource in resources:
            if isinstance(resource, dict):
                resource_candidates.extend(resource.get("candidate_ids") or [])
                if resource.get("value") is not None:
                    resource_candidates.append(resource["value"])
            elif resource is not None:
                resource_candidates.append(resource)
        alternatives = []
        if resource_candidates:
            alternatives.append(_alternative(
                item_identity=effect_id,
                kind="resource_candidate",
                source_record_id=effect_id,
                candidates=resource_candidates,
                basis="Function-level resources remain candidates and are not promoted to exact effect arguments.",
                evidence_links=[effect_link],
                bounds=bounds,
            ))
        scopes = sorted({
            *(str(value) for value in effect.get("source_screen_ids", [])),
            *(
                str(screen_id)
                for parent in parent_records
                for screen_id in parent.get("screen_ids", [])
            ),
        }) or [None]
        for scope in scopes:
            add_item(_work_item(
                scope=scope,
                kind=kind,
                subject_id=effect_id,
                classification=classification,
                title=f"{effect.get('kind') or kind} {effect.get('selector') or effect.get('symbol') or effect.get('state_id') or ''}",
                details={
                    "effect_kind": effect.get("kind"),
                    "operation": effect.get("operation"),
                    "selector": effect.get("selector"),
                    "symbol": effect.get("symbol"),
                    "state_id": effect.get("state_id"),
                    "call_site": effect.get("call_site"),
                    "destination_screen_ids": effect.get("destination_screen_ids", []),
                    "effect_details": effect.get("details", {}),
                },
                related_ids={
                    "screen_ids": [
                        *effect.get("source_screen_ids", []),
                        *effect.get("destination_screen_ids", []),
                    ],
                    "interaction_ids": [value.get("id") for value in parent_records],
                    "trigger_ids": [effect.get("trigger_id")],
                    "effect_ids": [effect_id],
                    "function_ids": [effect.get("function_id")],
                    "platform_dependency_ids": dependency_ids,
                },
                evidence_links=[effect_link, *dependency_links],
                candidate_alternatives=alternatives,
                failure_reasons=effect.get("failure_reasons", []),
                bounds=bounds,
            ))

    type_ids_by_function: dict[str, list[str]] = defaultdict(list)
    for function_id, records in objc_values_by_function.items():
        type_ids_by_function[function_id].extend(str(value["id"]) for value in records if value.get("id"))
    for function_id, records in native_values_by_function.items():
        type_ids_by_function[function_id].extend(str(value["id"]) for value in records if value.get("id"))

    for function in sorted(recovered_functions, key=lambda item: str(item.get("function_id") or "")):
        function_id = str(function["function_id"])
        methods = methods_by_function.get(function_id, [])
        class_names = sorted({str(value.get("class_name")) for value in methods if value.get("class_name")})
        type_records = [*objc_values_by_function.get(function_id, []), *native_values_by_function.get(function_id, [])]
        decompilation = function.get("decompilation") or {}
        classification = "exact" if decompilation.get("status") == "success" else "unresolved"
        function_link = _record_link(
            "recovered-code-index", "functions", function_pos[function_id], function_id,
            classification, input_hashes,
        )
        method_links = [
            _record_link(
                "recovered-code-index", "methods", method_pos[str(value["id"])], str(value["id"]),
                "exact", input_hashes,
            )
            for value in methods if value.get("id")
        ]
        class_links = [
            _record_link(
                "recovered-code-index", "classes", class_pos[value], value,
                "exact", input_hashes,
            )
            for value in class_names if value in class_by_name
        ]
        type_links = [
            _record_link(
                "objc-type-flow", "values", objc_value_pos[str(value["id"])], str(value["id"]),
                _record_classification(value), input_hashes,
            )
            for value in objc_values_by_function.get(function_id, []) if value.get("id")
        ] + [
            _record_link(
                "native-type-flow", "values", native_value_pos[str(value["id"])], str(value["id"]),
                _record_classification(value), input_hashes,
            )
            for value in native_values_by_function.get(function_id, []) if value.get("id")
        ]
        code_links = [_pseudocode_link(pseudocode_by_function[function_id])] if function_id in pseudocode_by_function else []
        failures = [] if classification == "exact" else [
            str(decompilation.get("failure_reason") or decompilation.get("status") or "pseudocode_not_available")
        ]
        scopes: list[str | None] = sorted(function_scopes.get(function_id, set())) or [None]
        for scope in scopes:
            item_identity = _stable_id("code-context", scope or "application", function_id)
            add_item(_work_item(
                scope=scope,
                kind="code_unit",
                subject_id=function_id,
                classification=classification,
                title=f"Recovered code unit {function_id}",
                details={
                    "decompilation_status": decompilation.get("status"),
                    "output_path": decompilation.get("output_path"),
                    "method_selectors": [value.get("selector") for value in methods],
                    "referenced_strings": function.get("referenced_strings", []),
                    "referenced_assets": function.get("referenced_assets", []),
                },
                related_ids={
                    "screen_ids": [scope],
                    "function_ids": [function_id],
                    "method_ids": [value.get("id") for value in methods],
                    "class_names": class_names,
                    "type_value_ids": type_ids_by_function.get(function_id, []),
                    "pseudocode_paths": [decompilation.get("output_path")],
                },
                evidence_links=[function_link, *method_links, *class_links, *code_links, *type_links],
                candidate_alternatives=_type_alternatives(
                    item_identity, type_records, type_links, bounds
                ),
                failure_reasons=failures,
                bounds=bounds,
            ))

    for dependency in sorted(platform_dependencies, key=lambda item: str(item.get("id") or "")):
        dependency_id = str(dependency["id"])
        classification = _record_classification(dependency)
        link = _record_link(
            "platform-api-map", "dependencies", dependency_pos[dependency_id], dependency_id,
            classification, input_hashes,
        )
        scope_ids = sorted({
            screen_id
            for function_id in dependency.get("affected_function_ids", [])
            for screen_id in function_scopes.get(str(function_id), set())
        } | {
            str(screen["id"])
            for screen in screens
            if screen.get("controller_class_name") in dependency.get("affected_class_names", [])
        })
        scopes: list[str | None] = scope_ids or [None]
        for scope in scopes:
            add_item(_work_item(
                scope=scope,
                kind="platform_dependency",
                subject_id=dependency_id,
                classification=classification,
                title=f"Platform dependency {dependency.get('symbol') or dependency.get('class_name') or dependency.get('selector') or dependency_id}",
                details={
                    "dependency_kind": dependency.get("kind"),
                    "symbol": dependency.get("symbol"),
                    "class_name": dependency.get("class_name"),
                    "selector": dependency.get("selector"),
                    "frameworks": dependency.get("frameworks", []),
                    "categories": dependency.get("categories", []),
                    "call_sites": dependency.get("call_sites", []),
                },
                related_ids={
                    "screen_ids": [scope],
                    "function_ids": dependency.get("affected_function_ids", []),
                    "method_ids": dependency.get("affected_method_ids", []),
                    "class_names": dependency.get("affected_class_names", []),
                    "platform_dependency_ids": [dependency_id],
                },
                evidence_links=[link],
                candidate_alternatives=[],
                failure_reasons=dependency.get("failure_reasons", []),
                bounds=bounds,
            ))

    represented_type_ids: set[str] = {
        value
        for items in items_by_scope.values()
        for item in items
        for value in item["related_ids"]["type_value_ids"]
    }
    for artifact, collection, records, positions in (
        ("objc-type-flow", "values", objc_values, objc_value_pos),
        ("native-type-flow", "values", native_values, native_value_pos),
    ):
        for value in sorted(records, key=lambda item: str(item.get("id") or "")):
            value_id = str(value.get("id") or "")
            if not value_id or value_id in represented_type_ids:
                continue
            classification = _record_classification(value)
            link = _record_link(
                artifact, collection, positions[value_id], value_id, classification, input_hashes,
            )
            scopes = sorted({
                *function_scopes.get(str(value.get("function_id") or ""), set()),
                *(
                    str(screen["id"])
                    for screen in screens
                    if screen.get("controller_class_name") == value.get("owner_class")
                ),
            }) or [None]
            for scope in scopes:
                add_item(_work_item(
                    scope=scope,
                    kind="type_context",
                    subject_id=value_id,
                    classification=classification,
                    title=f"Type context {value.get('name') or value.get('kind') or value_id}",
                    details={
                        "value_kind": value.get("kind"),
                        "declared_type": value.get("declared_type"),
                        "declared_encoding": value.get("declared_encoding"),
                        "type_candidates": value.get("type_candidates", []),
                    },
                    related_ids={
                        "screen_ids": [scope],
                        "function_ids": [value.get("function_id")],
                        "method_ids": [value.get("method_id"), *value.get("related_objc_method_ids", [])],
                        "class_names": [value.get("owner_class"), *value.get("related_objc_class_names", [])],
                        "type_value_ids": [value_id],
                    },
                    evidence_links=[link],
                    candidate_alternatives=_type_alternatives(value_id, [value], [link], bounds),
                    failure_reasons=value.get("failure_reasons", []),
                    bounds=bounds,
                ))

    for layout in sorted(native_layouts, key=lambda item: str(item.get("id") or "")):
        layout_id = str(layout.get("id") or "")
        if not layout_id:
            continue
        classification = _record_classification(layout)
        link = _record_link(
            "native-type-flow", "layouts", native_layout_pos[layout_id], layout_id,
            classification, input_hashes,
        )
        add_item(_work_item(
            scope=None,
            kind="type_context",
            subject_id=layout_id,
            classification=classification,
            title=f"Native layout {layout_id}",
            details={
                "class_ids": layout.get("class_ids", []),
                "field_ids": layout.get("field_ids", []),
                "size": layout.get("size"),
                "alignment": layout.get("alignment"),
            },
            related_ids={
                "class_names": layout.get("class_ids", []),
                "type_value_ids": layout.get("value_ids", []),
            },
            evidence_links=[link],
            candidate_alternatives=[],
            failure_reasons=layout.get("failure_reasons", []),
            bounds=bounds,
        ))

    for global_record in sorted(native_globals, key=lambda item: str(item.get("id") or "")):
        global_id = str(global_record.get("id") or "")
        if not global_id:
            continue
        classification = _record_classification(global_record)
        link = _record_link(
            "native-type-flow", "globals", native_global_pos[global_id], global_id,
            classification, input_hashes,
        )
        scopes = sorted({
            screen_id
            for reference in global_record.get("references", [])
            for screen_id in function_scopes.get(str(reference.get("function_id") or ""), set())
        }) or [None]
        for scope in scopes:
            add_item(_work_item(
                scope=scope,
                kind="state",
                subject_id=global_id,
                classification=classification,
                title=f"Native global state {global_id}",
                details={
                    "address": global_record.get("address"),
                    "exact_symbols": global_record.get("exact_symbols", []),
                    "type_candidates": global_record.get("type_candidates", []),
                },
                related_ids={
                    "screen_ids": [scope],
                    "function_ids": [value.get("function_id") for value in global_record.get("references", [])],
                    "type_value_ids": [global_record.get("value_id")],
                },
                evidence_links=[link],
                candidate_alternatives=_type_alternatives(global_id, [global_record], [link], bounds),
                failure_reasons=global_record.get("failure_reasons", []),
                bounds=bounds,
            ))

    for artifact in REQUIRED_REPORTS:
        for index, error in enumerate(reports[artifact].get("errors", [])):
            code = str(error.get("code") or "upstream_error")
            subject_id = f"{artifact}:error:{index}:{code}"
            link = _document_link(
                artifact, f"/errors/{index}", subject_id, "unresolved", input_hashes,
            )
            add_item(_work_item(
                scope=None,
                kind="source_issue",
                subject_id=subject_id,
                classification="unresolved",
                title=f"Upstream issue {artifact} {code}",
                details={"artifact": artifact, "error": error},
                related_ids={},
                evidence_links=[link],
                candidate_alternatives=[],
                failure_reasons=[code],
                bounds=bounds,
            ))

    phase_order = {value: index for index, value in enumerate(policy["phase_order"])}
    kind_order = {value: index for index, value in enumerate(policy["work_item_kinds"])}
    screen_order_values = sorted(
        screens,
        key=lambda value: (
            {"main": 0, "launch": 1, "none": 2}.get(str(value.get("entry_point_kind") or "none"), 3),
            str(value.get("id") or ""),
        ),
    )
    screen_order = {str(value["id"]): index for index, value in enumerate(screen_order_values)}
    all_items = [item for items in items_by_scope.values() for item in items]
    for item in all_items:
        classification = str(item["classification"])
        if classification == "exact":
            phase = str(policy["exact_phase_by_kind"][item["kind"]])
            basis = "Exact upstream evidence; ordered by the policy's dependency-neutral implementation phase."
        elif classification == "candidate_set":
            phase = "candidate_validation"
            basis = "Candidate evidence must be validated after exact implementation work."
        else:
            phase = "unresolved_research"
            basis = "Missing evidence must be recovered after exact and candidate-scoped work."
        item["implementation_phase"] = phase
        item["priority_basis"] = basis
    ordered_items = sorted(all_items, key=lambda item: (
        phase_order[item["implementation_phase"]],
        screen_order.get(item["screen_id"], len(screen_order)),
        kind_order[item["kind"]],
        item["subject_id"],
        item["id"],
    ))
    for rank, item in enumerate(ordered_items, 1):
        item["implementation_rank"] = rank

    packets: list[dict[str, Any]] = []
    scope_sequence: list[str | None] = [str(value["id"]) for value in screen_order_values]
    if None in items_by_scope or not scope_sequence:
        scope_sequence.append(None)
    for scope in scope_sequence:
        scope_items = items_by_scope.get(scope, [])
        if not scope_items and scope is not None:
            continue
        screen_name = (
            str(screen_by_id[scope].get("name") or scope)
            if scope is not None else "Application-wide"
        )
        packets.extend(_pack_scope(
            scope=scope,
            screen_name=screen_name,
            items=scope_items,
            policy=policy,
            policy_sha256=policy_sha256,
            input_fingerprint=input_fingerprint,
            bounds=bounds,
        ))

    _assert_inputs_unchanged(workspace, input_artifacts)
    packets_root = _write_packets_atomic(workspace, packets)
    packet_refs: list[dict[str, Any]] = []
    item_to_packet: dict[str, str] = {}
    packet_path_by_id: dict[str, str] = {}
    for packet in sorted(packets, key=lambda value: (
        value["scope"], str(value.get("screen_id") or ""), int(value["sequence"])
    )):
        filename = _packet_filename(packet)
        path = packets_root / filename
        relative = f"handoff/work-packets/{filename}"
        digest = sha256_file(path)
        size = path.stat().st_size
        if size > bounds["max_packet_bytes"]:
            raise HandoffError(f"Written packet {relative} exceeds the configured byte bound")
        packet_path_by_id[packet["id"]] = relative
        for item in packet["work_items"]:
            item_to_packet[item["id"]] = packet["id"]
        packet_refs.append({
            "id": packet["id"],
            "scope": packet["scope"],
            "screen_id": packet["screen_id"],
            "sequence": packet["sequence"],
            "total_sequences": packet["total_sequences"],
            "path": relative,
            "sha256": digest,
            "size": size,
            "work_item_count": packet["summary"]["work_item_count"],
            "classification_counts": packet["summary"]["classification_counts"],
            "work_item_kind_counts": packet["summary"]["work_item_kind_counts"],
            "candidate_alternative_count": packet["summary"]["candidate_alternative_count"],
            "unresolved_question_count": packet["summary"]["unresolved_question_count"],
        })

    packet_refs_by_screen: dict[str | None, list[dict[str, Any]]] = defaultdict(list)
    for packet_ref in packet_refs:
        packet_refs_by_screen[packet_ref["screen_id"]].append(packet_ref)

    def plan_summary(scope: str | None, screen: dict[str, Any] | None = None) -> dict[str, Any]:
        items = sorted(items_by_scope.get(scope, []), key=lambda value: value["implementation_rank"])
        refs = sorted(packet_refs_by_screen.get(scope, []), key=lambda value: value["sequence"])
        classes = Counter(str(value["classification"]) for value in items)
        kinds = Counter(str(value["kind"]) for value in items)
        result = {
            "packet_ids": [value["id"] for value in refs],
            "packet_paths": [value["path"] for value in refs],
            "work_item_count": len(items),
            "classification_counts": {name: classes.get(name, 0) for name in CLASSIFICATIONS},
            "work_item_kind_counts": dict(sorted(kinds.items())),
            "candidate_alternative_count": sum(len(value["candidate_alternatives"]) for value in items),
            "unresolved_question_count": sum(len(value["unresolved_questions"]) for value in items),
            "implementation_rank_start": min((value["implementation_rank"] for value in items), default=None),
            "implementation_rank_end": max((value["implementation_rank"] for value in items), default=None),
        }
        if screen is not None:
            result = {
                "screen_id": scope,
                "screen_name": str(screen.get("name") or scope),
                "classification": _record_classification(screen),
                "controller_class_name": str(screen.get("controller_class_name") or "") or None,
                **result,
            }
        else:
            result = {"scope": "application", **result}
        return result

    screen_plans = [
        plan_summary(str(screen["id"]), screen)
        for screen in screen_order_values
    ]
    application_plan = plan_summary(None)
    implementation_order = [
        {
            "rank": item["implementation_rank"],
            "work_item_id": item["id"],
            "packet_id": item_to_packet[item["id"]],
            "packet_path": packet_path_by_id[item_to_packet[item["id"]]],
            "screen_id": item["screen_id"],
            "kind": item["kind"],
            "classification": item["classification"],
            "phase": item["implementation_phase"],
            "basis": item["priority_basis"],
        }
        for item in ordered_items
    ]
    classifications = Counter(str(item["classification"]) for item in ordered_items)
    kinds = Counter(str(item["kind"]) for item in ordered_items)
    phases = Counter(str(item["implementation_phase"]) for item in ordered_items)
    reasons = Counter(
        reason for item in ordered_items for reason in item.get("failure_reasons", [])
    )
    question_kinds = Counter(
        question["kind"]
        for item in ordered_items
        for question in item["unresolved_questions"]
    )
    summary = {
        "screen_plan_count": len(screen_plans),
        "application_plan_count": 1,
        "packet_count": len(packet_refs),
        "work_item_count": len(ordered_items),
        "pseudocode_artifact_count": len(pseudocode_artifacts),
        "candidate_alternative_count": sum(len(item["candidate_alternatives"]) for item in ordered_items),
        "unresolved_question_count": sum(len(item["unresolved_questions"]) for item in ordered_items),
        "classification_counts": {name: classifications.get(name, 0) for name in CLASSIFICATIONS},
        "work_item_kind_counts": {name: kinds.get(name, 0) for name in policy["work_item_kinds"]},
        "implementation_phase_counts": {name: phases.get(name, 0) for name in policy["phase_order"]},
        "failure_reason_counts": dict(sorted(reasons.items())),
        "question_kind_counts": dict(sorted(question_kinds.items())),
        "error_count": 0,
    }
    bundle = reports["application"]["facts"].get("bundle") or {}
    source_inventory = {
        "archive_asset_count": int(assets_report.get("asset_count") or len(assets_report.get("assets") or [])),
        "ui_asset_count": len(ui_assets),
        "screen_count": len(screens),
        "component_count": len(elements),
        "navigation_count": len(navigation_edges),
        "interaction_count": len(interactions),
        "effect_count": len(effects),
        "recovered_function_count": len(recovered_functions),
        "recovered_method_count": len(recovered_methods),
        "recovered_class_count": len(recovered_classes),
        "objc_type_value_count": len(objc_values),
        "native_type_value_count": len(native_values),
        "native_global_count": len(native_globals),
        "native_layout_count": len(native_layouts),
        "platform_dependency_count": len(platform_dependencies),
        "upstream_hypothesis_count": sum(len(reports[name]["hypotheses"]) for name in REQUIRED_REPORTS),
        "upstream_error_count": sum(len(reports[name]["errors"]) for name in REQUIRED_REPORTS),
    }
    facts = {
        "policy": {
            "catalog_id": policy["catalog_id"],
            "catalog_version": policy["catalog_version"],
            "sha256": policy_sha256,
            "bounds": bounds,
            "phase_order": policy["phase_order"],
            "work_item_kinds": policy["work_item_kinds"],
        },
        "input_artifacts": input_artifacts,
        "input_fingerprint": input_fingerprint,
        "application": {
            "bundle_identifier": str(bundle.get("bundle_identifier") or "") or None,
            "display_name": str(bundle.get("display_name") or bundle.get("bundle_name") or "") or None,
            "version": str(bundle.get("version") or bundle.get("short_version") or "") or None,
            "build_version": str(bundle.get("build_version") or "") or None,
        },
        "source_inventory": source_inventory,
        "summary": summary,
        "screen_plans": screen_plans,
        "application_plan": application_plan,
        "packet_index": packet_refs,
        "implementation_order": implementation_order,
        "pseudocode_artifacts": pseudocode_artifacts,
        "unresolved_summary": [
            {"code": code, "count": count}
            for code, count in sorted(reasons.items())
        ],
        "evidence_boundary": {
            "new_behavioral_inference_introduced": False,
            "names_used_to_invent_behavior": False,
            "candidate_sets_promoted": False,
            "unresolved_items_omitted": False,
            "packets_bounded": True,
            "upstream_artifacts_preserved": True,
            "work_items_claim_original_source_recovery": False,
            "full_evidence_remains_in_upstream_artifacts": True,
        },
    }
    hypotheses = [
        {
            "id": _stable_id("handoff-hypothesis", item["id"]),
            "kind": "candidate_handoff_work_item",
            "work_item_id": item["id"],
            "packet_id": item_to_packet[item["id"]],
            "confidence": "medium",
            "basis": "The source work item retains candidate-set evidence and requires validation.",
        }
        for item in ordered_items if item["classification"] == "candidate_set"
    ]
    manifest = report_envelope("reconstruction-handoff", facts, hypotheses=hypotheses, errors=[])
    manifest_path = workspace / "analysis" / "reconstruction-handoff.json"
    report_path = workspace / "reports" / "reconstruction-handoff-report.md"
    _assert_inputs_unchanged(workspace, input_artifacts)
    write_json_atomic(manifest_path, manifest)
    write_text_atomic(report_path, _render_report(facts))
    _assert_inputs_unchanged(workspace, input_artifacts)
    return HandoffResult(workspace, manifest, manifest_path, packets_root, report_path)
