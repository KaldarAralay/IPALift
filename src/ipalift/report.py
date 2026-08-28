"""Concise deterministic human-readable reporting."""

from __future__ import annotations

from typing import Any


def render_report(
    application: dict[str, Any],
    architectures: dict[str, Any],
    frameworks: dict[str, Any],
    classes: dict[str, Any],
    assets: dict[str, Any],
    unresolved: dict[str, Any],
) -> str:
    bundle = application["bundle"]
    source = application["source"]
    architecture_items = architectures["architectures"]
    objc_items = classes["architectures"]
    lines = [
        "# IPALift analysis report",
        "",
        "## Application",
        "",
        f"- Display name: {bundle.get('display_name') or 'unknown'}",
        f"- Bundle identifier: {bundle.get('bundle_identifier') or 'unknown'}",
        f"- Bundle version: {bundle.get('bundle_version') or 'unknown'}",
        f"- Executable: {bundle.get('executable_name') or 'unknown'}",
        f"- Minimum iOS version (Info.plist): {bundle.get('minimum_os_version') or 'unknown'}",
        f"- Source SHA-256: `{source['sha256']}`",
        f"- Source preserved unchanged: {'yes' if source['preserved_unchanged'] else 'no'}",
        "",
        "## Executable",
        "",
    ]
    for item in architecture_items:
        encryption = item["encryption"]
        if encryption["command_present"]:
            encrypted = "yes" if encryption["is_encrypted"] else "no"
        else:
            encrypted = "unknown (no encryption command)"
        target = item.get("deployment_target")
        target_text = (
            f"{target['platform']} {target['minimum_version']} (SDK {target['sdk']})" if target else "not declared in Mach-O"
        )
        lines.extend([
            f"### {item['architecture']}",
            "",
            f"- Format: {item['bits']}-bit {item['endianness']}-endian {item['magic']}",
            f"- File type: {item['file_type_name']}",
            f"- Deployment target: {target_text}",
            f"- Encrypted: {encrypted}",
            f"- Imports: {len(item['imports'])}",
            f"- Exports: {len(item['exports'])}",
            "",
        ])
    framework_names = [item["name"] for item in frameworks["linked_libraries"]]
    lines.extend([
        "## Recovered Objective-C structure",
        "",
    ])
    for item in objc_items:
        method_count = sum(
            len(record["instance_methods"]) + len(record["class_methods"])
            for record in item["classes"]
        ) + sum(
            len(record["instance_methods"]) + len(record["class_methods"])
            for record in item["categories"]
        )
        lines.extend([
            f"- {item['architecture']}: {item['class_count']} classes, {item['category_count']} categories, "
            f"{item['protocol_count']} protocols, {item['selector_count']} selectors, {method_count} methods",
        ])
    lines.extend([
        "",
        "## Linked frameworks and libraries",
        "",
        f"Count: {frameworks['linked_library_count']}",
        "",
    ])
    lines.extend(f"- {name}" for name in framework_names)
    category_counts = assets["category_counts"]
    lines.extend([
        "",
        "## Bundle inventory",
        "",
        f"- Files: {assets['file_count']}",
        f"- Assets: {assets['asset_count']}",
        f"- Uncompressed bytes: {assets['total_uncompressed_bytes']}",
    ])
    for category, count in sorted(category_counts.items()):
        lines.append(f"- {category}: {count}")
    lines.extend([
        "",
        "## Unresolved findings",
        "",
    ])
    if unresolved["item_count"]:
        for item in unresolved["items"]:
            lines.append(f"- [{item['severity']}] {item['code']}: {item['message']}")
    else:
        lines.append("No unresolved findings were recorded.")
    lines.extend([
        "",
        "## Evidence",
        "",
        "Machine-readable facts are in `analysis/*.json`; preserved extracted files are in `evidence/extracted/`.",
        "Hypotheses and errors are separate top-level arrays in every JSON artifact.",
        "",
    ])
    return "\n".join(lines)


def render_decompilation_report(
    functions: dict[str, Any],
    callgraph: dict[str, Any],
    strings: dict[str, Any],
    decompilation: dict[str, Any],
    unresolved_items: list[dict[str, Any]],
) -> str:
    """Render a deterministic coverage summary for the headless Ghidra stage."""
    ghidra = functions["ghidra"]
    lines = [
        "# IPALift decompilation report",
        "",
        "## Analysis engine",
        "",
        f"- Ghidra: {ghidra.get('version') or 'unknown'}",
        f"- Language: {ghidra.get('language_id') or 'unknown'}",
        f"- Compiler specification: {ghidra.get('compiler_spec_id') or 'unknown'}",
        f"- Executable format: {ghidra.get('executable_format') or 'unknown'}",
        f"- Image base: {ghidra.get('image_base') or 'unknown'}",
        "",
        "## Function discovery",
        "",
        f"- All discovered functions: {functions['discovered_function_count']}",
        f"- Internal functions: {functions['internal_function_count']}",
        f"- External functions: {functions['external_function_count']}",
        f"- Entrypoints: {functions['entrypoint_count']}",
        f"- Thunks: {functions['thunk_count']}",
        f"- Objective-C method records supplied: {functions['objective_c_method_record_count']}",
        f"- Objective-C implementation addresses supplied: {functions['objective_c_unique_implementation_count']}",
        f"- Objective-C implementation addresses not mapped: {functions['objective_c_missing_function_count']}",
        f"- Mach-O imports matched to external functions: {functions['macho_import_function_match_count']}/{functions['macho_import_count']}",
        f"- Mach-O exports matched to internal functions: {functions['macho_export_function_match_count']}/{functions['macho_export_count']}",
        "",
        "## Decompilation coverage",
        "",
        f"- Eligible internal non-thunk functions: {decompilation['eligible_internal_non_thunk_count']}",
        f"- Attempted: {decompilation['attempted_count']}",
        f"- Successful: {decompilation['success_count']}",
        f"- Failed: {decompilation['failure_count']}",
        f"- Timed out: {decompilation['timeout_count']}",
        f"- Success coverage: {decompilation['success_coverage']:.2%}",
        "",
        "## Recovered relationships",
        "",
        f"- Call edges: {callgraph['edge_count']}",
        f"- Statically resolved function edges: {callgraph['resolved_function_edge_count']}",
        f"- Semantically resolved edges: {callgraph['semantic_resolved_edge_count']}",
        f"- Unresolved indirect or dynamic edges: {callgraph['unresolved_edge_count']}",
        f"- Objective-C dispatch edges: {callgraph['objective_c_dispatch_edge_count']}",
        f"- Defined strings: {strings['string_count']}",
        f"- Selector strings: {strings['selector_string_count']}",
        f"- Strings matched to bundle assets: {strings['asset_matched_string_count']}",
        "",
        "## Unresolved findings",
        "",
    ]
    ghidra_items = [item for item in unresolved_items if str(item.get("code", "")).startswith("ghidra_")]
    if ghidra_items:
        for item in ghidra_items:
            suffix = f" ({item['count']})" if item.get("count") is not None else ""
            address = f" at {item['address']}" if item.get("address") else ""
            lines.append(f"- [{item['severity']}] {item['code']}{address}{suffix}: {item['message']}")
    else:
        lines.append("No Ghidra-stage unresolved findings were recorded.")
    lines.extend([
        "",
        "## Evidence",
        "",
        "Every discovered function is recorded in `analysis/functions.json`. Call edges and unresolved dynamic targets are in `analysis/callgraph.json`.",
        "Per-function status is in `analysis/decompilation.json`; successful pseudocode is in `decompiled/functions/`.",
        "Recovered associations include explicit provenance and confidence rather than inferred source-level certainty.",
        "",
    ])
    return "\n".join(lines)


def render_objc_recovery_report(facts: dict[str, Any]) -> str:
    """Render deterministic coverage for the recovered Objective-C views."""
    classifications = facts["classification_counts"]
    statuses = facts["method_decompilation_status_counts"]
    lines = [
        "# IPALift Objective-C recovery report",
        "",
        "> Evidence-organized metadata and Ghidra pseudocode. This is not original source and is not buildable.",
        "",
        "## Coverage",
        "",
        f"- Discovered functions indexed: {facts['function_count']}",
        f"- Objective-C method functions: {classifications['objective_c_method']}",
        f"- Unassociated native internal functions: {classifications['native_internal_function']}",
        f"- Thunks: {classifications['thunk']}",
        f"- External functions: {classifications['external_function']}",
        f"- Objective-C method records: {facts['objective_c_method_count']}",
        f"- Mapped Objective-C method records: {facts['mapped_objective_c_method_count']}",
        f"- Unresolved Objective-C method records: {facts['unresolved_objective_c_method_count']}",
        f"- Classes: {facts['class_count']}",
        f"- Categories: {facts['category_count']}",
        f"- Protocols: {facts['protocol_count']}",
        f"- Protocol metadata records merged into those views: {facts['protocol_metadata_record_count']}",
        "",
        "## Objective-C method decompilation",
        "",
    ]
    if statuses:
        for status, count in sorted(statuses.items()):
            lines.append(f"- {status}: {count}")
    else:
        lines.append("- No Objective-C method records were recovered.")
    lines.extend([
        "",
        "## Failed or timed-out functions",
        "",
    ])
    failed = facts["failed_or_timed_out_functions"]
    if failed:
        for function in failed:
            result = function["decompilation"]
            lines.append(
                f"- `{function.get('address') or function['function_id']}` "
                f"{function.get('full_name') or function.get('name') or 'unnamed'}: "
                f"{result['status']} — {str(result.get('message') or 'no diagnostic').strip()}"
            )
    else:
        lines.append("No failed or timed-out functions were recorded.")
    lines.extend([
        "",
        "## Unresolved Objective-C mappings",
        "",
    ])
    unresolved = facts["unresolved_methods"]
    if unresolved:
        for method in unresolved:
            lines.append(
                f"- `{method['implementation_pointer']}` {method['exact_name']}: {method['mapping_reason']}"
            )
    else:
        lines.append("Every recovered Objective-C method record maps to a discovered function.")
    lines.extend([
        "",
        "## Generated views",
        "",
        f"- Generated files: {facts['generated_file_count']}",
        "- Class declarations and pseudocode: `recovered/objc/classes/`",
        "- Category declarations and pseudocode: `recovered/objc/categories/`",
        "- Protocol declarations and evidence views: `recovered/objc/protocols/`",
        "- Unassociated native function inventory: `recovered/native-functions.md`",
        "- Complete machine-readable index: `analysis/recovered-code-index.json`",
        "",
        "All generated `.h` and `.m` files carry an explicit non-original, non-buildable warning.",
        "No gameplay behavior, semantic names, dynamic dispatch targets, or porting code are invented.",
        "",
    ])
    return "\n".join(lines)


def render_objc_dispatch_report(facts: dict[str, Any]) -> str:
    """Render deterministic coverage for Objective-C dispatch inference."""
    classifications = facts["classification_counts"]
    selectors = facts["selector_status_counts"]
    receivers = facts["receiver_status_counts"]
    lines = [
        "# IPALift Objective-C dispatch report",
        "",
        "> Static dispatch hypotheses over recovered metadata. These are not original source or runtime observations.",
        "",
        "## Coverage",
        "",
        f"- Direct call-graph edges examined: {facts['direct_callgraph_edge_count']}",
        f"- Objective-C runtime dispatch callsites: {facts['dispatch_callsite_count']}",
        f"- Resolved callsites: {classifications['resolved']}",
        f"- Candidate-set callsites: {classifications['candidate_set']}",
        f"- Unresolved callsites: {classifications['unresolved']}",
        f"- Inferred target edges: {facts['inferred_edge_count']}",
        f"- Resolved inferred edges: {facts['resolved_inferred_edge_count']}",
        f"- Candidate inferred edges: {facts['candidate_inferred_edge_count']}",
        f"- Type-flow refinement available: {str(facts['type_flow_refinement_available']).lower()}",
        f"- Type-flow refinements applied: {facts['type_flow_refinement_count']}",
        f"- Type-flow refinements changing receiver or targets: {facts['type_flow_changed_count']}",
        "",
        "## Static evidence",
        "",
        f"- Selectors resolved: {selectors['resolved']}",
        f"- Selector candidate sets: {selectors['candidate_set']}",
        f"- Selectors unresolved: {selectors['unresolved']}",
        f"- Receiver contexts resolved: {receivers['resolved']}",
        f"- Receiver candidate sets: {receivers['candidate_set']}",
        f"- Receiver contexts unresolved: {receivers['unresolved']}",
        f"- Pseudocode artifacts used as evidence: {facts['pseudocode_artifact_count']}",
        "",
        "## Runtime variants",
        "",
    ]
    for name, count in facts["runtime_variant_counts"].items():
        lines.append(f"- {name}: {count}")
    lines.extend([
        "",
        "## Classification rules",
        "",
        "- `resolved` requires one selector, a statically proven class-object or super context, and one mapped method from hierarchy lookup.",
        "- `candidate_set` preserves every recovered method still possible under the supported evidence.",
        "- `unresolved` records why no local method target can be supported.",
        "- A `self` or typed receiver remains a candidate set because subclasses can override the selected method.",
        "",
        "## Unresolved and uncertainty reasons",
        "",
    ])
    if facts["unresolved_reason_counts"]:
        for reason, count in facts["unresolved_reason_counts"].items():
            lines.append(f"- {reason}: {count}")
    else:
        lines.append("No unresolved or candidate uncertainty reasons were recorded.")
    lines.extend([
        "",
        "## Evidence boundary",
        "",
        "`analysis/callgraph.json` remains the unchanged direct graph to Objective-C runtime entrypoints.",
        "Inferred target edges are separate hypotheses in the top-level `hypotheses` array of `analysis/objc-dispatch.json`.",
        "Every callsite retains its runtime edge, selector and receiver evidence, confidence, provenance, candidates, and explicit failure reasons.",
        "No selector, receiver type, target method, gameplay behavior, or runtime observation is invented.",
        "",
    ])
    return "\n".join(lines)


def render_objc_type_flow_report(facts: dict[str, Any]) -> str:
    """Render deterministic coverage for evidence-bounded type flow."""
    classifications = facts["classification_counts"]
    fixed_point = facts["fixed_point"]
    lines = [
        "# IPALift Objective-C type-flow report",
        "",
        "> Static types recovered from explicit metadata and Ghidra evidence. This is not original source or runtime observation.",
        "",
        "## Coverage",
        "",
        f"- Type values analyzed: {facts['value_count']}",
        f"- Exact values: {classifications['exact']}",
        f"- Candidate-set values: {classifications['candidate_set']}",
        f"- Unresolved values: {classifications['unresolved']}",
        f"- Evidence records: {facts['evidence_count']}",
        f"- Propagation steps: {facts['propagation_step_count']}",
        f"- Dispatch receiver values: {facts['dispatch_receiver_value_count']}",
        f"- Dispatch refinements: {facts['dispatch_refinement_count']}",
        f"- Changed dispatch refinements: {facts['changed_dispatch_refinement_count']}",
        "",
        "## Fixed point",
        "",
        f"- Converged: {str(fixed_point['converged']).lower()}",
        f"- Iterations: {fixed_point['iteration_count']}",
        f"- Cyclic components: {fixed_point['cyclic_component_count']}",
        f"- Values in cycles: {fixed_point['cyclic_value_count']}",
        "",
        "## Value kinds",
        "",
    ]
    for name, count in facts["value_kind_counts"].items():
        lines.append(f"- {name}: {count}")
    lines.extend([
        "",
        "## Unresolved and uncertainty reasons",
        "",
    ])
    if facts["unresolved_reason_counts"]:
        for reason, count in facts["unresolved_reason_counts"].items():
            lines.append(f"- {reason}: {count}")
    else:
        lines.append("No unresolved or candidate uncertainty reasons were recorded.")
    lines.extend([
        "",
        "## Evidence boundary",
        "",
        "Exact types require non-hypothetical evidence; subclassable, protocol-only, init/factory-convention, and ambiguous flows remain candidate sets.",
        "Variable names, selector semantics, gameplay concepts, and unsupported naming conventions never create type evidence.",
        "Init/new-family conventions remain hypotheses; explicit class alloc is exact only when class-object evidence proves the receiver class.",
        "Ghidra pseudocode is treated only as analysis evidence and is never represented as original source.",
        "Dispatch refinements are optional evidence records; the baseline dispatch classification, target set, and direct call graph remain preserved.",
        "",
    ])
    return "\n".join(lines)


def render_platform_api_map_report(facts: dict[str, Any]) -> str:
    """Render deterministic compatibility-planning platform dependency coverage."""
    summary = facts["summary"]
    classifications = summary["classification_counts"]
    statuses = summary["message_status_counts"]
    catalog = facts["catalog"]
    lines = [
        "# IPALift platform API map report",
        "",
        "> Evidence-linked platform dependencies for compatibility planning. This report does not infer gameplay or provide reconstructed implementations.",
        "",
        "## Coverage",
        "",
        f"- Linked libraries: {summary['linked_library_count']}",
        f"- Imported symbols: {summary['imported_symbol_count']}",
        f"- Exact external class references: {summary['external_class_reference_count']}",
        f"- Objective-C message callsites: {summary['message_callsite_count']}",
        f"- Catalog-backed callback dependencies: {summary['callback_dependency_count']}",
        f"- Platform dependency records: {summary['dependency_count']}",
        f"- Exact: {classifications['exact']}",
        f"- Candidate sets: {classifications['candidate_set']}",
        f"- Unresolved: {classifications['unresolved']}",
        "",
        "## Objective-C message boundaries",
        "",
        f"- Exact external messages: {statuses['external_exact']}",
        f"- Candidate external messages: {statuses['external_candidate']}",
        f"- Application-local messages: {statuses['application_local']}",
        f"- Unresolved messages: {statuses['unresolved']}",
        "",
        "## Dependency kinds",
        "",
    ]
    for name, count in summary["dependency_kind_counts"].items():
        lines.append(f"- {name}: {count}")
    lines.extend([
        "",
        "## Framework index",
        "",
    ])
    if facts["indexes"]["frameworks"]:
        for item in facts["indexes"]["frameworks"]:
            lines.append(
                f"- {item['framework']}: {len(item['dependency_ids'])} dependencies; "
                f"{len(item['function_ids'])} functions; {len(item['method_ids'])} methods; "
                f"{len(item['class_names'])} classes"
            )
    else:
        lines.append("No framework owner was proven.")
    lines.extend([
        "",
        "## Category index",
        "",
    ])
    if facts["indexes"]["categories"]:
        for item in facts["indexes"]["categories"]:
            lines.append(
                f"- {item['category']}: {len(item['dependency_ids'])} dependencies across "
                f"{len(item['frameworks'])} frameworks"
            )
    else:
        lines.append("No cataloged category was assigned.")
    lines.extend([
        "",
        "## Unresolved and uncertainty reasons",
        "",
    ])
    if summary["failure_reason_counts"]:
        for reason, count in summary["failure_reason_counts"].items():
            lines.append(f"- {reason}: {count}")
    else:
        lines.append("No unresolved or candidate uncertainty reasons were recorded.")
    lines.extend([
        "",
        "## Catalog and evidence boundary",
        "",
        f"- Catalog: `{catalog['catalog_id']}` version `{catalog['catalog_version']}`",
        f"- Catalog SHA-256: `{catalog['sha256']}`",
        "- Framework ownership and categories are emitted only from exact Mach-O linkage or an explicit catalog record.",
        "- Instance receiver ambiguity remains a candidate set; unknown ownership remains unresolved.",
        "- Superclass overrides and protocol callbacks require exact recovered metadata plus an exact cataloged selector contract.",
        "- Selectors, names, and strings do not create gameplay or behavioral claims.",
        "- The direct call graph, Objective-C dispatch report, and type-flow report remain unchanged inputs.",
        "- No Windows shim or reconstructed platform implementation is emitted.",
        "",
        "Machine-readable evidence, provenance, confidence, failure reasons, and all indexes are in `analysis/platform-api-map.json`.",
        "",
    ])
    return "\n".join(lines)


def render_cpp_object_model_report(facts: dict[str, Any]) -> str:
    """Render deterministic C++ ABI recovery coverage and evidence limits."""
    summary = facts["summary"]
    classifications = summary["classification_counts"]
    lines = [
        "# IPALift C++ object-model report",
        "",
        "> Evidence-bounded recovery of documented compiler ABI structures. This is not original source and does not infer application behavior.",
        "",
        "## Coverage",
        "",
        f"- Classes: {summary['class_count']}",
        f"- RTTI records: {summary['rtti_record_count']}",
        f"- Inheritance relationships: {summary['inheritance_relationship_count']}",
        f"- Virtual-table groups: {summary['vtable_count']}",
        f"- Virtual-table address points: {summary['address_point_count']}",
        f"- Virtual-table slots: {summary['vtable_slot_count']}",
        f"- Constructor/destructor ABI symbols: {summary['special_member_function_count']}",
        f"- Object-to-vtable assignments: {summary['vtable_assignment_count']}",
        f"- Non-Objective-C indirect callsites: {summary['indirect_callsite_count']}",
        f"- Mechanically recognized virtual callsites: {summary['virtual_callsite_count']}",
        f"- Separate virtual-target hypothesis edges: {summary['hypothesis_edge_count']}",
        f"- Exact records: {classifications['exact']}",
        f"- Candidate-set records: {classifications['candidate_set']}",
        f"- Unresolved records: {classifications['unresolved']}",
        "",
        "## ABI assumptions",
        "",
    ]
    for abi in facts["abi_records"]:
        lines.append(f"- {abi['name']}: {abi['primary_source']}")
        for assumption in abi["assumptions"]:
            lines.append(f"  - {assumption}")
    lines.extend(["", "## Uncertainty and failure reasons", ""])
    if summary["failure_reason_counts"]:
        for reason, count in summary["failure_reason_counts"].items():
            lines.append(f"- {reason}: {count}")
    else:
        lines.append("No uncertainty or unresolved reasons were recorded.")
    lines.extend([
        "",
        "## Evidence boundary",
        "",
        "- Exact structure claims require defined ABI symbols, relocations, pointer layouts, or exact function-address matches.",
        "- Pseudocode contributes only mechanical pointer-cell stores and virtual-slot offset forms.",
        "- Names, strings, selectors, call proximity, and application-specific concepts never create behavior or class evidence.",
        "- Unsupported ABI/compiler structures remain unresolved; construction tables, VTTs, thunks, and extensions are not guessed.",
        "- Virtual-target edges are hypotheses kept separate from the unchanged direct call graph.",
        "- Objective-C dispatch, Objective-C type flow, and the platform API map remain unchanged inputs.",
        "",
        "Machine-readable records, provenance, confidence, failures, and class/vtable/function/callsite indexes are in `analysis/cpp-object-model.json`.",
        "",
    ])
    return "\n".join(lines)


def render_native_type_flow_report(facts: dict[str, Any]) -> str:
    """Render native type, layout, global, and virtual-refinement coverage."""
    summary = facts["summary"]
    value_counts = summary["classification_counts"]
    layout_counts = summary["layout_classification_counts"]
    refinement_counts = summary["virtual_refinement_classification_counts"]
    lines = [
        "# IPALift native type-flow report",
        "",
        "> Architecture-aware native/C++ types and numeric layouts derived from preserved evidence. This report does not recover original source or infer behavior.",
        "",
        "## Coverage",
        "",
        f"- Native values: {summary['value_count']}",
        f"- Exact values: {value_counts['exact']}",
        f"- Candidate-set values: {value_counts['candidate_set']}",
        f"- Unresolved values: {value_counts['unresolved']}",
        f"- Globals: {summary['global_count']}",
        f"- Numeric field accesses: {summary['field_access_count']}",
        f"- Recovered fields: {summary['field_count']}",
        f"- Data layouts: {summary['layout_count']} ({layout_counts['exact']} exact, {layout_counts['candidate_set']} candidate, {layout_counts['unresolved']} unresolved)",
        f"- C++ virtual refinements: {summary['virtual_refinement_count']} ({summary['changed_virtual_refinement_count']} changed)",
        f"- Refined exact/candidate/unresolved: {refinement_counts['exact']}/{refinement_counts['candidate_set']}/{refinement_counts['unresolved']}",
        f"- Evidence records: {summary['evidence_count']}",
        f"- Propagation steps: {summary['propagation_step_count']}",
        f"- Cyclic components: {facts['fixed_point']['cyclic_component_count']}",
        f"- Unsupported C++ ABI classes quarantined: {summary['unsupported_cpp_class_count']}",
        "",
        "## Architecture and ABI assumptions",
        "",
    ]
    for architecture in facts["architecture_records"]:
        lines.append(
            f"- {architecture['name']}: {architecture['bits']}-bit, "
            f"{architecture['endianness']}-endian, {architecture['pointer_size']}-byte pointers, "
            f"{architecture['cpp_abi']}"
        )
        for assumption in architecture["assumptions"]:
            lines.append(f"  - {assumption}")
    lines.extend(["", "## Uncertainty and failure reasons", ""])
    if summary["failure_reason_counts"]:
        for reason, count in summary["failure_reason_counts"].items():
            lines.append(f"- {reason}: {count}")
    else:
        lines.append("No uncertainty or unresolved reasons were recorded.")
    lines.extend([
        "",
        "## Evidence boundary",
        "",
        "- Existing Objective-C type-flow candidates are retained with their original evidence identities and uncertainty.",
        "- Exact C++ identity requires ABI special-member evidence, a mechanically verified vptr store, or an exact constructor receiver binding.",
        "- Numeric offsets and widths are structural evidence; no semantic field name is invented.",
        "- Static C++ types include recovered descendants unless an exact preceding vptr store proves one runtime table.",
        "- Virtual refinements and target edges are additive and never rewrite the C++ object model or direct call graph.",
        "- Variable names, strings, selectors, application concepts, and call proximity never create class or behavior evidence.",
        "- Unsupported C++ ABI classes are inventoried but never seed native values, layouts, or virtual targets.",
        "",
        "Machine-readable values, layouts, globals, evidence paths, cycles, refinements, and indexes are in `analysis/native-type-flow.json`.",
        "",
    ])
    return "\n".join(lines)
