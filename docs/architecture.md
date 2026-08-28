# IPALift architecture

IPALift is a deterministic evidence pipeline. The core knows about ZIP/IPA,
property lists, Mach-O, and Objective-C runtime metadata; it does not contain
logic for any specific application.

The pipeline layers are:

1. **Source identity** records SHA-256, size, and modification time before work.
2. **Safe archive intake** rejects traversal paths, absolute paths, duplicate
   members, unsafe symbolic links, encrypted entries, and unsafe expansion
   ratios. Internal relative file links are resolved within the archive and
   materialized as regular files with their original link metadata retained.
   A missing internal target is preserved as inert link-payload evidence and
   reported as unresolved; no operating-system symbolic link is created.
3. **Evidence extraction** writes each archive member once and refuses to
   overwrite a conflicting file. The source identity is checked again after
   extraction and reporting.
4. **Mach-O facts** recover slice architecture, headers, segments, sections,
   load commands, imports, exports, libraries, deployment targets, UUIDs,
   entrypoints, and encryption information.
5. **Objective-C facts** recover ObjC2 classes, metaclasses, inheritance,
   instance and class methods, implementation addresses, selectors, ivars,
   properties, protocols, and categories.
6. **Ghidra evidence preparation** verifies the extracted executable hash and
   serializes recovered method names and implementation pointers, Mach-O
   sections/symbols/imports, linked libraries, classes, selectors, and asset
   inventory into a transient input document. ARM/Thumb pointers retain their
   original low-bit value alongside the canonical code address.
7. **Headless program analysis** imports the Mach-O into a transient Ghidra
   project, applies evidence before decompilation, and exports every internal
   and external function, entrypoint, thunk, basic block, outgoing reference,
   call edge, defined string, and per-function decompilation status.
8. **Deterministic normalization** joins Ghidra facts to Objective-C metadata,
   imports, exports, selectors, classes, strings, and assets. Each association
   states its provenance and confidence. Indirect calls and Objective-C message
   dispatch remain explicitly unresolved when no static semantic target exists.
9. **Recovered-code organization** consumes only normalized reports and
   pseudocode. It assigns every discovered function exactly one classification,
   places each Objective-C method in one class/category source view, generates
   protocol declaration views, and inventories unassociated native functions.
   It preserves raw encodings, canonical and Thumb addresses, decompilation
   failures, references, provenance, confidence, and unresolved mappings.
10. **Objective-C dispatch analysis** identifies every message-send runtime
    edge, associates bounded selector and receiver evidence, performs
    class-hierarchy lookup, and emits resolved, candidate-set, or unresolved
    callsite records. Inferred method edges remain separate hypotheses; the
    direct runtime call graph is not rewritten.
11. **Objective-C type flow** creates values for method signatures, ivars,
    properties, Ghidra parameters/locals/returns, and message receivers/results.
    It propagates only supported metadata, hierarchy, dispatch, and explicit
    pseudocode evidence to a deterministic fixed point, retaining cycles,
    candidate sets, provenance, and failure reasons.
12. **Platform API mapping** joins exact Mach-O import ownership, direct Ghidra
    edges and class xrefs, recovered hierarchy/protocol metadata, dispatch
    callsites, and type-flow receiver candidates to an explicit versioned
    ownership/category/callback catalog. It emits exact, candidate-set, and
    unresolved dependencies plus framework/category/component indexes without
    rewriting an input artifact.
13. **C++ ABI object-model recovery** reads the verified executable plus
    normalized Ghidra and Objective-C artifacts to recover documented Itanium
    RTTI layouts, inheritance descriptors, virtual-table groups/address points/
    slots, constructor/destructor variants, mechanical vptr assignments, and a
    complete inventory of non-Objective-C indirect calls. Possible virtual
    targets remain separate hypotheses and every prior graph is preserved.
14. **Native type and data-layout flow** propagates native/C++ parameters,
    returns, locals, globals, object receivers, constructor bindings, explicit
    casts, assignments, and numeric fields to a deterministic fixed point. It
    emits additive receiver-aware virtual refinements and per-function/class/
    global/layout/callsite indexes without rewriting an upstream artifact.
15. **Plugin seam** accepts read-only `PluginContext` objects. Any future
    game-, engine-, or format-specific inference belongs in a plugin.
16. **Reports** separate verified `facts`, inferred `hypotheses`, and `errors`
    in versioned deterministic JSON envelopes.

Gameplay reconstruction, claims of original-source recovery, and Windows-port
scaffolding remain deliberately outside this stage.

## Determinism

Reports contain no timestamps, transient project identifiers, machine-specific
absolute paths, or output-root paths. Records are sorted before serialization,
JSON keys are sorted, UTF-8 and LF are fixed, and report files are atomically
replaced. An identical source, IPALift revision, Ghidra version, and analysis
configuration therefore produce byte-identical normalized reports.

Extracted evidence is not regenerated over conflicting content. A repeated run
may reuse a matching evidence tree, but a mismatch stops analysis.

## Ghidra boundary and failure model

Ghidra is an explicitly configured external analysis engine. IPALift validates
the installation layout and version, invokes `analyzeHeadless` without a GUI,
and requires a completion manifest. The project directory, raw JSON Lines, and
intermediate code are temporary. A non-zero process exit, missing manifest,
omitted eligible function status, or missing successful code file fails the
stage instead of emitting partial normalized reports.

A pre-analysis script disables Ghidra's Objective-C Message Analyzer. That
analyzer can install schedule-dependent call overrides for dynamic message
sends; disabling it makes the raw program model repeatable and preserves the
more honest `objc_msgSend` boundary. IPALift still applies exact recovered
Objective-C names and selectors itself before decompilation. Headless execution
also uses `-max-cpu 1` so analyzer and demangler commits have a fixed order.

`functions.json` is the complete function inventory and includes callers,
callees, blocks, cross-references, ObjC methods, matched imports/exports, and
evidence associations. `callgraph.json` distinguishes address resolution from
semantic resolution. `strings.json` records defined strings and incoming
references. `decompilation.json` records the outcome for every eligible
function; successful pseudocode is stored by canonical address.

## Recovered-code boundary

`recover-objc` does not invoke or modify Ghidra. Its authoritative inputs are
`classes.json`, `functions.json`, `strings.json`, `decompilation.json`,
and the successful per-address pseudocode files named by those reports. Input
report hashes and per-function pseudocode hashes are recorded in
`recovered-code-index.json`.

Class and category views preserve runtime names, hierarchy, protocols, ivars,
properties, method pointers, type encodings, and linked pseudocode. Protocol
records with the same architecture and name are merged into a single view;
every metadata address and declaration occurrence remains explicit. Filesystem
names are sanitized without changing displayed runtime names, with
deterministic hash suffixes when names collide case-insensitively.

The generated Objective-C syntax is an organizational notation. Unknown types
stay `unknown`, argument placeholders are mechanical, and every file says it
is non-original and non-buildable. Failed, timed-out, or unmapped methods get
diagnostic blocks rather than fabricated bodies. Native internal functions
without Objective-C metadata remain in the complete index and in
`recovered/native-functions.md`.

## Objective-C dispatch boundary

`resolve-objc-dispatch` is a deterministic consumer of `callgraph.json`,
`functions.json`, `strings.json`, `recovered-code-index.json`, and the
pseudocode files named by the recovered index. It does not invoke Ghidra and
does not modify `callgraph.json`. Input report hashes and hashes for every
pseudocode artifact used as receiver evidence are recorded in
`objc-dispatch.json`.

Each runtime message-send edge becomes one callsite record keyed by caller and
instruction address. Runtime families include `objc_msgSend`, super sends,
return-convention variants, and related `objc_msgLookup` entrypoints.
Selectors are associated only from Ghidra `PARAM` references after the
previous dispatch and no later than the current callsite. Zero references stay
unresolved; multiple distinct selector references stay a candidate set.

Receiver evidence is intentionally stricter. A decompiled receiver contributes
an exact class-object or `self` context only when every pseudocode call
matching that selector and runtime family has the same mechanically recognized
context and the pseudocode/callsite counts agree. A super send uses its exact
Objective-C caller method and begins lookup at the recovered superclass.
Window-local class references that do not prove an argument position remain
receiver candidates. Unknown variables are never assigned an invented type.

An exact resolution requires one selector, a proven class-object or super
context, and one mapped method at the first defining class in hierarchy lookup.
`self` and statically typed instances remain candidate sets because recovered
subclasses can override the method. Unknown receivers use all locally recovered
implementations of the supported selector as possibilities. No local
implementation produces an explicit unresolved reason rather than an external
or fabricated target.

The original runtime edge remains a direct-call fact. Candidate and resolved
method edges use `objective_c_dynamic_dispatch_inference` and live only in the
report envelope's `hypotheses` array. They are static analysis results, not
proof of a runtime receiver, swizzle state, or observed execution.

## Objective-C type-flow boundary

`infer-objc-types` is a deterministic consumer of `callgraph.json`,
`functions.json`, `strings.json`, `recovered-code-index.json`,
`objc-dispatch.json`, and the successful pseudocode files named by the
recovered index. It does not invoke Ghidra, change pseudocode, or rewrite the
direct call graph.

Values represent method returns and ABI parameters, ivars, properties,
function returns and parameters, locals, exact ivar accesses, message
receivers, and message results. Evidence roots are limited to Objective-C
method/property/ivar encodings; recovered class, metaclass, hierarchy, and
protocol records; exact self/super context; explicit class `alloc`; formal
`new` and `init` method-family conventions; Ghidra declarations, explicit
casts, assignments, returns, and exact class/ivar cross-references; and already
resolved or retained dispatch targets.

Each propagation edge records its source and target value, evidence basis,
confidence, hypothesis status, source artifact, and source address when one is
available. Candidate paths never become exact merely because only one class or
method survives. Static Objective-C class types include recovered subclasses.
Protocol-only types, casts, ambiguous dispatch targets, bounded ivar-to-receiver
associations, and `new`/`init` conventions remain hypotheses. An explicit
class-object `alloc` receiver is the only allocation convention promoted to
an exact result class.

The solver uses stable node/edge ordering and a bounded monotone fixed point.
Strongly connected components and self-cycles are reported explicitly; a cycle
without supported incoming evidence remains unresolved. The artifact contains
the chosen evidence path for every retained candidate, plus complete evidence
and propagation inventories so results can be audited back to metadata or
pseudocode.

Optional dispatch feedback is additive. The type-flow artifact fingerprints a
projection containing only the original dispatch callsite fields and original
`objective_c_dynamic_dispatch_inference` edges. A later
`resolve-objc-dispatch` run applies refinements only when that projection
matches exactly. It writes separate refined receiver/classification/target
fields while preserving the original receiver, classification, possible
targets, hypotheses, and `callgraph.json`. Baseline super callsites are
excluded from the overlay because their exact evidence describes a lookup
starting class, not an ordinary runtime instance type.

Variable names, gameplay meaning, arbitrary selector semantics, and unsupported
naming conventions are never evidence. Ghidra declarations and pseudocode are
analysis outputs, not claims about original source.

## Platform API mapping boundary

`map-platform-apis` is a deterministic, read-derived consumer of the normalized
Mach-O, Ghidra, recovered Objective-C, dispatch, and type-flow artifacts. It
records hashes for all seven JSON inputs, every inspected pseudocode artifact,
and the bundled platform catalog. It does not invoke Ghidra or modify the call
graph, dispatch decisions, type-flow values, or recovered views.

Mach-O library ordinals are the only linkage-owner proof for imported native
functions and imported Objective-C class symbols. Exact Ghidra thunk edges link
direct native callsites to those imports; exact `_OBJC_CLASS_$_` xrefs link app
functions to external class references. An invalid or special ordinal stays
unresolved even if a symbol name resembles a familiar API.

Objective-C message ownership requires explicit receiver evidence. A one-to-one
pseudocode class-object receiver may be exact. Class-object or super type-flow
evidence may be exact when the refinement is exact; ordinary instance receivers
and ambiguous class sets remain candidates because dynamic subclasses and
runtime types are not proven. Calls with only recovered local targets are
indexed as application-local. A call with neither an external receiver owner
nor a local target remains unresolved rather than being guessed external.

Superclass overrides and protocol callbacks require an exact recovered method,
an exact recovered hierarchy or conformance path, and an exact selector listed
in the versioned catalog. Categories are assigned only by catalog records.
Selectors, symbol names, strings, and application names never create behavior
or gameplay semantics. The stage emits an inventory and indexes only—never a
Windows compatibility shim or reconstructed implementation.

## C++ ABI object-model boundary

`recover-cpp-model` is a deterministic consumer of `application.json`,
`architectures.json`, `functions.json`, `callgraph.json`,
`recovered-code-index.json`, `objc-dispatch.json`, `objc-type-flow.json`,
`platform-api-map.json`, the verified extracted executable, and successful
pseudocode named by the recovered index. It does not invoke Ghidra or rewrite
any upstream analysis artifact.

The stage implements only documented Itanium C++ ABI structures selected by
exact binary evidence: `_ZTI`, `_ZTS`, and `_ZTV` symbols; relocations to the
three supported RTTI runtime layouts; pointer-sized headers, base descriptors,
address points, and slots; exact function addresses; and ABI constructor/
destructor variants. ARM/Thumb targets are canonicalized only by clearing the
architectural low state bit. All architecture, pointer-width, endianness,
extent, and unsupported-layout assumptions are recorded in the artifact.

A Ghidra pseudocode vptr store is retained only when mechanically
dereferencing its literal `PTR_*_<address>` cell plus constant offset equals a
validated ABI address point. It becomes exact only inside an exact ABI special
member for the same recovered class; other stores remain candidates. A virtual
call form supplies only a pointer-aligned slot number. It is associated with
instruction call edges only when the function has one of each, or when counts
match and every form has the same offset. Other indirect calls remain
explicitly unresolved.

Exact virtual-table slots are facts. Callsite target edges are additive
hypotheses and never replace the direct graph. A unique slot target is not
promoted without receiver-vtable proof. Construction tables, VTTs, covariant
thunks, unsupported RTTI/compiler extensions, ambiguous pseudocode-to-
instruction ordering, and direct function pointers remain unresolved until a
documented layout and explicit evidence support them.

Names are retained as ABI identities and may be mechanically decoded for
display; they do not establish behavior, semantics, class relationships, or
dispatch. Strings, Objective-C selectors, call proximity, application names,
and validation-target details never create C++ evidence. Cross-language links
only report exact shared function/method identifiers already present in the
normalized artifacts.

## Native type and data-layout boundary

`infer-native-types` is a deterministic consumer of `application.json`,
`architectures.json`, `functions.json`, `callgraph.json`,
`recovered-code-index.json`, `objc-dispatch.json`, `objc-type-flow.json`,
`platform-api-map.json`, `cpp-object-model.json`, the verified executable, and
successful pseudocode named by the recovered index. It invokes no external
analyzer and preserves every upstream artifact byte for byte.

The value graph covers function returns and ABI parameters, locals, globals,
field storage, C++ receivers, vptr objects, and virtual-call receivers. Roots
are limited to existing Objective-C type-flow candidates, Ghidra declarations,
explicit casts, exact ABI special-member identities, verified vptr stores,
exact constructor call bindings, exact symbol addresses, typed dereferences,
and validated vtable pointer cells. Edges require direct whole-value
assignments/returns, exact direct-call identity and ABI position, exact field
read/write syntax, or a mechanically associated virtual receiver.

The solver is monotone and deterministically ordered. Every retained type has
one auditable evidence path; strongly connected components are explicit and a
cycle without supported incoming evidence remains unresolved. Generic Ghidra
pointer declarations can be superseded by proven runtime C++ evidence, but an
explicit named cast remains a candidate and can prevent an exact result.
Unsupported C++ ABI class records are listed separately and never seed values,
inheritance expansion, vtable slots, constructor bindings, globals, or target
refinements.

Numeric field offsets and widths are recovered only from mechanically parsed
pointer arithmetic or decompiler field forms. Fields have no invented names.
A layout is class-associated only through receiver type evidence; ambiguous
owners remain candidate sets and unknown owners remain anonymous/unresolved.
Globals require exact in-image addresses and retain every pseudocode reference
and exact Mach-O symbol at that address.

A virtual refinement becomes exact only when a preceding exact vptr assignment
proves one runtime class and its supported slot proves one function target.
Static C++ types expand through exact recovered descendants and remain
candidates even if they narrow to a unique target. Refined edges live only in
the native report envelope's `hypotheses` array. Names, strings, selectors,
call proximity, validation-target details, and application concepts never
create type, class, field, behavior, or target evidence.
