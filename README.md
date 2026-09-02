# IPALift

IPALift turns a legally obtained, decrypted iOS IPA into a deterministic,
evidence-linked reverse-engineering workspace. It inventories the application,
analyzes Mach-O and Objective-C metadata, runs Ghidra headlessly, organizes
pseudocode, and builds conservative Objective-C, platform API, C++, native
type, user-interface, interaction, behavioral-contract, and application-state models, then packages them into a reconstruction handoff.

IPALift does not decrypt App Store binaries, recover original source code, or
infer gameplay from names. Facts, hypotheses, and unresolved evidence stay
separate so a person or coding agent can see what is known and what is not.

## What you get

- Safe, read-only IPA intake with path traversal, symlink, expansion, and
  integrity checks.
- Mach-O architecture, section, symbol, import, export, library, deployment,
  entrypoint, UUID, and encryption facts.
- Objective-C classes, categories, protocols, selectors, properties, ivars, and
  method implementation addresses.
- Deterministic headless Ghidra function discovery, call graphs, strings, and
  per-function pseudocode status.
- Evidence-linked Objective-C views, dynamic-dispatch candidates, type flow,
  and platform dependency maps.
- Conservative Itanium C++ ABI recovery, virtual-call candidates, native type
  flow, globals, and numeric data layouts.
- App-neutral storyboard, XIB, binary `NIBArchive`, and keyed NIB decoding
  correlated with UIKit code, assets, localization, outlets, actions,
  navigation, and constraints.
- Deterministic trigger-to-handler-to-effect reconstruction for UI actions,
  lifecycle methods, delegates, notifications, timers, and callbacks, with
  bounded call slices and explicit state, navigation, persistence, network,
  notification, timer, and platform effects.
- Per-function behavioral contracts and application/screen state-machine
  candidates derived from verified pseudocode, type flow, calls, and interaction
  evidence without claiming runtime execution.
- Bounded per-screen reconstruction work packets with exact evidence links,
  candidate alternatives, unresolved questions, verified pseudocode references,
  and a deterministic evidence-prioritized implementation order.
- Versioned JSON schemas and human-readable reports for every stage.
- An optional app-neutral C++ reconstruction core for building separate
  application adapters.

## Requirements

- Python 3.10 or newer.
- A legally obtained IPA whose executable is decrypted. A present
  LC_ENCRYPTION_INFO command must have cryptid=0.
- An official Ghidra installation for the decompile stage. IPALift has been
  tested with Ghidra 12.1.x; use the Java version required by your Ghidra
  release.
- Windows, macOS, or Linux for the Python analyzer. The included reconstruction
  core has a Windows/Visual Studio reference workflow.

IPALift never downloads Ghidra and contains no DRM bypass.

## Install

Create an isolated environment and install the downloaded release wheel:

~~~powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .\ipalift-0.1.0-py3-none-any.whl
.\.venv\Scripts\ipalift.exe --version
~~~

For development from a cloned repository, install the editable development
environment instead:

~~~powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\ipalift.exe --version
~~~

On macOS or Linux, use `python3`, `.venv/bin/python`, and
`.venv/bin/ipalift`. If plain `ipalift` is not recognized, invoke the executable
inside the virtual environment directly; activation is optional.

Download Ghidra from the
[official releases page](https://github.com/NationalSecurityAgency/ghidra/releases).
Pass the extracted release directory with `--ghidra-home`, set `GHIDRA_HOME`,
or place it under `tools/ghidra/ghidra_*_PUBLIC`. See the
[troubleshooting guide](docs/troubleshooting.md) for exact discovery checks.

## Quick start

Use an output directory outside the source tree or under the ignored
analysis-output directory.

### Run the complete pipeline

~~~powershell
.\.venv\Scripts\ipalift.exe run-all path\to\Example.ipa --output analysis-output\example --ghidra-home C:\tools\ghidra_12.1.3_PUBLIC
~~~

`run-all` executes all fourteen stages in dependency order, including the second
Objective-C dispatch/type-flow refinement pass, UI/interaction recovery, behavioral lifting, and the final bounded reconstruction handoff. It
prints each stage as it starts and stops on the first error. The individual
commands below remain available when you want to inspect, resume, or repeat a
specific stage.

### 1. Inspect and extract the IPA

~~~powershell
ipalift analyze path\to\Example.ipa --output analysis-output\example
~~~

This stage records the source hash, safely extracts the archive, inventories
bundle resources, parses every Mach-O slice, and recovers Objective-C runtime
metadata. If any executable slice is still encrypted, later decompilation is
rejected before Ghidra starts.

### 2. Run deterministic Ghidra analysis

~~~powershell
ipalift decompile analysis-output\example --ghidra-home C:\tools\ghidra_12.1.3_PUBLIC
~~~

Both `run-all` and `decompile` accept:

~~~text
--function-timeout SECONDS   Per-function decompiler limit (default: 30)
--analysis-timeout SECONDS   Ghidra auto-analysis limit (default: 3600)
~~~

IPALift uses a temporary Ghidra project, one analysis CPU, and its own
Objective-C evidence application. Ghidra pseudocode is analysis output, not
original or buildable source code.

### 3. Build the higher-level evidence models

Run the remaining stages in this order:

~~~powershell
ipalift recover-objc analysis-output\example
ipalift resolve-objc-dispatch analysis-output\example
ipalift infer-objc-types analysis-output\example

# Apply type-flow feedback to dispatch, then recompute type flow.
ipalift resolve-objc-dispatch analysis-output\example
ipalift infer-objc-types analysis-output\example

ipalift map-platform-apis analysis-output\example
ipalift recover-cpp-model analysis-output\example
ipalift infer-native-types analysis-output\example
ipalift recover-ui analysis-output\example
ipalift recover-interactions analysis-output\example
ipalift lift-behavior analysis-output\example
ipalift build-handoff analysis-output\example
~~~

The second dispatch/type-flow pass is deterministic and additive: it preserves
the original direct call graph and baseline classifications while applying only
fingerprinted feedback. `recover-ui` writes `analysis/ui-model.json` and a
screen-by-screen `reports/ui-reconstruction-report.md`; it preserves exact
serialized facts separately from code/resource candidates and unresolved data.
`recover-interactions` then consumes that UI model without reparsing it and writes
`analysis/interaction-model.json` plus
`reports/interaction-reconstruction-report.md`, connecting triggers to bounded
call-graph slices and evidence-linked effects. `lift-behavior` converts verified
pseudocode, type flow, call edges, and interactions into `analysis/behavior-ir.json`
and `analysis/state-model.json`; all transitions remain candidates requiring
runtime validation. `build-handoff` verifies the shared input hashes and
pseudocode artifacts, then writes
`analysis/reconstruction-handoff.json`, bounded JSON packets under
`handoff/work-packets/`, and `reports/reconstruction-handoff-report.md`.

The handoff is the final consolidation layer planned for the current feature set.
Further work should strengthen evidence quality and real-IPA failure handling
instead of adding new speculative inference stages.

## Workspace layout

A completed workspace looks like this:

~~~text
analysis-output/example/
|-- analysis/                 Versioned JSON artifacts
|   |-- application.json
|   |-- architectures.json
|   |-- classes.json
|   |-- functions.json
|   |-- callgraph.json
|   |-- objc-dispatch.json
|   |-- objc-type-flow.json
|   |-- platform-api-map.json
|   |-- cpp-object-model.json
|   |-- native-type-flow.json
|   |-- ui-model.json
|   |-- interaction-model.json
|   |-- behavior-ir.json
|   |-- state-model.json
|   +-- reconstruction-handoff.json
|-- evidence/extracted/       Preserved archive contents
|-- decompiled/functions/     Ghidra pseudocode by address
|-- recovered/                Objective-C and native evidence views
|-- handoff/work-packets/      Bounded per-screen/application work packets
+-- reports/                  Human-readable stage summaries
~~~

Additional JSON artifacts cover assets, frameworks, strings, decompilation
status, recovered-code indexing, UI/interaction reconstruction, behavioral contracts, state models, handoff planning, and unresolved findings. See
[schemas](schemas/) for the complete machine-readable contracts.

## Reading the results

Every JSON artifact uses the same evidence envelope:

- **facts** contains directly measured or mechanically derived records.
- **hypotheses** contains bounded candidates and inferred edges.
- **errors** contains artifact-level failures.
- Individual records use exact, candidate_set, or unresolved where a
  classification is required.
- Downstream stages fingerprint their authoritative inputs and never rewrite
  the direct Ghidra call graph.

Normalized reports omit timestamps and transient project paths. Given the same
IPA, IPALift revision, Ghidra version, and options, independent runs are
designed to be byte-identical.

For the full evidence model and stage boundaries, read
[the architecture guide](docs/architecture.md).

## Encrypted inputs

IPALift can inventory unencrypted bundle resources and metadata in an IPA whose
executable is encrypted, but it will not send encrypted code to Ghidra:

~~~text
ipalift: error: Cannot decompile encrypted Mach-O code: arm7 (cryptid=1).
Supply a legally obtained decrypted IPA whose LC_ENCRYPTION_INFO cryptid is 0.
~~~

Obtain a decrypted executable through a lawful process outside IPALift. The
project does not provide instructions or tooling for bypassing platform
encryption.

## Reconstruction core

[reconstruction-core](reconstruction-core/) is an optional C++20 library and
adapter scaffold for reconstruction projects. It contains reusable mechanisms
only: fixture loading, event/navigation state, versioned persistence, XML model
parsing, image loading, bitmap text, PNG normalization, and CMake helpers.

Application assets, recovered models, routes, behavior, and evidence belong in
a separate adapter repository. See the
[reconstruction-core README](reconstruction-core/README.md) for its build and
scaffold workflow.

## Test and package

Run the complete analyzer suite:

~~~powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
~~~

Build the source and wheel distributions, then verify both in clean temporary
environments:

~~~powershell
.\.venv\Scripts\python.exe -m build
.\.venv\Scripts\python.exe scripts\verify-release.py --dist-dir dist
~~~

Release maintainers can add `--ghidra-home C:\path\to\ghidra_*_PUBLIC` to run
the full pipeline twice from each artifact, validate every schema, and compare
all outputs byte-for-byte. See the
[release checklist](docs/release-checklist.md) for the complete gate.

The tests and release verifier use generated synthetic IPA and Mach-O fixtures.
No commercial application data is required or included.

## Repository layout

~~~text
src/ipalift/           Analyzer and Ghidra integration
schemas/               Draft 2020-12 report schemas
tests/                 Synthetic regression suite
docs/                  Architecture documentation
reconstruction-core/   Optional app-neutral C++ reconstruction helpers
~~~

Generated workspaces, IPA files, Ghidra installations, local dependencies, and
reconstruction adapters are intentionally ignored by Git.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a change. Generic
defects should be demonstrated with synthetic fixtures; proprietary inputs and
outputs must never be committed. Report vulnerabilities privately and follow
the lawful-use and workspace-handling guidance in [SECURITY.md](SECURITY.md).
Release history is recorded in [CHANGELOG.md](CHANGELOG.md).

## License

IPALift is available under the [MIT License](LICENSE). Ghidra and SDL are
separate projects distributed under their own licenses and are not bundled
with IPALift.
