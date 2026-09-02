# Changelog

All notable changes to IPALift are documented here.

## 0.1.0 - 2026-08-30

Initial public release candidate.

### Added

- Safe, bounded IPA extraction and deterministic Mach-O, Objective-C, asset,
  framework, and encryption inventories.
- Headless Ghidra orchestration with normalized functions, calls, strings,
  pseudocode status, and explicit failure reporting.
- Evidence-bounded Objective-C dispatch/type flow, platform API mapping, C++
  ABI recovery, native type flow, UI recovery, and interaction recovery.
- Deterministic behavioral lifting into per-function contracts and application/
  screen state-machine candidates with verified pseudocode hashes and explicit
  runtime-evidence boundaries.
- A final deterministic reconstruction manifest and bounded per-screen work
  packets with evidence links, candidate alternatives, unresolved questions,
  and implementation ordering.
- Strict Draft 2020-12 JSON schemas, synthetic regression fixtures, an optional
  app-neutral C++ reconstruction core, and Windows/Linux CI coverage.
- Clean wheel/source-distribution verification and a real-Ghidra release smoke
  path using only a generated synthetic IPA.

### Security and correctness

- Archive traversal, unsafe links, expansion limits, encrypted executable use,
  stale evidence, pseudocode traversal, and pseudocode hash mismatches are
  rejected.
- User-facing failures are returned as concise CLI errors without tracebacks.
- The handoff accepts both list-shaped provenance used by newer stages and the
  mapping-shaped provenance emitted by Objective-C type flow.
- The Visual Studio 2022 reconstruction job uses GitHub's matching Windows 2022
  runner image and passes the discovered C++ installation to CMake explicitly.

### Known limitations

- Input executables must already be lawfully decrypted.
- Ghidra and a compatible Java runtime must be installed separately.
- Results are static-analysis evidence, not recovered original source or proof
  of runtime behavior; ambiguous evidence remains candidate or unresolved.
- Complex custom rendering and runtime-generated UI may require manual review
  during reconstruction.
