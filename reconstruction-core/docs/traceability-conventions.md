# Traceability conventions

Traceability is shared as a convention; its identifiers and claims remain app-owned.

Each adapter keeps a CSV with these columns:

| Column | Meaning |
|---|---|
| `feature_id` | Stable adapter-local feature identifier |
| `feature` | Short observable behavior |
| `evidence_ids` | Semicolon-separated recovered or manual evidence IDs |
| `reconstruction` | Files, symbols, fixtures, or assets implementing the behavior |
| `test` | Contract, conversion, smoke, or visual gate that exercises it |
| `confidence` | `high`, `medium`, or `low` based on evidence strength |
| `manual_boundary` | Explicit substitute or hypothesis ID, blank only when none applies |

Rules:

1. Keep recovered facts immutable and outside generated build trees.
2. Put app evidence IDs in adapters, never in `reconstruction_core` implementation comments or
   metadata.
3. Label fixtures that describe reconstructed behavior as manual unless the original format is
   evidenced.
4. Link asset source hashes and generated hashes; never replace frozen source bytes.
5. Separate mechanism tests in the core from app-semantic tests in adapters.
6. Record unknowns and confidence. A successful build does not increase evidentiary confidence.
7. Require a reproducible, app-neutral defect and a synthetic regression before changing the analyzer.
