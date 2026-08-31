# IPALift 0.1.0 release checklist

This checklist prepares a release candidate. It does not publish, upload, or
tag anything.

## Source and policy gates

- [x] Package and runtime versions agree on `0.1.0`.
- [x] License, changelog, security/lawful-use policy, troubleshooting guide,
  architecture guide, and contribution rules are present.
- [x] `.gitignore` excludes IPA inputs, generated workspaces, local tools,
  virtual environments, build products, and package metadata.
- [x] The source audit contains no private IPA data, proprietary outputs,
  credentials, personal machine paths, or app-specific implementation logic.
- [x] The wheel contains only runtime package files and metadata.
- [x] The source distribution contains the public schemas, synthetic tests,
  documentation, CI workflow, verifier, and reconstruction core.

## Reproducible local gates

From a clean checkout on Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m build
.\.venv\Scripts\python.exe scripts\verify-release.py --dist-dir dist --ghidra-home C:\tools\ghidra_12.1.3_PUBLIC
.\reconstruction-core\scripts\build-and-test.ps1
```

The release verifier creates clean temporary environments for both the wheel
and source distribution. With `--ghidra-home`, it runs the generated synthetic
IPA twice from each package, validates all 19 analysis artifacts and every work
packet, compares byte-for-byte outputs, and checks cross-package equality. It
prints `RELEASE_VERIFICATION_OK` only if every gate succeeds.

## GitHub gates before tagging

- [ ] Initialize/push the intended public repository and review the complete
  staged file list; this working folder currently has no Git metadata.
- [ ] Confirm the `CI` workflow passes on GitHub for Windows and Linux.
- [ ] Confirm repository private vulnerability reporting is enabled.
- [ ] Review generated wheel and source-distribution SHA-256 hashes.
- [ ] Create the `v0.1.0` tag and GitHub release only after explicit owner
  approval.

## Candidate assessment

**Local verdict: SHIP as the IPALift 0.1.0 release candidate.** The candidate is
eligible to be pushed for its first GitHub CI run after all checked local gates
remain green. **Publication verdict: DO NOT TAG YET** because publishing and
tagging require explicit owner approval and the first remote CI result.
