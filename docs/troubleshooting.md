# Troubleshooting

## `ipalift` is not recognized in PowerShell

The virtual environment is not active or its scripts directory is not on
`PATH`. Invoke the executable directly:

```powershell
.\.venv\Scripts\ipalift.exe --version
```

Alternatively run `.\.venv\Scripts\Activate.ps1` first. If PowerShell blocks
activation, direct invocation still works and does not require changing the
execution policy.

## Ghidra was not found

Pass the installation directory—the directory containing both
`support\analyzeHeadless.bat` and `Ghidra\application.properties`:

```powershell
.\.venv\Scripts\ipalift.exe run-all app.ipa --output analysis-output\app --ghidra-home C:\tools\ghidra_12.1.3_PUBLIC
```

Or configure it for the current PowerShell session:

```powershell
$env:GHIDRA_HOME = 'C:\tools\ghidra_12.1.3_PUBLIC'
```

IPALift also searches `tools\ghidra\ghidra_*_PUBLIC` below the current working
directory. Point to the extracted Ghidra release itself, not a Ghidra project
directory or a directory containing only scripts.

## Ghidra or Java fails before analysis

Use the Java version required by that Ghidra release and confirm Ghidra's own
`support\analyzeHeadless.bat` starts outside IPALift. IPALift reports the last
lines of Ghidra output when no completion manifest is produced. Those lines are
diagnostic logs and may contain local paths; review them before sharing.

## The IPA is reported as encrypted

IPALift intentionally refuses to send a Mach-O slice with a nonzero `cryptid`
to Ghidra. Supply a lawfully obtained decrypted IPA. IPALift does not include a
decryption or access-control bypass.

## A stage reports stale or mismatched evidence

Downstream artifacts fingerprint their inputs. Do not edit generated JSON or
pseudocode in place. The safest recovery is to choose a new output directory
and rerun `run-all`. To resume intentionally, rerun the failed stage and every
later stage in the order shown in the README.

## Analysis times out

Increase `--function-timeout` only for individual complex functions, or
`--analysis-timeout` for Ghidra's full analysis. Accepted ranges are enforced
by the CLI. A timeout remains explicit in `decompilation.json`; it is never
silently converted into successful output.

## An output directory already contains files

IPALift preserves source evidence and refuses conflicting extraction state.
Use a fresh output directory rather than deleting individual generated files
or mixing results from different IPAs.

## Reporting a reproducible defect

Run the complete synthetic suite first:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Report the IPALift version, Python version, operating system, Ghidra version,
command, concise error, and a synthetic reproducer. Do not post a proprietary
IPA or generated workspace. Report security-sensitive defects privately as
described in [SECURITY.md](../SECURITY.md).
