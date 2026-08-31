# Contributing

Thanks for helping improve IPALift.

## Ground rules

- Submit only code and fixtures you have the right to publish.
- Never commit IPA files, extracted application assets, decompiler output, signing material, or
  other proprietary application data.
- Keep analyzer and reconstruction-core changes app-neutral. Application-specific behavior belongs
  in a separate adapter repository.
- Preserve uncertainty: unsupported or ambiguous evidence must remain explicit rather than being
  converted into a confident guess.
- A bug fix should include a small synthetic regression that reproduces the generic failure without
  commercial application data.

## Development setup

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

On macOS or Linux, use `.venv/bin/python` instead.

Before opening a pull request, run the complete Python suite and confirm that no generated analysis
workspace or private input was added. Changes to `reconstruction-core/` should also pass its CMake
and CTest workflow documented in that directory.

Release-affecting changes must also build both distributions and pass
`python scripts/verify-release.py --dist-dir dist`. Do not post suspected vulnerabilities publicly;
follow [SECURITY.md](SECURITY.md).
