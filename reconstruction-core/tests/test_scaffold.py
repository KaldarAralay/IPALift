#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generator", type=Path, required=True)
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    args = parser.parse_args()
    if args.work_root.exists():
        shutil.rmtree(args.work_root)
    output = args.work_root / "FifthPilot"
    subprocess.run(
        [sys.executable, str(args.generator), "--template", str(args.template),
         "--name", "FifthPilot", "--namespace", "fifth_pilot", "--output", str(output)],
        check=True,
    )
    files = sorted(path for path in output.rglob("*") if path.is_file())
    assert len(files) == 10
    combined = "\n".join(path.read_text(encoding="utf-8") for path in files)
    assert re.search(r"\{\{[A-Z_]+\}\}", combined) is None

    assert "reconstruction_core::reconstruction_core" in combined
    assert not (output / "src" / "EventNavigation.cpp").exists()
    assert not (output / "tools" / "normalize_png.py").exists()
    print(f"RECONSTRUCTION_CORE_SCAFFOLD_TESTS_OK files={len(files)} framework_copies=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
