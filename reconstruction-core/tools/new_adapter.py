#!/usr/bin/env python3
"""Instantiate an application adapter without copying reconstruction_core sources."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


TOKENS = {
    "APP_NAME": re.compile(r"^[A-Za-z][A-Za-z0-9]*$"),
    "APP_NAMESPACE": re.compile(r"^[a-z][a-z0-9_]*$"),
    "APP_SLUG": re.compile(r"^[a-z][a-z0-9_]*$"),
}


def instantiate(template: Path, output: Path, values: dict[str, str]) -> list[Path]:
    if output.exists():
        raise ValueError(f"output already exists: {output}")
    written: list[Path] = []
    for source in sorted(path for path in template.rglob("*") if path.is_file()):
        relative = source.relative_to(template).as_posix().replace("app_namespace", values["APP_NAMESPACE"])
        if relative.endswith(".tmpl"):
            relative = relative[:-5]
        destination = output / relative
        text = source.read_text(encoding="utf-8")
        for key, value in values.items():
            text = text.replace("{{" + key + "}}", value)
        unresolved = re.findall(r"\{\{[A-Z_]+\}\}", text)
        if unresolved:
            raise ValueError(f"unresolved template tokens in {source}: {unresolved}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8", newline="\n")
        written.append(destination)
    return written


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True, help="PascalCase application name")
    parser.add_argument("--namespace", required=True, dest="namespace_id")
    parser.add_argument("--slug", help="lowercase target/resource slug; defaults to namespace")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--template",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "templates" / "app-adapter",
    )
    args = parser.parse_args()
    values = {
        "APP_NAME": args.name,
        "APP_NAMESPACE": args.namespace_id,
        "APP_SLUG": args.slug or args.namespace_id,
    }
    for key, pattern in TOKENS.items():
        if not pattern.fullmatch(values[key]):
            raise ValueError(f"invalid {key.lower()}: {values[key]}")
    written = instantiate(args.template.resolve(), args.output.resolve(), values)
    print(f"ADAPTER_CREATED name={args.name} files={len(written)} output={args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
