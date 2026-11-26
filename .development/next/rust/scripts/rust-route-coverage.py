#!/usr/bin/env python3
"""Compare literal HTTP method/path registrations in the two panel servers."""
import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GO = re.compile(r'HandleFunc\("(GET|POST|PUT|PATCH|DELETE) (/api/[^"]+)"')
RUST = re.compile(r'\.route\(\s*"(/api/[^"]+)"\s*,')
METHOD = re.compile(r'\b(get|post|delete|put|patch)\s*\(')
KNOWN_GAPS = set()


def router_methods(source):
    for match in RUST.finditer(source):
        depth = 1
        for end in range(match.end(), len(source)):
            char = source[end]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    break
        else:
            raise ValueError(f"unfinished .route() for {match[1]}")
        for method in METHOD.findall(source[match.end():end]):
            yield method.upper(), match[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--missing", action="store_true", help="list unmatched Go registrations")
    parser.add_argument("--check", action="store_true", help="fail on a new unmatched registration")
    args = parser.parse_args()
    go = set()
    for file in (ROOT / "internal/server").glob("*.go"):
        if not file.name.endswith("_test.go"):
            go.update(GO.findall(file.read_text(encoding="utf-8")))
    rust = set()
    for file in (ROOT / "rust/panel/src").rglob("*.rs"):
        if file.name != "tests.rs":
            rust.update(router_methods(file.read_text(encoding="utf-8")))
    print(f"Go registered routes: {len(go)}")
    print(f"Matching Rust method/path registrations: {len(go & rust)}")
    print(f"Rust-only routes: {len(rust - go)}")
    print(f"Go registrations still missing: {len(go - rust)}")
    if args.missing:
        for method, path in sorted(go - rust, key=lambda r: (r[1], r[0])):
            print(method, path)
    if args.check:
        if not go or not rust:
            raise SystemExit("could not read panel route registrations")
        regressions = (go - rust) - KNOWN_GAPS
        if regressions:
            for method, path in sorted(regressions):
                print("New unmatched registration:", method, path)
            raise SystemExit(1)


if __name__ == "__main__":
    main()
