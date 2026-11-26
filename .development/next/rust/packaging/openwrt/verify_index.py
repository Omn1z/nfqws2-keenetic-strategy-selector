"""Check signed OpenWrt index entries against the staged native packages."""

import json
import sys
from email.parser import Parser
from pathlib import Path


def verify(payload, feed, arch, kind, index):
    expected = {p.name.removesuffix(".tar.gz") for p in payload.glob("*.tar.gz")}
    if kind == "apk":
        data = json.loads(index.read_text(encoding="utf-8"))
        rows = data["packages"] if isinstance(data, dict) else data
        records = ((row["name"], row["version"]) for row in rows)
    elif kind == "ipk":
        rows = (Parser().parsestr(row) for row in index.read_text(encoding="utf-8").strip().split("\n\n"))
        records = ((row["Package"], row["Version"]) for row in rows)
    else:
        raise ValueError(f"unknown index format {kind}")
    seen = set()
    for name, version in records:
        if name not in expected or name in seen:
            raise ValueError(f"unexpected or duplicate package in signed index: {name}")
        seen.add(name)
        filename = f"{name}-{version}.apk" if kind == "apk" else f"{name}_{version}_{arch}.ipk"
        if not version or Path(filename).name != filename or not (feed / filename).is_file():
            raise ValueError(f"signed index does not match package file for {name} {version}")
    if seen != expected:
        raise ValueError("missing from signed index: " + ", ".join(sorted(expected - seen)))


if __name__ == "__main__":
    try:
        verify(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], sys.argv[4], Path(sys.argv[5]))
    except (OSError, ValueError, KeyError) as error:
        sys.exit(f"verify-index: {error}")
