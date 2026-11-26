"""Collect notices for the resolved Rust packages shipped in a native router feed."""

import hashlib
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ROOTS = ("nfqws2-strategy", "nfqws2-geo", "nfqws2-runs", "nfqws2-blockcheck",
         "nfqws2-strategies", "nfqws2-trace", "nfqws2-tgws", "nfqws2-tools")
FULL_BINARIES = ("nfqws2-strategy", "nfqws2-blockcheck", "nfqws2-trace", "nfqws2-tgws")
NOTICE = re.compile(r"^(?:licen[cs]es?|copying|copyright|notices?|unlicense)(?:$|[._-])", re.I)


def normal_graph(metadata, name, *, compact=True):
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    root = next(i for i in metadata["workspace_members"] if packages[i]["name"] == name)
    found = set()
    pending = [root]
    while pending:
        current = pending.pop()
        if current in found:
            continue
        found.add(current)
        for dep in nodes[current]["deps"]:
            if any(kind["kind"] is None for kind in dep["dep_kinds"]):
                pending.append(dep["pkg"])
    if name == "nfqws2-strategy":
        features = set(nodes[root]["features"])
        embedded_features = {"embedded-runs", "embedded-geo", "embedded-strategies"}
        linked_workers = {packages[i]["name"] for i in found} & (set(ROOTS) - {name})
        if compact and ("compact" not in features or features & embedded_features or linked_workers):
            raise ValueError("compact panel includes an optional worker or lacks the compact feature")
        if not compact and ("compact" in features or not embedded_features.issubset(features)
                            or linked_workers != {"nfqws2-geo", "nfqws2-runs", "nfqws2-strategies"}):
            raise ValueError("standalone panel must embed runs, Geo and strategy services")
    return {i: packages[i] for i in found if packages[i]["source"]}


def license_files(target, *, compact=True, shared=False):
    # Use the same Cargo feature selection and target as the native cross-build.
    # Host-only/dev dependencies are absent from the distribution.
    toolchain = ["+nightly-2026-07-11"] if target.startswith("mips") else []
    features = ["--no-default-features", "--features", "nfqws2-strategy/compact"] if compact else []
    command = ["cargo", *toolchain, "metadata", "--format-version=1", "--locked", "--offline",
               *features, "--filter-platform", target]
    metadata = json.loads(subprocess.check_output(command, cwd=ROOT))
    compiler = subprocess.check_output(["rustc", *toolchain, "--version"], text=True).strip()
    sysroot = Path(subprocess.check_output(["rustc", *toolchain, "--print", "sysroot"], text=True).strip())
    manifest = [compiler, "Target " + target, ""]
    packages = {}
    for binary in (ROOTS if compact else FULL_BINARIES):
        if binary == "nfqws2-tools" and not shared:
            continue
        graph = normal_graph(metadata, binary, compact=compact)
        packages.update(graph)
        manifest.extend([binary, *(f'  {p["name"]} {p["version"]}' for p in
                                   sorted(graph.values(), key=lambda p: (p["name"], p["version"]))), ""])

    files = {}
    for package in sorted(packages.values(), key=lambda p: (p["name"], p["version"])):
        source = Path(package["manifest_path"]).parent
        notices = {p for p in source.rglob("*") if p.is_file() and NOTICE.match(p.name)}
        if package["license_file"]:
            notices.add(source / package["license_file"])
        if not notices:
            raise ValueError(f'no license files for {package["name"]} {package["version"]}')
        manifest.append(f'{package["name"]} {package["version"]} | {package["license"] or ""} | '
                        f'{package["repository"] or package["source"]}')
        for path in sorted(notices):
            data = path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            entry = f"texts/{digest}.txt"
            files.setdefault(entry, data)
            manifest.append(f"  {path.relative_to(source).as_posix()} -> {entry}")
        manifest.append("")

    files["INDEX.txt"] = ("\n".join(manifest) + "\n").encode()
    runtime = {
        "runtime/Rust-standard-library.html": sysroot / "share/doc/rust/COPYRIGHT-library.html",
        "runtime/libunwind-LICENSE.txt": sysroot / "lib/rustlib/src/rust/src/llvm-project/libunwind/LICENSE.TXT",
        "runtime/musl-1.2.5-COPYRIGHT.txt": ROOT / "THIRD_PARTY_LICENSES/musl-1.2.5-COPYRIGHT.txt",
    }
    if target.startswith("mips"):
        runtime["runtime/Zig-0.14.1-LICENSE.txt"] = ROOT / "THIRD_PARTY_LICENSES/Zig-0.14.1-LICENSE.txt"
    for name, path in runtime.items():
        if not path.is_file():
            raise ValueError(f"missing runtime license {path}. Install rust-docs and rust-src with rustup")
        files[name] = path.read_bytes()
    return [(name, data, 0o644) for name, data in sorted(files.items())]
