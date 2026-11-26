#!/usr/bin/env python3
"""Build the standalone Rust panel, its sibling helpers and a release checksum file."""
import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

from rust_feed_notices import FULL_BINARIES, ROOT, license_files
from rust_release_elf import check_elf

TARGETS = {
    "amd64": "x86_64-unknown-linux-musl",
    "arm64": "aarch64-unknown-linux-musl",
    "arm": "armv7-unknown-linux-musleabihf",
    "mipsle": "mipsel-unknown-linux-musl",
    "mips": "mips-unknown-linux-musl",
}
PROJECT_NOTICES = ("THIRD_PARTY_NOTICES.md", "THIRD_PARTY_LICENSES/Frontend-LICENSES.txt",
                   "THIRD_PARTY_LICENSES/AdGuard-urlfilter-GPL-3.0.txt",
                   "rust/auth/LICENSE-crypt", "internal/services/tgws/LICENSE.upstream")


def add_bytes(archive, name, data, mode=0o644):
    info = tarfile.TarInfo(name)
    info.size, info.mode = len(data), mode
    archive.addfile(info, io.BytesIO(data))


def bundle_files(archive, binaries, licenses):
    for name in FULL_BINARIES:
        with (binaries / name).open("rb") as source:
            info = tarfile.TarInfo(name)
            info.size, info.mode = os.fstat(source.fileno()).st_size, 0o755
            archive.addfile(info, source)
    for name, data, mode in licenses:
        add_bytes(archive, "licenses/" + name, data, mode)
    for name in PROJECT_NOTICES:
        add_bytes(archive, "licenses/" + name, (ROOT / name).read_bytes())


def package(stage, arch, binaries, licenses):
    for name in FULL_BINARIES:
        check_elf(binaries / name, TARGETS[arch], static=True)
    panel = stage / f"nfqws2-strategy-rust-linux-{arch}"
    shutil.copyfile(binaries / "nfqws2-strategy", panel)
    panel.chmod(0o755)
    bundle = stage / f"nfqws2-strategy-rust-full-linux-{arch}.tar.gz"
    with bundle.open("wb") as destination:
        with gzip.GzipFile(filename="", mode="wb", fileobj=destination, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
                bundle_files(archive, binaries, licenses)
    sums = []
    for file in (panel, bundle):
        with file.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        sums.append(f"{digest}  {file.name}\n")
    (stage / "SHA256SUMS").write_bytes("".join(sums).encode("ascii"))


def release_version(text):
    numeric = r"(?:0|[1-9][0-9]*)"
    core = rf"{numeric}\.{numeric}\.{numeric}"
    # The panel updater also understands the project's legacy "1.8.3a" tags.
    if re.fullmatch(core + r"[a-z]+", text):
        return True
    ident = r"[A-Za-z0-9-]+"
    parts = re.fullmatch(core + rf"(?:-({ident}(?:\.{ident})*))?(?:\+{ident}(?:\.{ident})*)?", text)
    if not parts:
        return False
    return not any(len(field) > 1 and field.startswith("0") and field.isdigit()
                   for field in (parts.group(1) or "").split("."))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("arch", choices=TARGETS)
    parser.add_argument("version")
    args = parser.parse_args()
    if not release_version(args.version):
        parser.error("expected a release version, e.g. 0.1.0-rust.2")
    target = TARGETS[args.arch]
    output = ROOT / "dist/rust-full" / args.version / args.arch
    if output.exists():
        parser.error(f"destination already exists: {output}")
    env = dict(os.environ, N2S_BUILD_VERSION=args.version)
    platform = target.replace("-", "_").upper()
    build = ["cargo", "build"]
    if target.startswith("mips"):
        build = ["cargo", "+nightly-2026-07-11", "build", "-Zbuild-std=std,panic_abort"]
        key = f"CARGO_TARGET_{platform}_RUSTFLAGS"
        env[key] = (env.get(key, "") + " -Ctarget-feature=+crt-static -Clink-self-contained=no").strip()
    else:
        env.setdefault(f"CARGO_TARGET_{platform}_LINKER", "rust-lld")
    target_dir = ROOT / "target/standalone"
    build += ["--release", "--locked", "--offline", "--target-dir", str(target_dir), "--target", target]
    for name in FULL_BINARIES:
        build += ["-p", name]
    subprocess.run(build, env=env, cwd=ROOT, check=True)
    binaries = target_dir / target / "release"
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        stage = Path(tmp) / "release"
        stage.mkdir()
        package(stage, args.arch, binaries, license_files(target, compact=False))
        stage.rename(output)
    print(output)


if __name__ == "__main__":
    main()
