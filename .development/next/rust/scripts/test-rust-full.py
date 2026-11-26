#!/usr/bin/env python3
"""Verify the release checksums, sibling executables, ABI and bundled notices."""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("rust_full", Path(__file__).with_name("build-rust-full.py"))
full = importlib.util.module_from_spec(spec)
spec.loader.exec_module(full)


def digest(source):
    return hashlib.file_digest(source, "sha256").hexdigest()


def checksum(path):
    with path.open("rb") as source:
        return digest(source)


def verify(directory, arch, binaries):
    panel = directory / f"nfqws2-strategy-rust-linux-{arch}"
    bundle = directory / f"nfqws2-strategy-rust-full-linux-{arch}.tar.gz"
    expected = "".join(f"{checksum(path)}  {path.name}\n" for path in (panel, bundle))
    if (directory / "SHA256SUMS").read_bytes() != expected.encode("ascii"):
        raise ValueError("incorrect standalone release checksums")
    if checksum(panel) != checksum(binaries / "nfqws2-strategy"):
        raise ValueError("wrong raw panel asset")
    with tarfile.open(bundle, "r:gz") as archive:
        items = archive.getmembers()
        names = {item.name for item in items}
        if len(names) != len(items) or any(not item.isfile() for item in items):
            raise ValueError("standalone bundle contains duplicate or non-file members")
        if {name for name in names if not name.startswith("licenses/")} != set(full.FULL_BINARIES):
            raise ValueError("wrong combination of standalone panel and sibling helpers")
        for name in full.FULL_BINARIES:
            full.check_elf(binaries / name, full.TARGETS[arch], static=True)
            item = archive.getmember(name)
            with archive.extractfile(item) as source:
                if item.mode != 0o755 or digest(source) != checksum(binaries / name):
                    raise ValueError(f"incorrect archived executable {name}")
        for name in full.PROJECT_NOTICES:
            with archive.extractfile("licenses/" + name) as source:
                if digest(source) != checksum(full.ROOT / name):
                    raise ValueError(f"incorrect notice {name}")
        with archive.extractfile("licenses/INDEX.txt") as source:
            lines = source.read().decode().splitlines()
        if {line for line in lines if line.startswith("nfqws2-")} != set(full.FULL_BINARIES):
            raise ValueError("Rust license index does not match the shipped executables")
        required = {"runtime/Rust-standard-library.html", "runtime/musl-1.2.5-COPYRIGHT.txt",
                    "runtime/libunwind-LICENSE.txt"}
        if arch.startswith("mips"):
            required.add("runtime/Zig-0.14.1-LICENSE.txt")
        if any("licenses/" + path not in names for path in required):
            raise ValueError("missing Rust runtime license")
    print(f"Verified standalone {arch} panel and {len(full.FULL_BINARIES)-1} sibling executables")


class Bundle(unittest.TestCase):
    def test_versions_match_the_standalone_updater(self):
        for value in ("0.1.0-rust.2", "1.8.3a", "1.2.3", "1.2.3+nightly.002"):
            self.assertTrue(full.release_version(value), value)
        for value in ("1", "01.2.3", "1.2.3.", "1.2.3+", "1.2.3-02", "1.2.3/../else"):
            self.assertFalse(full.release_version(value), value)

    def test_reproducible_archive_and_sibling_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            elf = bytearray(64 + 56)
            elf[:7] = b"\x7fELF\x02\x01\x01"
            for offset, size, value in [(16,2,2),(18,2,183),(32,8,64),(54,2,56),(56,2,1),(64,4,1)]:
                elf[offset:offset+size] = value.to_bytes(size, "little")
            for name in full.FULL_BINARIES:
                (root / name).write_bytes(elf + name.encode())
            licenses = [("INDEX.txt", "\n".join(full.FULL_BINARIES).encode(), 0o644)]
            for name in ("Rust-standard-library.html", "musl-1.2.5-COPYRIGHT.txt", "libunwind-LICENSE.txt"):
                licenses.append(("runtime/" + name, b"test notice", 0o644))
            stages = [root / "first", root / "second"]
            for stage in stages:
                stage.mkdir()
                full.package(stage, "arm64", root, licenses)
                verify(stage, "arm64", root)
            self.assertEqual((stages[0] / "SHA256SUMS").read_bytes(), (stages[1] / "SHA256SUMS").read_bytes())
            (stages[1] / "SHA256SUMS").write_bytes(b"wrong")
            with self.assertRaisesRegex(ValueError, "checksums"):
                verify(stages[1], "arm64", root)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", nargs=3, metavar=("DIRECTORY","ARCH","BINARIES"))
    args = parser.parse_args()
    if args.verify:
        destination, architecture, inputs = args.verify
        verify(Path(destination), architecture, Path(inputs))
    else:
        unittest.main()
