#!/usr/bin/env python3
"""Inspect compact feed metadata and payloads without installing router software."""

import argparse
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
from pathlib import Path, PurePosixPath
from openwrt_recipe import Recipe, rust_arch
from rust_feed_notices import normal_graph


spec = importlib.util.spec_from_file_location("builder", Path(__file__).with_name("build-compact-feed.py"))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def contents(data, *, installed=False):
    files = {}
    directories = {PurePosixPath(".")}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or path in directories or str(path) in files:
                raise ValueError(f"invalid or duplicate archive path: {path}")
            if installed and path.parent not in directories:
                raise ValueError(f"missing parent directory record before {path}")
            if member.isdir():
                if member.mode != 0o755 or member.uid or member.gid or member.size:
                    raise ValueError(f"incorrect directory metadata for {path}")
                directories.add(path)
            elif member.isreg():
                files[str(path)] = archive.extractfile(member).read(), member.mode
            elif (installed and member.issym() and member.linkname == builder.TOOL_LINK
                  and member.mode == 0o777 and member.size == 0
                  and str(path) in {f"{builder.LIB}/modules/{m}/nfqws2-{m}" for m in builder.MODULES}):
                files[str(path)] = member.linkname, member.mode
            else:
                raise ValueError(f"unexpected archive entry type for {path}")
    if installed:
        expected = {parent for name in files for parent in PurePosixPath(name).parents}
        if directories != expected:
            raise ValueError("data archive contains unused directories")
    return files


class CompactFeedTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.args = argparse.Namespace(panel=self.root / "panel", geo=self.root / "nfqws2-geo",
                                       ui=self.root / "ui", out=self.root / "feed",
                                       arch="aarch64-3.10", version="1.8.7-1")
        # Package tests exercise ELF identification independently of the cross compiler.
        elf = bytearray(64 + 56)
        elf[:7] = b"\x7fELF\x02\x01\x01"
        elf[16:20] = b"\x02\x00\xb7\x00"
        elf[32] = 64
        elf[54] = 56
        elf[56] = 1
        elf[64] = 1  # PT_LOAD of this synthetic static ELF64
        manifest = "\n".join(f"modules/{module}/{module}-abCD_123.js" for module in builder.MODULES)
        self.args.panel.write_bytes(elf + manifest.encode())
        self.args.geo.write_bytes(elf + b"geo")
        for module in builder.MODULES:
            path = self.args.ui / module / f"{module}-abCD_123.js.gz"
            path.parent.mkdir(parents=True)
            path.write_bytes(gzip.compress(module.encode(), mtime=0))

    def build(self):
        with contextlib.redirect_stdout(io.StringIO()):
            builder.build(self.args)

    def test_openwrt_sdk_architecture_guards(self):
        for arch, expected in (("x86_64", "x86_64"), ("aarch64_generic", "aarch64"), ("aarch64_cortex-a53", "aarch64"),
                               ("arm_cortex-a7_neon-vfpv4", "armv7"), ("arm_cortex-a9_vfpv3-d16", "armv7"),
                               ("mips_24kc", "mips"), ("mipsel_74kc", "mipsel")):
            self.assertEqual(rust_arch(arch), expected)
        for unknown in ("arm_cortex-a9", "arm_cortex-a9_vfp", "arm_arm1176jzf-s_vfp",
                        "mipsel_24kc_24kf", "mips64_octeonplus", "mips_4kec", "arm64", "x86", "i386_pentium4", "../sdk"):
            with self.assertRaises(ValueError):
                rust_arch(unknown)

    def test_x86_64_sdk_only_accepts_static_amd64_elf(self):
        self.args.native_rust = True
        self.args.arch = self.args.openwrt_arch = "x86_64"
        self.args.version = "1.8.7-1+shared"
        self.args.shared_tools = self.args.trace = self.args.tgws = self.args.panel
        self.args.geo = None
        elf = bytearray(self.args.panel.read_bytes())
        with self.assertRaisesRegex(ValueError, "not an ELF executable for x86_64"):
            self.build()  # ELF64/AArch64
        elf[18:20] = (62).to_bytes(2, "little")
        for offset, value, message in ((4, 1, "not an ELF"), (5, 2, "not an ELF"),
                                       (64, 3, "dynamic loader")):
            invalid = bytearray(elf)
            invalid[offset] = value
            self.args.panel.write_bytes(invalid)
            with self.assertRaisesRegex(ValueError, message):
                self.build()
        self.args.panel.write_bytes(elf)
        with mock.patch.object(builder, "license_files", return_value=[]) as licenses:
            self.build()
        licenses.assert_called_once_with("x86_64-unknown-linux-musl", shared=True)

    def test_signed_index_must_list_each_payload_and_its_actual_version(self):
        path = builder.ROOT / "packaging/openwrt/verify_index.py"
        spec = importlib.util.spec_from_file_location("verify_index", path)
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        payload = self.root / "payload"
        payload.mkdir()
        names = ["nfqws2-strategy-compact", "nfqws2-strategy-runs"]
        for name in names:
            (payload / (name + ".tar.gz")).touch()
            (self.root / (name + "-2-r1.apk")).touch()
            (self.root / (name + "_2-r1_x86_64.ipk")).touch()
        index = self.root / "index"
        for kind in ("apk", "ipk"):
            for listed, version, ok in ((names, "2-r1", True), (names[:1], "2-r1", False),
                                        (names + names[:1], "2-r1", False),
                                        (names + ["other"], "2-r1", False), (names, "3-r1", False)):
                if kind == "apk":
                    data = json.dumps({"packages": [{"name": n, "version": version} for n in listed]})
                else:
                    data = "\n\n".join(f"Package: {n}\nVersion: {version}" for n in listed)
                index.write_text(data)
                with self.subTest(kind=kind, listed=listed, version=version):
                    if ok:
                        verifier.verify(payload, self.root, "x86_64", kind, index)
                    else:
                        with self.assertRaises(ValueError):
                            verifier.verify(payload, self.root, "x86_64", kind, index)

    def test_sdk_uses_each_firmwares_native_revision_for_dependencies(self):
        make = os.environ.get("GNUMAKE") or shutil.which("make")
        if not make:
            self.skipTest("GNU make is required to evaluate SDK recipes")
        sdk = self.root / "sdk"
        sdk.mkdir()
        stage = self.root / "recipe"
        stage.mkdir()
        recipe = Recipe("aarch64_generic", "aarch64", "1.8.7-2+shared", True, builder.pack)
        recipe.add(stage, "nfqws2-strategy-geo", "", "", "Geo module", [], pinned=[builder.TOOLS])
        recipe.finish(stage)
        (sdk / "rules.mk").write_text("INCLUDE_DIR:=$(TOPDIR)\nARCH_PACKAGES:=aarch64_generic\n")
        for revision in ("-", "-r"):  # 21.02/23.05 opkg and 24.10 opkg/25.12 apk
            (sdk / "package.mk").write_text(
                "define BuildPackage\n"
                f"$(eval VERSION:=$(PKG_VERSION){revision}$(PKG_RELEASE))\n"
                "$(eval $(Package/$(1)))\n"
                "$(info $(EXTRA_DEPENDS))\n"
                "endef\nall: ;\n"
            )
            output = subprocess.check_output([make, "-s", f"TOPDIR={sdk.as_posix()}", "all"],
                                             cwd=stage, text=True)
            version = f"1.8.7{revision}4"
            self.assertIn(f"{builder.BASE} (={version}), {builder.TOOLS} (={version})", output)

    def test_openwrt_sdk_recipe_matches_both_layouts(self):
        self.args.native_rust = True
        self.args.openwrt_arch = "aarch64_cortex-a53"
        self.args.arch = "aarch64"
        for shared in (False, True):
            with self.subTest(shared=shared):
                for module in (*builder.MODULES, "trace", "tgws"):
                    setattr(self.args, module, None if shared and module in builder.MODULES else self.root / "nfqws2-geo")
                self.args.shared_tools = self.root / "nfqws2-geo" if shared else None
                self.args.version = "1.8.7-2" + ("+shared" if shared else "")
                stage = self.args.out = self.root / ("shared" if shared else "split")
                with mock.patch.object(builder, "license_files", return_value=[("INDEX.txt", b"licenses", 0o644)]):
                    self.build()
                self.assertFalse(list(stage.glob("*.ipk")))
                version = (stage / "version.mk").read_text()
                self.assertIn("N2S_ARCH:=aarch64_cortex-a53\n", version)
                self.assertIn(f"PKG_VERSION:=1.8.7\nPKG_RELEASE:={4 if shared else 3}\n", version)
                workers = {*builder.MODULES, "compact", "trace", "tgws"}
                if shared:
                    workers.add("tools")
                self.assertEqual({p.name.split(".")[0].removeprefix("nfqws2-strategy-") for p in
                                  (stage / "payload").glob("*.tar.gz")}, workers)
                metadata = (stage / "packages.mk").read_text()
                self.assertIn("curl ip-full iptables))", metadata)
                for module in workers:
                    pkg = "nfqws2-strategy-" + module
                    deps = next(line for line in metadata.splitlines() if line.startswith(f"PINNED_{pkg}="))
                    self.assertEqual("nfqws2-strategy-compact (=$(VERSION))" in deps,
                                     module != "compact")
                    self.assertEqual("nfqws2-strategy-tools (=$(VERSION))" in deps,
                                     shared and module in builder.MODULES)
                    with tarfile.open(stage / "payload" / f"{pkg}.tar.gz") as archive:
                        members = {p.name.removeprefix("./"): p for p in archive if not p.isdir()}
                        self.assertTrue(all(p.startswith("usr/") for p in members))
                        if module == "compact":
                            self.assertFalse(any("/modules/" in p for p in members))
                            for name in ("n2s-compact", "install.sh", "uninstall.sh"):
                                self.assertEqual(members[f"usr/lib/nfqws2-strategy/{name}"].mode, 0o755)
                        else:
                            binary = members[f"usr/lib/nfqws2-strategy/modules/{module}/nfqws2-{module}"]
                            if shared and module in builder.MODULES:
                                self.assertTrue(binary.issym())
                                self.assertEqual(binary.linkname, "../tools/nfqws2-tools")
                            else:
                                self.assertTrue(binary.isreg())
                                self.assertEqual(binary.mode, 0o755)
        self.args.openwrt_arch = "mips_24kc"
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.build()

    def test_mips_linker_forwards_compiler_failure(self):
        (self.root / "cc").write_text("raise SystemExit(9)\n")
        wrapper = Path(__file__).with_name("rust-mips-cc.py").resolve()
        failed = subprocess.run([sys.executable, wrapper], cwd=self.root,
                                env=dict(os.environ, N2S_MIPS_TARGET="mipsel", ZIG=sys.executable))
        self.assertEqual(failed.returncode, 9)

    def test_clean_entware_root_requires_explicit_directories(self):
        files = [("opt/lib/nfqws2-strategy/modules/geo/worker", b"worker", 0o755)]
        with self.assertRaisesRegex(ValueError, "missing parent directory record"):
            contents(builder.pack(files), installed=True)
        packed = builder.pack(files, directories=True)
        self.assertEqual(contents(packed, installed=True), {files[0][0]: (b"worker", 0o755)})

    def test_index_and_installable_files(self):
        self.build()
        out = self.args.out
        index = (out / "Packages").read_bytes()
        self.assertEqual(gzip.decompress((out / "Packages.gz").read_bytes()), index)
        for notice in ("THIRD-PARTY-NOTICES.txt", "TGWS-LICENSE.txt", "ADGUARD-URLFILTER-LICENSE.txt"):
            self.assertGreater((out / notice).stat().st_size, 0)
        records = index.decode().strip().split("\n\n")
        self.assertEqual(len(records), 5)
        payloads = {}
        for record in records:
            fields = dict(line.split(": ", 1) for line in record.splitlines())
            package = fields["Package"]
            blob = (out / fields["Filename"]).read_bytes()
            self.assertEqual(hashlib.sha256(blob).hexdigest(), fields["SHA256sum"])
            self.assertEqual(len(blob), int(fields["Size"]))
            envelope = contents(blob)
            self.assertEqual(envelope["debian-binary"][0], b"2.0\n")
            payloads[package] = contents(envelope["data.tar.gz"][0], installed=True)
            control = contents(envelope["control.tar.gz"][0])
            self.assertEqual(fields["Version"], self.args.version)
            self.assertIn(f"Package: {package}\n".encode(), control["control"][0])
            self.assertEqual(sum(len(data) for data, _ in payloads[package].values()),
                             int(fields["Installed-Size"]))
            if package == builder.BASE:
                self.assertEqual(fields["Architecture"], self.args.arch)
                self.assertNotIn("Depends", fields)
                self.assertEqual(control["prerm"][1], 0o755)
                self.assertEqual(control["postinst"][1], 0o755)
            else:
                module = package.removeprefix("nfqws2-strategy-")
                expected_deps = [f"{builder.BASE} (= {self.args.version})"]
                if module == "runs":
                    expected_deps.append(f"nfqws2-strategy-strategies (= {self.args.version})")
                self.assertEqual(fields["Depends"].split(", "), expected_deps)
                self.assertEqual(fields["Architecture"], self.args.arch if module == "geo" else "all")
                js = f"{builder.LIB}/modules/{module}/{module}-abCD_123.js.gz"
                self.assertEqual(payloads[package][js], ((self.args.ui / module / Path(js).name).read_bytes(), 0o644))
                self.assertEqual(len(payloads[package]), 2 if module in ("geo", "strategies") else 1)
        self.assertEqual(len(payloads[builder.BASE]), 3)
        self.assertEqual(payloads[builder.BASE][f"{builder.LIB}/n2s-compact"],
                         (self.args.panel.read_bytes(), 0o755))
        self.assertEqual(payloads["nfqws2-strategy-geo"][f"{builder.LIB}/modules/geo/nfqws2-geo"],
                         (self.args.geo.read_bytes(), 0o755))
        self.assertEqual(payloads["nfqws2-strategy-strategies"][f"{builder.LIB}/modules/strategies/catalog.json"],
                         (builder.CATALOG.read_bytes(), 0o644))
        # Rebuilding from identical inputs is reproducible; leaving old files
        # in place could silently mix incompatible frontend versions.
        first = self.args.out
        with self.assertRaisesRegex(ValueError, "empty or new"):
            self.build()
        self.args.out = self.root / "again"
        self.build()
        for path in first.iterdir():
            self.assertEqual(path.read_bytes(), (self.args.out / path.name).read_bytes())

    def test_bad_inputs_leave_no_partial_feed(self):
        self.args.arch = "mipselsf-k3.4"
        with self.assertRaisesRegex(ValueError, "not an ELF executable"):
            self.build()
        self.args.arch = "aarch64-3.10"
        path = next((self.args.ui / "geo").iterdir())
        path.unlink()
        with self.assertRaisesRegex(ValueError, "exactly one geo"):
            self.build()
        path.write_bytes(b"invalid gzip")
        with self.assertRaises(gzip.BadGzipFile):
            self.build()
        self.assertFalse(self.args.out.exists())

    def test_cross_build_module_mismatch(self):
        chunk = next((self.args.ui / "geo").iterdir())
        chunk.rename(chunk.with_name("geo-different.js.gz"))
        with self.assertRaisesRegex(ValueError, "panel manifest does not reference"):
            self.build()
        self.assertFalse(self.args.out.exists())

    def test_compact_graph_excludes_dev_and_rejects_embedded_workers(self):
        panel = {"name": "nfqws2-strategy", "id": "panel", "source": None}
        worker = {"name": "nfqws2-runs", "id": "runs", "source": None}
        crate = {"name": "serde", "id": "serde", "source": "registry"}
        edge = {"pkg": "runs", "dep_kinds": [{"kind": "dev"}]}
        root = {"id": "panel", "features": ["compact"], "deps": [
            edge, {"pkg": "serde", "dep_kinds": [{"kind": None}]},
        ]}
        metadata = {"packages": [panel, worker, crate], "workspace_members": ["panel", "runs"],
                    "resolve": {"nodes": [root, {"id": "runs", "deps": []}, {"id": "serde", "deps": []}]}}
        self.assertEqual(normal_graph(metadata, panel["name"]), {"serde": crate})
        for feature in ["embedded-geo", "embedded-runs", "embedded-strategies"]:
            root["features"].append(feature)
            with self.assertRaisesRegex(ValueError, "optional worker"):
                normal_graph(metadata, panel["name"])
            root["features"].pop()
        edge["dep_kinds"] = [{"kind": None}]
        with self.assertRaisesRegex(ValueError, "optional worker"):
            normal_graph(metadata, panel["name"])

    def test_base_available_without_rust_geo_target(self):
        self.args.geo = None
        self.build()
        self.assertEqual(len(list(self.args.out.glob("*.ipk"))), 4)
        self.assertNotIn("nfqws2-strategy-geo", (self.args.out / "Packages").read_text())

    def test_mips_requires_matching_byteorder_o32_soft_float_and_static_segments(self):
        for arch, endian, encoding in [("mipselsf-k3.4", "little", 1), ("mipssf-k3.4", "big", 2)]:
            elf = bytearray(64 + 2 * 32 + 24)
            elf[:7] = b"\x7fELF" + bytes([1, encoding, 1])
            for offset, width, value in [(16, 2, 2), (18, 2, 8), (28, 4, 64), (36, 4, 0x70001005),
                                         (42, 2, 32), (44, 2, 2), (64, 4, 1), (96, 4, 0x70000003),
                                         (100, 4, 128), (112, 4, 24)]:
                elf[offset:offset + width] = value.to_bytes(width, endian)
            elf[135] = 3
            self.args.panel.write_bytes(elf)
            builder.check_elf(self.args.panel, arch, static=True)
            for offset, width, value, message in [(5, 1, 3 - encoding, "not an ELF"),
                                                  (36, 4, 0x70002005, "o32 soft-float"),
                                                  (135, 1, 1, "o32 soft-float"),
                                                  (64, 4, 3, "dynamic loader")]:
                changed = elf.copy()
                changed[offset:offset + width] = value.to_bytes(width, endian)
                self.args.panel.write_bytes(changed)
                with self.assertRaisesRegex(ValueError, message):
                    builder.check_elf(self.args.panel, arch, static=True)

    def test_shared_tools_are_pinned_once_with_independent_ui_packages(self):
        self.args.native_rust = True
        self.args.version += "+shared"
        self.args.trace = self.args.tgws = self.args.shared_tools = self.args.geo
        self.args.geo = None
        with mock.patch.object(builder, "license_files", return_value=[]):
            self.build()
        records = (self.args.out / "Packages").read_text().strip().split("\n\n")
        self.assertEqual(len(records), 8)
        for block in records:
            record = dict(row.split(": ", 1) for row in block.splitlines())
            module = record["Package"].removeprefix("nfqws2-strategy-")
            data = contents((self.args.out / record["Filename"]).read_bytes())
            payload = contents(data["data.tar.gz"][0], installed=True)
            self.assertEqual(int(record["Installed-Size"]), sum(len(v[0]) for v in payload.values()))
            if module in builder.MODULES:
                self.assertIn(f"{builder.TOOLS} (= {self.args.version})", record["Depends"])
                self.assertEqual(payload[f"{builder.LIB}/modules/{module}/nfqws2-{module}"], (builder.TOOL_LINK, 0o777))
                self.assertIn(f"{builder.LIB}/modules/{module}/{module}-abCD_123.js.gz", payload)
            else:
                self.assertNotIn(builder.TOOLS, record.get("Depends", ""))
                if module == "tools":
                    self.assertEqual(payload, {f"{builder.LIB}/modules/tools/nfqws2-tools":
                                               (self.args.shared_tools.read_bytes(), 0o755)})
        self.args.version = "1.2.3"
        with self.assertRaisesRegex(ValueError, "version ending in"):
            self.build()

    def test_native_workers_have_router_architecture_and_stay_out_of_base(self):
        self.args.native_rust = True
        self.args.runs = self.args.geo
        self.args.blockcheck = self.args.geo
        self.args.trace = self.args.geo
        self.args.strategies = self.args.geo
        self.args.tgws = self.args.geo
        with mock.patch.object(builder, "license_files", return_value=[("INDEX.txt", b"fixture", 0o644)]):
            self.build()
        base = contents(next(self.args.out.glob("nfqws2-strategy-compact_*.ipk")).read_bytes())
        control = contents(base["control.tar.gz"][0])
        self.assertEqual(control["preinst"],
                         ((builder.ROOT / "packaging/compact/preinst").read_bytes(), 0o755))
        data = contents(base["data.tar.gz"][0], installed=True)
        self.assertIn("opt/share/licenses/nfqws2-strategy/LICENSE-crypt", data)
        self.assertEqual(data["opt/share/licenses/nfqws2-strategy/RUST-THIRD-PARTY-NOTICES.tar.gz"][0],
                         (self.args.out / "RUST-THIRD-PARTY-NOTICES.tar.gz").read_bytes())
        self.assertFalse(any("/modules/" in path for path in data))
        for name in ("blockcheck", "runs", "geo", "strategies", "trace", "tgws"):
            package = next(self.args.out.glob(f"nfqws2-strategy-{name}_*.ipk"))
            archive = contents(package.read_bytes())
            control = contents(archive["control.tar.gz"][0])["control"][0].decode()
            self.assertIn(f"Architecture: {self.args.arch}", control)
            files = contents(archive["data.tar.gz"][0], installed=True)
            helper = f"opt/lib/nfqws2-strategy/modules/{name}/nfqws2-{name}"
            self.assertEqual(files[helper], (self.args.geo.read_bytes(), 0o755))
            if name in ("blockcheck", "geo"):
                self.assertIn(", curl\n", control)
            if name == "runs":
                self.assertIn(", curl, ca-certificates\n", control)
                self.assertNotIn("nfqws2-strategy-strategies (=", control)
            if name == "strategies":
                self.assertEqual(files[f"{builder.LIB}/modules/strategies/catalog.json"][0],
                                 builder.CATALOG.read_bytes())
            if name in ("trace", "tgws"):
                dependency = "tcpdump" if name == "trace" else "ca-certificates"
                self.assertIn(f", {dependency}\n", control)
                paths = {helper}
                if name == "tgws":
                    notice = "opt/share/licenses/nfqws2-strategy/TGWS-LICENSE.txt"
                    self.assertEqual(files[notice][0], (builder.ROOT / "internal/services/tgws/LICENSE.upstream").read_bytes())
                    paths.add(notice)
                self.assertEqual(set(files), paths)


def verify_native(feed, binaries):
    """Check unpacked artifacts from the real cross-build, including ELF program headers."""
    index = (feed / "Packages").read_bytes()
    if index != gzip.decompress((feed / "Packages.gz").read_bytes()):
        raise ValueError("Packages.gz differs from Packages")
    records = [dict(line.split(": ", 1) for line in record.splitlines())
               for record in index.decode().strip().split("\n\n")]
    expected = {"compact", "runs", "blockcheck", "geo", "strategies", "trace", "tgws"}
    names = {r["Package"].removeprefix("nfqws2-strategy-") for r in records}
    shared = all(r["Version"].endswith("+shared") for r in records)
    if shared:
        expected.add("tools")
    if names != expected or len(records) != len(expected):
        raise ValueError(f"unexpected set of IPKs: {names}")
    panel = (binaries / "nfqws2-strategy").read_bytes()
    for r in records:
        module = r["Package"].removeprefix("nfqws2-strategy-")
        ipk = (feed / r["Filename"]).read_bytes()
        if hashlib.sha256(ipk).hexdigest() != r["SHA256sum"] or len(ipk) != int(r["Size"]):
            raise ValueError(f"wrong index digest or size for {module}")
        payload = contents(contents(ipk)["data.tar.gz"][0], installed=True)
        size = sum(len(data) for data, _ in payload.values())
        if size != int(r["Installed-Size"]):
            raise ValueError(f"wrong installed size for {module}")
        if module == "compact":
            if any("/modules/" in p for p in payload):
                raise ValueError("base includes optional payload")
            licenses = contents(payload["opt/share/licenses/nfqws2-strategy/RUST-THIRD-PARTY-NOTICES.tar.gz"][0])
            if b"ring " not in licenses["INDEX.txt"][0] or "runtime/Rust-standard-library.html" not in licenses:
                raise ValueError("base lacks Rust dependency notices")
        if module in builder.MODULES:
            pages = [p for p in payload if p.endswith(".js.gz")]
            if len(pages) != 1 or pages[0].removeprefix(f"{builder.LIB}/").removesuffix(".gz").encode() not in panel:
                raise ValueError(f"panel manifest does not reference the {module} page")
            if payload[pages[0]][0] in panel:
                raise ValueError(f"base contains the {module} page")
        if module == "strategies":
            catalog = payload[f"{builder.LIB}/modules/strategies/catalog.json"][0]
            if catalog != builder.CATALOG.read_bytes() or catalog in panel:
                raise ValueError("wrong strategy catalog")
        relative = "n2s-compact" if module == "compact" else f"modules/{module}/nfqws2-{module}"
        name = "nfqws2-strategy" if module == "compact" else f"nfqws2-{module}"
        executable = binaries / name
        data, mode = payload[f"{builder.LIB}/{relative}"]
        if shared and module in builder.MODULES:
            required = f"{builder.TOOLS} (= {r['Version']})"
            if required not in r["Depends"].split(", ") or (data, mode) != (builder.TOOL_LINK, 0o777):
                raise ValueError(f"missing pinned shared command for {module}")
            continue
        if builder.TOOLS in r.get("Depends", ""):
            raise ValueError(f"unexpected shared tools dependency for {module}")
        if mode != 0o755 or data != executable.read_bytes():
            raise ValueError(f"incorrect binary or mode for {name}")
        builder.check_elf(executable, r["Architecture"], static=True)
    print(f"Verified {len(records)} native IPKs in {feed}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 4 and sys.argv[1] == "--verify-native":
        verify_native(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        unittest.main()
