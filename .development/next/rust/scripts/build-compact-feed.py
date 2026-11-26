#!/usr/bin/env python3
"""Build an Entware feed or a native OpenWrt SDK recipe from one compact panel and its modules."""

import argparse
import gzip
import hashlib
import io
import mmap
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from rust_feed_notices import license_files
from rust_release_elf import check_elf


ROOT = Path(__file__).resolve().parents[1]
BASE = "nfqws2-strategy-compact"
LIB = "opt/lib/nfqws2-strategy"
MODULES = ("runs", "blockcheck", "strategies", "geo")
TOOLS = "nfqws2-strategy-tools"
TOOL_LINK = "../tools/nfqws2-tools"
CATALOG = ROOT / "internal/services/strategy/core/catalog/builtin.json"


def pack(files, *, directories=False):
    """Entware's gzip/tar IPK format, with reproducible metadata."""
    result = io.BytesIO()
    with gzip.GzipFile(fileobj=result, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            # Entware opkg opens regular files directly. It creates their
            # parents only when the data archive contains directory records.
            if directories:
                parents = {parent.as_posix() for name, _, _ in files
                           for parent in PurePosixPath(name).parents if parent.parts}
                for name in sorted(parents):
                    item = tarfile.TarInfo("./" + name)
                    item.type = tarfile.DIRTYPE
                    item.mode = 0o755
                    archive.addfile(item)
            for name, content, mode in files:
                if isinstance(content, str):
                    if content != TOOL_LINK or name not in {
                        f"{prefix}/lib/nfqws2-strategy/modules/{m}/nfqws2-{m}"
                        for m in MODULES for prefix in ("opt", "usr")
                    }:
                        raise ValueError(f"unexpected helper link: {name}")
                    item = tarfile.TarInfo("./" + name)
                    item.type, item.mode, item.linkname = tarfile.SYMTYPE, mode, content
                    archive.addfile(item)
                    continue
                src = content.open("rb") if isinstance(content, Path) else io.BytesIO(content)
                with src:
                    item = tarfile.TarInfo("./" + name)
                    item.mode = mode
                    item.size = src.seek(0, os.SEEK_END)
                    src.seek(0)
                    archive.addfile(item, src)
    return result.getvalue()


def make_package(out, name, version, arch, description, files, hooks=(), requires=(), pinned=()):
    size = sum(len(path) if isinstance(path, str) else path.stat().st_size for _, path, _ in files)
    control = (f"Package: {name}\nVersion: {version}\nArchitecture: {arch}\n"
               "Maintainer: NFQWS2 Strategy\nSection: net\nPriority: optional\n"
               f"Installed-Size: {size}\nDescription: {description}\n")
    if name != BASE:
        dependencies = [BASE, *pinned]
        control += "Depends: " + ", ".join([f"{dep} (= {version})" for dep in dependencies] + list(requires)) + "\n"
    metadata = [("control", control.encode(), 0o644)]
    metadata.extend((hook, ROOT / "packaging/compact" / hook, 0o755) for hook in hooks)
    data = pack([("debian-binary", b"2.0\n", 0o644),
                 ("control.tar.gz", pack(metadata), 0o644),
                 ("data.tar.gz", pack(files, directories=True), 0o644)])
    filename = f"{name}_{version}_{arch}.ipk"
    (out / filename).write_bytes(data)
    print(f"{name}: {size} bytes installed payload, {len(data)} bytes download")
    return (control + f"Filename: {filename}\nSize: {len(data)}\n"
            f"SHA256sum: {hashlib.sha256(data).hexdigest()}\n")


def build(args):
    if not re.fullmatch(r"[0-9][0-9A-Za-z.+~-]*", args.version):
        raise ValueError("expected an opkg version starting with a digit")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", args.arch):
        raise ValueError("expected a single architecture from opkg print-architecture")
    native = getattr(args, "native_rust", False)
    shared = getattr(args, "shared_tools", None)
    sdk_arch = getattr(args, "openwrt_arch", None)
    if sdk_arch:
        from openwrt_recipe import Recipe
        if not native:
            raise ValueError("OpenWrt packages require the native compact Rust build")
        recipe = Recipe(sdk_arch, args.arch, args.version, bool(shared), pack)
    if shared:
        if not native or not args.version.endswith("+shared"):
            raise ValueError("--shared-tools requires a native feed version ending in +shared")
        if any(getattr(args, m, None) for m in MODULES):
            raise ValueError("supply the shared binary or individual workers, not both")
        check_elf(shared, args.arch, static=True)
    elif native and args.version.endswith("+shared"):
        raise ValueError("a +shared feed requires --shared-tools")
    check_elf(args.panel, args.arch, static=native)
    workers = {}
    if native:
        if not args.geo and not shared:
            raise ValueError("native Rust feed requires --geo")
        for module in (("trace", "tgws") if shared else ("runs", "blockcheck", "strategies", "trace", "tgws")):
            binary = getattr(args, module, None)
            if not binary:
                raise ValueError(f"native Rust profile requires --{module}")
            check_elf(binary, args.arch, static=True)
            workers[module] = binary
    modules = MODULES
    if args.geo is not None:
        check_elf(args.geo, args.arch, static=native)
    elif not shared:
        modules = tuple(module for module in MODULES if module != "geo")
        print("Building without the Geo package (no target --geo helper supplied)")
    chunks = {}
    for module in modules:
        files = sorted((args.ui / module).glob("*"))
        if len(files) != 1 or not re.fullmatch(rf"{module}-[A-Za-z0-9_-]+\.js\.gz", files[0].name):
            raise ValueError(f"expected exactly one {module}-<hash>.js.gz in {args.ui / module}")
        with gzip.open(files[0], "rb") as js:
            if not js.read():
                raise ValueError(f"empty module {files[0]}")
        chunks[module] = files[0]
    # The compact server embeds its Vite manifest verbatim. A full build, or
    # chunks left over from a different frontend build, cannot serve this UI.
    with args.panel.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as panel:
        for module, chunk in chunks.items():
            expected = f"modules/{module}/{chunk.name.removesuffix('.gz')}".encode()
            if panel.find(expected) == -1:
                raise ValueError(f"compact panel manifest does not reference {chunk.name}")

    # Publish only a complete feed. Each architecture/version has its own
    # directory; accidentally reusing an older feed could mix chunk builds.
    args.out.parent.mkdir(parents=True, exist_ok=True)
    if args.out.exists() and (not args.out.is_dir() or any(args.out.iterdir())):
        raise ValueError(f"output directory must be empty or new: {args.out}")
    with tempfile.TemporaryDirectory(dir=args.out.parent) as tmp:
        stage = Path(tmp) / "feed"
        stage.mkdir()
        package = recipe.add if sdk_arch else make_package
        base = [(f"{LIB}/n2s-compact", args.panel, 0o755)]
        if native:
            if args.arch == "x86_64":
                target = "x86_64-unknown-linux-musl"
            elif "armv7" in args.arch:
                target = "armv7-unknown-linux-musleabihf"
            elif "aarch64" in args.arch or "arm64" in args.arch:
                target = "aarch64-unknown-linux-musl"
            elif "mipsel" in args.arch or "mipsle" in args.arch:
                target = "mipsel-unknown-linux-musl"
            elif "mips" in args.arch:
                target = "mips-unknown-linux-musl"
            else:
                raise ValueError(f"unsupported native Rust target {args.arch}")
            notices = stage / "RUST-THIRD-PARTY-NOTICES.tar.gz"
            notices.write_bytes(pack(license_files(target, shared=bool(shared))))
            base.append(("opt/share/licenses/nfqws2-strategy/" + notices.name, notices, 0o644))
            base.append(("opt/share/licenses/nfqws2-strategy/LICENSE-crypt",
                         ROOT / "rust/auth/LICENSE-crypt", 0o644))
        base.extend((f"{LIB}/{script}.sh", ROOT / "packaging" / f"{script}.sh", 0o755)
                    for script in ("install", "uninstall"))
        base_hooks = ("preinst", "postinst", "prerm") if native and not sdk_arch else ("postinst", "prerm")
        records = [package(stage, BASE, args.version, args.arch, "Compact router panel",
                                base, hooks=base_hooks)]
        if shared:
            records.append(package(stage, TOOLS, args.version, args.arch,
                                        "Shared executable for optional panel commands",
                                        [(f"{LIB}/modules/tools/nfqws2-tools", shared, 0o755)]))
        for module, chunk in chunks.items():
            files = [(f"{LIB}/modules/{module}/{chunk.name}", chunk, 0o644)]
            requires = []
            pinned = [TOOLS] if shared else []
            description = f"Compact router panel {module} module"
            if module in workers:
                files.append((f"{LIB}/modules/{module}/nfqws2-{module}", workers[module], 0o755))
            elif shared:
                files.append((f"{LIB}/modules/{module}/nfqws2-{module}", TOOL_LINK, 0o777))
            if native and module in ("blockcheck", "geo", "runs"):
                requires.append("curl")
            if native and module == "runs":
                requires.append("ca-certificates")
                description = "HTTPS checks through the current router configuration and saved run reports"
            if native and module == "blockcheck":
                description = "BlockCheck (requires firmware ip and iptables commands)"
            if module == "geo" and not shared:
                files.append((f"{LIB}/modules/geo/nfqws2-geo", args.geo, 0o755))
            if module == "strategies":
                files.append((f"{LIB}/modules/strategies/catalog.json", CATALOG, 0o644))
            if module == "runs" and not native:
                pinned.append("nfqws2-strategy-strategies")
            records.append(package(stage, f"nfqws2-strategy-{module}", args.version,
                                        args.arch if native or module == "geo" else "all",
                                        description, files, requires=requires,
                                        pinned=pinned))
        if native:
            for module, description, dependency in (
                ("trace", "Connection tracing and packet capture", "tcpdump"),
                ("tgws", "Telegram MTProto over TLS WebSocket", "ca-certificates"),
            ):
                files = [(f"{LIB}/modules/{module}/nfqws2-{module}", workers[module], 0o755)]
                if module == "tgws":
                    files.append(("opt/share/licenses/nfqws2-strategy/TGWS-LICENSE.txt",
                                  ROOT / "internal/services/tgws/LICENSE.upstream", 0o644))
                records.append(package(stage, f"nfqws2-strategy-{module}", args.version,
                                            args.arch, description, files, requires=[dependency]))
        if sdk_arch:
            recipe.finish(stage)
        else:
            index = "\n".join(records).encode()
            (stage / "Packages").write_bytes(index)
            with (stage / "Packages.gz").open("wb") as dst:
                with gzip.GzipFile(filename="", fileobj=dst, mode="wb", mtime=0) as compressed:
                    compressed.write(index)
        (stage / "THIRD-PARTY-NOTICES.txt").write_bytes(
            (ROOT / "THIRD_PARTY_NOTICES.md").read_bytes() + b"\n" +
            (ROOT / "THIRD_PARTY_LICENSES/Frontend-LICENSES.txt").read_bytes())
        shutil.copyfile(ROOT / "THIRD_PARTY_LICENSES/AdGuard-urlfilter-GPL-3.0.txt",
                        stage / "ADGUARD-URLFILTER-LICENSE.txt")
        shutil.copyfile(ROOT / "internal/services/tgws/LICENSE.upstream", stage / "TGWS-LICENSE.txt")
        if args.out.exists():
            args.out.rmdir()
        stage.rename(args.out)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="opkg version, e.g. 1.8.7-1")
    parser.add_argument("--openwrt-arch", help="emit an SDK recipe for this CONFIG_TARGET_ARCH_PACKAGES")
    parser.add_argument("--arch", required=True, help="target architecture from opkg print-architecture")
    parser.add_argument("--panel", type=Path, required=True, help="Linux panel built with the compact profile")
    parser.add_argument("--native-rust", action="store_true", help="package the native Rust panel and optional executables")
    parser.add_argument("--shared-tools", type=Path, help="one multicall binary for the four optional pages")
    parser.add_argument("--runs", type=Path, help="native Rust current-HTTPS measurement and report helper")
    parser.add_argument("--blockcheck", type=Path, help="native Rust BlockCheck worker")
    parser.add_argument("--trace", type=Path, help="native Rust tracing and packet capture helper")
    parser.add_argument("--strategies", type=Path, help="native Rust service strategy compiler")
    parser.add_argument("--tgws", type=Path, help="native Rust Telegram WebSocket proxy")
    parser.add_argument("--geo", type=Path, help="include the Geo package with this target's nfqws2-geo")
    parser.add_argument("--ui", type=Path, default=ROOT / "dist/compact-ui/modules")
    parser.add_argument("--out", type=Path, required=True, help="new or empty feed directory")
    try:
        build(parser.parse_args())
    except (ValueError, OSError, EOFError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"build-compact-feed: {error}\n")
