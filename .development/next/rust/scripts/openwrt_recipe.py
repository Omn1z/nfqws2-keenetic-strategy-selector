"""Stage validated compact Rust payloads for OpenWrt's own SDK package builder."""

import re
import shutil
from pathlib import Path


TEMPLATE = Path(__file__).resolve().parents[1] / "packaging/openwrt"
BASE = "nfqws2-strategy-compact"


def rust_arch(sdk_arch):
    if sdk_arch == "x86_64":
        return "x86_64"
    # ARMv7 ELF is hard-float and requires VFPv3-D16. Some OpenWrt ARMv7
    # targets use soft float even on the same CPU. MIPS uses o32 soft-float,
    # the MIPS32r2 ISA, and a target-specific byte order.
    if re.fullmatch(r"aarch64_(?:generic|cortex-a[0-9]+)", sdk_arch):
        return "aarch64"
    if re.fullmatch(r"arm_cortex-a(?:5|7|8|9|15)_(?:neon(?:-vfpv[34])?|vfpv[34](?:-d16)?)", sdk_arch):
        return "armv7"
    match = re.fullmatch(r"(mips|mipsel)_(?:24kc|24kec|74kc|1004kc)", sdk_arch)
    if match:
        return match[1]
    raise ValueError(f"no compatible compact Rust target for SDK architecture {sdk_arch!r}")


class Recipe:
    def __init__(self, sdk_arch, binary_arch, version, shared, pack):
        if rust_arch(sdk_arch) != binary_arch:
            raise ValueError(f"Rust target {binary_arch!r} does not match {sdk_arch!r}")
        # OpenWrt 24.10 and 25.12 both use <upstream>-r<release>. Interleave
        # release numbers so the solver can never mix a shared and split build.
        match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)*)-([1-9][0-9]*)(\+shared)?", version)
        if not match or bool(match[3]) != shared:
            raise ValueError("OpenWrt requires a numeric version and release, e.g. 1.8.7-1")
        self.sdk_arch = sdk_arch
        self.version = match[1]
        self.release = int(match[2]) * 2 - (0 if shared else 1)
        self.pack = pack
        self.definitions = []
        self.names = []

    def add(self, out, name, _version, _arch, description, files, hooks=(), requires=(), pinned=()):
        # SDK hook registration lives in the Makefile, independently of Entware.
        native = []
        for path, source, mode in files:
            if not path.startswith(("opt/lib/nfqws2-strategy/", "opt/share/licenses/nfqws2-strategy/")):
                raise ValueError(f"unexpected compact payload path: {path}")
            native.append(("usr/" + path.removeprefix("opt/"), source, mode))
        payloads = out / "payload"
        payloads.mkdir(exist_ok=True)
        (payloads / f"{name}.tar.gz").write_bytes(self.pack(native, directories=True))

        dependencies = list(requires)
        if name == "nfqws2-strategy-blockcheck":
            # The firmware supplies the appropriate iptables implementation
            # (fw3 legacy or the fw4 nftables compatibility frontend).
            dependencies.extend(("ip-full", "iptables"))
        exact = [BASE, *pinned] if name != BASE else []
        # The SDK supplies VERSION when it evaluates each package. Use the
        # native revision syntax even on opkg SDKs predating the "-r" prefix.
        self.definitions.append(f"PINNED_{name}=" + ", ".join(f"{pkg} (=$(VERSION))" for pkg in exact))
        self.definitions.append(f"$(eval $(call N2SPackage,{name},{description},{' '.join(dependencies)}))")
        self.names.append(name)

    def finish(self, out):
        for file in ("Makefile", "postinst", "prerm", "verify_index.py"):
            shutil.copyfile(TEMPLATE / file, out / file)
        definitions = [
            f"PKG_VERSION:={self.version}", f"PKG_RELEASE:={self.release}",
            f"N2S_ARCH:={self.sdk_arch}", f"N2S_PACKAGES:={' '.join(self.names)}", "",
        ]
        (out / "version.mk").write_text("\n".join(definitions), encoding="ascii", newline="\n")
        (out / "packages.mk").write_text("\n".join(self.definitions) + "\n", encoding="ascii", newline="\n")
