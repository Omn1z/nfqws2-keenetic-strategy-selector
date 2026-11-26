#!/usr/bin/env python3
"""C compiler and final linker for the two soft-float MIPS musl builds."""
import os
import subprocess
import sys


def command(arch, args):
    if arch not in ("mips", "mipsel"):
        raise ValueError("set N2S_MIPS_TARGET to mipsel or mips")
    # cc-rs also passes the Rust target triple to Clang. Zig uses its own
    # target spelling to select the correct musl headers and startup objects.
    flags = [arg for arg in args if not arg.startswith("--target=")]
    return [os.environ.get("ZIG", "zig"), "cc", "-target", arch + "-linux-musleabi",
            "-mcpu=mips32r2", "-msoft-float", *flags]


if __name__ == "__main__":
    argv = command(os.environ.get("N2S_MIPS_TARGET"), sys.argv[1:])
    if os.name == "nt":
        # Windows exec starts a new process. Cargo needs Zig's actual exit
        # status before it marks the object or executable as up to date.
        sys.exit(subprocess.call(argv))
    os.execvp(argv[0], argv)
