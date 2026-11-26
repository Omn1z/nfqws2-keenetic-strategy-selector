"""Validate executable load segments and the router target ABI before packaging."""

def check_elf(path, arch, *, static=False):
    with path.open("rb") as stream:
        header = stream.read(64)
    # Check machine, class and endianness; the builder selects the CPU/ABI
    # baseline and libc/toolchain for the target Entware device.
    if "aarch64" in arch or "arm64" in arch:
        expected = (183, 2, 1)
    elif "armv7" in arch or "armv8" in arch:
        expected = (40, 1, 1)
    elif "mips" in arch and "64" not in arch:
        expected = (8, 1, 1 if "mipsel" in arch or "mipsle" in arch else 2)
    elif "x64" in arch or "x86_64" in arch or "amd64" in arch:
        expected = (62, 2, 1)
    else:
        raise ValueError(f"unsupported Entware architecture {arch}")
    byteorder = "little" if header[5:6] == b"\x01" else "big"
    if (len(header) < 52 or header[:4] != b"\x7fELF"
            or int.from_bytes(header[16:18], byteorder) not in (2, 3)
            or (int.from_bytes(header[18:20], byteorder), header[4], header[5]) != expected):
        raise ValueError(f"{path} is not an ELF executable for {arch}")
    if not static:
        return
    def word(data, start, width):
        return int.from_bytes(data[start:start + width], byteorder)
    is_64 = header[4] == 2
    offset = word(header, 32 if is_64 else 28, 8 if is_64 else 4)
    stride = word(header, 54 if is_64 else 42, 2)
    count = word(header, 56 if is_64 else 44, 2)
    if not count or stride != (56 if is_64 else 32) or offset + count * stride > path.stat().st_size:
        raise ValueError(f"{path} has invalid ELF program headers")
    flags = word(header, 48 if is_64 else 36, 4)
    if "armv7" in arch and not flags & 0x400:
        raise ValueError(f"{path} lacks the ARM hard-float ABI flag")
    with path.open("rb") as stream:
        stream.seek(offset)
        table = stream.read(count * stride)
        loadable = False
        soft_float = False
        for n in range(0, len(table), stride):
            kind = word(table, n, 4)
            if kind == 3:  # PT_INTERP
                raise ValueError(f"{path} requires a dynamic loader")
            if kind == 1:
                loadable = True
            if "mips" in arch and kind == 0x70000003:  # PT_MIPS_ABIFLAGS
                stream.seek(word(table, n + 4, 4))
                abi = stream.read(24)
                soft_float = len(abi) == 24 and word(abi, 0, 2) == 0 and abi[7] == 3
        if not loadable:
            raise ValueError(f"{path} has no loadable ELF segment")
        if "mips" in arch and (flags & 0xf000 != 0x1000 or not soft_float):
            raise ValueError(f"{path} lacks the MIPS o32 soft-float ABI")
