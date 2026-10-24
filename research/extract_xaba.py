"""
Extract .NET assemblies (DLLs) from a .NET MAUI 9+ "libassemblies.<abi>.blob.so"
assembly store file (XABA format), undoing per-entry XALZ/LZ4 compression.

Usage: python extract_xaba.py <path-to-libassemblies.arm64-v8a.blob.so> <output-dir>
"""
import struct
import sys
import os
import lz4.block


class Header:
    def __init__(self, magic, version, entry_count, index_entry_count, index_size):
        self.magic = magic
        self.version = version
        self.entry_count = entry_count
        self.index_entry_count = index_entry_count
        self.index_size = index_size

    @staticmethod
    def from_bytes(data):
        magic, version, entry_count, index_entry_count, index_size = struct.unpack("<5I", data[:20])
        if magic != 0x41424158:
            raise ValueError(f"Not an XABA store (magic={magic:#x})")
        return Header(magic, version, entry_count, index_entry_count, index_size)


class Descriptor:
    def __init__(self, mapping_index, data_offset, data_size, debug_offset, debug_size, config_offset, config_size):
        self.mapping_index = mapping_index
        self.data_offset = data_offset
        self.data_size = data_size
        self.debug_offset = debug_offset
        self.debug_size = debug_size
        self.config_offset = config_offset
        self.config_size = config_size

    @staticmethod
    def from_bytes(data):
        return Descriptor(*struct.unpack("<7I", data[:28]))


def maybe_decompress(data):
    if data[:4] == b"XALZ":
        uncompressed_size = struct.unpack("<I", data[8:12])[0]
        payload = data[12:]
        return lz4.block.decompress(payload, uncompressed_size=uncompressed_size)
    return data


def main():
    so_path, out_dir = sys.argv[1], sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)

    with open(so_path, "rb") as f:
        raw = f.read()

    xaba_off = raw.find(b"XABA")
    if xaba_off < 0:
        print("No XABA magic found in file.")
        return
    print(f"XABA payload starts at file offset {xaba_off:#x} ({xaba_off})")

    buf = raw[xaba_off:]  # treat as its own address space, offsets inside are relative to this
    header = Header.from_bytes(buf)
    print(f"version={header.version} entry_count={header.entry_count} "
          f"index_entry_count={header.index_entry_count} index_size={header.index_size}")

    pos = 20
    pos += header.index_size  # [INDEX] comes right after the header

    descriptors = []
    for _ in range(header.entry_count):
        descriptors.append(Descriptor.from_bytes(buf[pos:pos + 28]))
        pos += 28

    names = []
    for _ in range(header.entry_count):
        (name_len,) = struct.unpack("<I", buf[pos:pos + 4])
        pos += 4
        name = buf[pos:pos + name_len].decode("utf-8", errors="replace")
        pos += name_len
        names.append(name)

    print(f"Read {len(names)} names, extracting...")
    written = 0
    for desc, name in zip(descriptors, names):
        data = buf[desc.data_offset: desc.data_offset + desc.data_size]
        data = maybe_decompress(data)
        out_name = name if name.lower().endswith(".dll") else name + ".dll"
        out_path = os.path.join(out_dir, out_name)
        with open(out_path, "wb") as out:
            out.write(data)
        written += 1
    print(f"Wrote {written} DLLs to {out_dir}")


if __name__ == "__main__":
    main()
