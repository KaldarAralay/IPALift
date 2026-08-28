"""Dependency-free Mach-O parsing for deterministic IPA inventory reports."""

from __future__ import annotations

import struct
import uuid as uuidlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import MachOError


MAGIC_TABLE = {
    b"\xce\xfa\xed\xfe": ("<", 32, "MH_MAGIC"),
    b"\xfe\xed\xfa\xce": (">", 32, "MH_CIGAM"),
    b"\xcf\xfa\xed\xfe": ("<", 64, "MH_MAGIC_64"),
    b"\xfe\xed\xfa\xcf": (">", 64, "MH_CIGAM_64"),
}

FAT_MAGIC_TABLE = {
    b"\xca\xfe\xba\xbe": (">", 32, "FAT_MAGIC"),
    b"\xbe\xba\xfe\xca": ("<", 32, "FAT_CIGAM"),
    b"\xca\xfe\xba\xbf": (">", 64, "FAT_MAGIC_64"),
    b"\xbf\xba\xfe\xca": ("<", 64, "FAT_CIGAM_64"),
}

CPU_TYPES = {
    7: "x86",
    12: "arm",
    18: "powerpc",
    0x01000007: "x86_64",
    0x0100000C: "arm64",
    0x01000012: "powerpc64",
}

ARM_SUBTYPES = {
    0: "all",
    5: "v4t",
    6: "v6",
    7: "v5tej",
    8: "xscale",
    9: "v7",
    10: "v7f",
    11: "v7s",
    12: "v7k",
    13: "v8",
    14: "v6m",
    15: "v7m",
    16: "v7em",
}

FILE_TYPES = {
    1: "object",
    2: "executable",
    3: "fixed_vm_library",
    4: "core",
    5: "preload",
    6: "dynamic_library",
    7: "dynamic_linker",
    8: "bundle",
    9: "dynamic_library_stub",
    10: "debug_symbols",
    11: "kernel_collection",
}

LOAD_COMMANDS = {
    0x1: "LC_SEGMENT",
    0x2: "LC_SYMTAB",
    0x3: "LC_SYMSEG",
    0x4: "LC_THREAD",
    0x5: "LC_UNIXTHREAD",
    0x6: "LC_LOADFVMLIB",
    0x7: "LC_IDFVMLIB",
    0x8: "LC_IDENT",
    0x9: "LC_FVMFILE",
    0xA: "LC_PREPAGE",
    0xB: "LC_DYSYMTAB",
    0xC: "LC_LOAD_DYLIB",
    0xD: "LC_ID_DYLIB",
    0xE: "LC_LOAD_DYLINKER",
    0xF: "LC_ID_DYLINKER",
    0x10: "LC_PREBOUND_DYLIB",
    0x11: "LC_ROUTINES",
    0x12: "LC_SUB_FRAMEWORK",
    0x13: "LC_SUB_UMBRELLA",
    0x14: "LC_SUB_CLIENT",
    0x15: "LC_SUB_LIBRARY",
    0x16: "LC_TWOLEVEL_HINTS",
    0x17: "LC_PREBIND_CKSUM",
    0x18: "LC_LOAD_WEAK_DYLIB",
    0x19: "LC_SEGMENT_64",
    0x1A: "LC_ROUTINES_64",
    0x1B: "LC_UUID",
    0x1C: "LC_RPATH",
    0x1D: "LC_CODE_SIGNATURE",
    0x1E: "LC_SEGMENT_SPLIT_INFO",
    0x20: "LC_LAZY_LOAD_DYLIB",
    0x21: "LC_ENCRYPTION_INFO",
    0x22: "LC_DYLD_INFO",
    0x23: "LC_LOAD_UPWARD_DYLIB",
    0x24: "LC_VERSION_MIN_MACOSX",
    0x25: "LC_VERSION_MIN_IPHONEOS",
    0x26: "LC_FUNCTION_STARTS",
    0x27: "LC_DYLD_ENVIRONMENT",
    0x28: "LC_MAIN",
    0x29: "LC_DATA_IN_CODE",
    0x2A: "LC_SOURCE_VERSION",
    0x2B: "LC_DYLIB_CODE_SIGN_DRS",
    0x2C: "LC_ENCRYPTION_INFO_64",
    0x2D: "LC_LINKER_OPTION",
    0x2E: "LC_LINKER_OPTIMIZATION_HINT",
    0x2F: "LC_VERSION_MIN_TVOS",
    0x30: "LC_VERSION_MIN_WATCHOS",
    0x31: "LC_NOTE",
    0x32: "LC_BUILD_VERSION",
    0x33: "LC_DYLD_EXPORTS_TRIE",
    0x34: "LC_DYLD_CHAINED_FIXUPS",
    0x35: "LC_FILESET_ENTRY",
}

DYLIB_COMMANDS = {0xC, 0xD, 0x18, 0x20, 0x23}
STRING_COMMANDS = {0xE, 0xF, 0x1C, 0x27}
LINKEDIT_DATA_COMMANDS = {0x1D, 0x1E, 0x26, 0x29, 0x2B, 0x2E, 0x33, 0x34}


def _decode_fixed(value: bytes) -> str:
    return value.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def _version(value: int) -> str:
    return f"{value >> 16}.{(value >> 8) & 0xff}.{value & 0xff}"


def _source_version(value: int) -> str:
    return ".".join(
        str(part)
        for part in (
            (value >> 40) & 0xFFFFFF,
            (value >> 30) & 0x3FF,
            (value >> 20) & 0x3FF,
            (value >> 10) & 0x3FF,
            value & 0x3FF,
        )
    )


def _cpu_subtype_name(cpu_type: int, subtype: int) -> str:
    base = subtype & 0x00FFFFFF
    if cpu_type == 12:
        return ARM_SUBTYPES.get(base, f"unknown-{base}")
    if cpu_type == 0x0100000C:
        return {0: "all", 1: "v8", 2: "arm64e"}.get(base, f"unknown-{base}")
    return str(base)


@dataclass
class Segment:
    name: str
    vm_address: int
    vm_size: int
    file_offset: int
    file_size: int
    max_protection: int
    initial_protection: int
    flags: int


@dataclass
class Section:
    section_name: str
    segment_name: str
    address: int
    size: int
    offset: int
    alignment: int
    relocation_offset: int
    relocation_count: int
    flags: int
    reserved1: int
    reserved2: int
    reserved3: int = 0


@dataclass
class MachOSlice:
    data: bytes
    slice_offset: int
    slice_size: int
    endian: str
    bits: int
    magic_name: str
    cpu_type: int
    cpu_subtype: int
    file_type: int
    command_count: int
    commands_size: int
    flags: int
    reserved: int | None
    segments: list[Segment] = field(default_factory=list)
    sections: list[Section] = field(default_factory=list)
    load_commands: list[dict[str, Any]] = field(default_factory=list)
    linked_libraries: list[dict[str, Any]] = field(default_factory=list)
    imports: list[dict[str, Any]] = field(default_factory=list)
    exports: list[dict[str, Any]] = field(default_factory=list)
    encryption: dict[str, Any] = field(default_factory=lambda: {"command_present": False, "is_encrypted": None})
    deployment_target: dict[str, Any] | None = None
    binary_uuid: str | None = None
    entrypoint: int | None = None
    symbol_table: dict[str, int] | None = None
    dynamic_symbol_table: dict[str, int] | None = None
    symbols_by_index: list[dict[str, Any] | None] = field(default_factory=list, repr=False)
    relocations_by_address: dict[int, str] = field(default_factory=dict, repr=False)

    @property
    def pointer_size(self) -> int:
        return self.bits // 8

    @property
    def architecture_name(self) -> str:
        cpu = CPU_TYPES.get(self.cpu_type, f"cpu-{self.cpu_type}")
        subtype = _cpu_subtype_name(self.cpu_type, self.cpu_subtype)
        return cpu if subtype in ("all", "0") else f"{cpu}{subtype.removeprefix('v')}"

    def _ensure(self, offset: int, size: int, label: str) -> None:
        if offset < 0 or size < 0 or offset + size > self.slice_size:
            raise MachOError(f"{label} is outside the Mach-O slice (offset={offset}, size={size})")

    def unpack(self, fmt: str, offset: int, label: str) -> tuple:
        size = struct.calcsize(self.endian + fmt)
        self._ensure(offset, size, label)
        return struct.unpack_from(self.endian + fmt, self.data, self.slice_offset + offset)

    def bytes_at(self, offset: int, size: int, label: str = "data") -> bytes:
        self._ensure(offset, size, label)
        start = self.slice_offset + offset
        return self.data[start:start + size]

    def vm_to_offset(self, address: int, size: int = 1) -> int | None:
        for segment in self.segments:
            if segment.vm_address <= address and address + size <= segment.vm_address + segment.file_size:
                relative = segment.file_offset + (address - segment.vm_address)
                if 0 <= relative and relative + size <= self.slice_size:
                    return relative
        return None

    def read_pointer_vm(self, address: int) -> int | None:
        offset = self.vm_to_offset(address, self.pointer_size)
        if offset is None:
            return None
        return self.unpack("Q" if self.bits == 64 else "I", offset, "pointer")[0]

    def unpack_vm(self, fmt: str, address: int, label: str) -> tuple | None:
        size = struct.calcsize(self.endian + fmt)
        offset = self.vm_to_offset(address, size)
        if offset is None:
            return None
        return self.unpack(fmt, offset, label)

    def read_cstring_vm(self, address: int, limit: int = 16_384) -> str | None:
        offset = self.vm_to_offset(address)
        if offset is None:
            return None
        available = min(limit, self.slice_size - offset)
        raw = self.bytes_at(offset, available, "C string")
        terminator = raw.find(b"\0")
        if terminator < 0:
            return None
        return raw[:terminator].decode("utf-8", errors="replace")

    def section(self, name: str, segment: str | None = None) -> Section | None:
        for item in self.sections:
            if item.section_name == name and (segment is None or item.segment_name == segment):
                return item
        return None

    def sections_named(self, *names: str) -> list[Section]:
        accepted = set(names)
        return [item for item in self.sections if item.section_name in accepted]

    def as_facts(self) -> dict[str, Any]:
        return {
            "architecture": self.architecture_name,
            "cpu_type": self.cpu_type,
            "cpu_type_name": CPU_TYPES.get(self.cpu_type, "unknown"),
            "cpu_subtype": self.cpu_subtype,
            "cpu_subtype_name": _cpu_subtype_name(self.cpu_type, self.cpu_subtype),
            "bits": self.bits,
            "endianness": "little" if self.endian == "<" else "big",
            "magic": self.magic_name,
            "slice_offset": self.slice_offset,
            "slice_size": self.slice_size,
            "file_type": self.file_type,
            "file_type_name": FILE_TYPES.get(self.file_type, "unknown"),
            "flags": self.flags,
            "load_command_count": self.command_count,
            "load_commands_size": self.commands_size,
            "uuid": self.binary_uuid,
            "entrypoint_file_offset": self.entrypoint,
            "deployment_target": self.deployment_target,
            "encryption": self.encryption,
            "segments": [
                {
                    "name": segment.name,
                    "vm_address": segment.vm_address,
                    "vm_size": segment.vm_size,
                    "file_offset": segment.file_offset,
                    "file_size": segment.file_size,
                    "max_protection": segment.max_protection,
                    "initial_protection": segment.initial_protection,
                    "flags": segment.flags,
                }
                for segment in self.segments
            ],
            "sections": [
                {
                    "segment": section.segment_name,
                    "name": section.section_name,
                    "address": section.address,
                    "size": section.size,
                    "offset": section.offset,
                    "alignment": section.alignment,
                    "relocation_offset": section.relocation_offset,
                    "relocation_count": section.relocation_count,
                    "flags": section.flags,
                    "reserved1": section.reserved1,
                    "reserved2": section.reserved2,
                    "reserved3": section.reserved3,
                }
                for section in self.sections
            ],
            "load_commands": self.load_commands,
            "imports": self.imports,
            "exports": self.exports,
        }


@dataclass
class MachOAnalysis:
    container: str
    slices: list[MachOSlice]

    @property
    def architecture_facts(self) -> dict[str, Any]:
        return {
            "container": self.container,
            "architecture_count": len(self.slices),
            "architectures": [item.as_facts() for item in self.slices],
        }

    @property
    def framework_facts(self) -> dict[str, Any]:
        records: dict[tuple, dict[str, Any]] = {}
        for macho_slice in self.slices:
            for library in macho_slice.linked_libraries:
                key = (
                    library["path"], library["command"], library["current_version"], library["compatibility_version"]
                )
                record = records.setdefault(key, {**library, "architectures": []})
                record["architectures"].append(macho_slice.architecture_name)
        libraries = []
        for record in records.values():
            record["architectures"] = sorted(set(record["architectures"]))
            libraries.append(record)
        libraries.sort(key=lambda item: (item["path"], item["command"]))
        return {"linked_library_count": len(libraries), "linked_libraries": libraries}


def _read_lc_string(blob: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(blob):
        raise MachOError(f"Load-command string offset {offset} is invalid")
    return _decode_fixed(blob[offset:])


def _library_kind(path: str) -> tuple[str, str]:
    if ".framework/" in path:
        tail = path.split(".framework/", 1)[0].rsplit("/", 1)[-1]
        return "framework", tail
    name = path.rsplit("/", 1)[-1]
    if name.endswith(".dylib"):
        name = name[:-6]
    return "dynamic_library", name


def _parse_segment(macho_slice: MachOSlice, command_offset: int, command_size: int, is_64: bool) -> dict[str, Any]:
    if is_64:
        header_size = 72
        values = macho_slice.unpack("II16sQQQQiiII", command_offset, "LC_SEGMENT_64")
        _, _, raw_name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = values
        section_size = 80
    else:
        header_size = 56
        values = macho_slice.unpack("II16sIIIIiiII", command_offset, "LC_SEGMENT")
        _, _, raw_name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = values
        section_size = 68
    if header_size + nsects * section_size > command_size:
        raise MachOError("Segment sections exceed the enclosing load command")
    segment = Segment(_decode_fixed(raw_name), vmaddr, vmsize, fileoff, filesize, maxprot, initprot, flags)
    macho_slice.segments.append(segment)
    section_offset = command_offset + header_size
    section_names: list[str] = []
    for index in range(nsects):
        current = section_offset + index * section_size
        if is_64:
            unpacked = macho_slice.unpack("16s16sQQIIIIIIII", current, "section_64")
            (sectname, segname, address, size, offset, align, reloff, nreloc, secflags,
             reserved1, reserved2, reserved3) = unpacked
        else:
            unpacked = macho_slice.unpack("16s16sIIIIIIIII", current, "section")
            (sectname, segname, address, size, offset, align, reloff, nreloc, secflags,
             reserved1, reserved2) = unpacked
            reserved3 = 0
        section = Section(
            _decode_fixed(sectname), _decode_fixed(segname), address, size, offset, align,
            reloff, nreloc, secflags, reserved1, reserved2, reserved3,
        )
        macho_slice.sections.append(section)
        section_names.append(f"{section.segment_name},{section.section_name}")
    return {
        "segment": segment.name,
        "vm_address": vmaddr,
        "vm_size": vmsize,
        "file_offset": fileoff,
        "file_size": filesize,
        "section_count": nsects,
        "sections": section_names,
    }


def _parse_symbols(macho_slice: MachOSlice) -> None:
    table = macho_slice.symbol_table
    if not table:
        return
    symoff = table["symbol_offset"]
    count = table["symbol_count"]
    stroff = table["string_offset"]
    strsize = table["string_size"]
    entry_size = 16 if macho_slice.bits == 64 else 12
    macho_slice._ensure(symoff, count * entry_size, "symbol table")
    macho_slice._ensure(stroff, strsize, "symbol string table")
    strings = macho_slice.bytes_at(stroff, strsize, "symbol string table")
    imports: dict[str, dict[str, Any]] = {}
    exports: dict[tuple[str, int], dict[str, Any]] = {}
    symbols: list[dict[str, Any] | None] = [None] * count
    for index in range(count):
        offset = symoff + index * entry_size
        if macho_slice.bits == 64:
            strx, symbol_type, section, desc, value = macho_slice.unpack("IBBHQ", offset, "nlist_64")
        else:
            strx, symbol_type, section, desc, value = macho_slice.unpack("IBBHI", offset, "nlist")
        if strx == 0 or strx >= len(strings) or symbol_type & 0xE0:
            continue
        end = strings.find(b"\0", strx)
        if end < 0:
            continue
        name = strings[strx:end].decode("utf-8", errors="replace")
        if not name:
            continue
        type_kind = symbol_type & 0x0E
        external = bool(symbol_type & 0x01)
        symbols[index] = {
            "name": name,
            "type": symbol_type,
            "type_kind": type_kind,
            "section_index": section,
            "description": desc,
            "value": value,
            "external": external,
        }
        if type_kind == 0 and value == 0:
            imports.setdefault(name, {
                "name": name,
                "weak_reference": bool(desc & 0x0040),
                "library_ordinal": (desc >> 8) & 0xFF,
            })
        elif external and type_kind in (0x02, 0x0E):
            exports.setdefault((name, value), {
                "name": name,
                "address": value,
                "section_index": section,
                "weak_definition": bool(desc & 0x0080),
            })
    macho_slice.imports = sorted(imports.values(), key=lambda item: item["name"])
    macho_slice.exports = sorted(exports.values(), key=lambda item: (item["name"], item["address"]))
    macho_slice.symbols_by_index = symbols


def _parse_relocations(macho_slice: MachOSlice) -> None:
    """Resolve external section relocations to symbols for metadata pointers."""
    if not macho_slice.symbols_by_index:
        return
    resolved: dict[int, str] = {}
    for section in macho_slice.sections:
        if not section.relocation_count:
            continue
        macho_slice._ensure(section.relocation_offset, section.relocation_count * 8, "section relocation table")
        for index in range(section.relocation_count):
            offset = section.relocation_offset + index * 8
            raw_address, attributes = macho_slice.unpack("II", offset, "relocation")
            if raw_address & 0x80000000:
                continue
            symbol_index = attributes & 0x00FFFFFF
            is_external = bool(attributes & 0x08000000)
            if not is_external or symbol_index >= len(macho_slice.symbols_by_index):
                continue
            symbol = macho_slice.symbols_by_index[symbol_index]
            if symbol and symbol.get("name"):
                resolved[section.address + raw_address] = str(symbol["name"])
    dynamic = macho_slice.dynamic_symbol_table or {}
    external_offset = int(dynamic.get("external_relocation_offset", 0))
    external_count = int(dynamic.get("external_relocation_count", 0))
    if external_count:
        macho_slice._ensure(external_offset, external_count * 8, "external relocation table")
        for index in range(external_count):
            raw_address, attributes = macho_slice.unpack(
                "II", external_offset + index * 8, "external relocation"
            )
            if raw_address & 0x80000000:
                continue
            symbol_index = attributes & 0x00FFFFFF
            is_external = bool(attributes & 0x08000000)
            if not is_external or symbol_index >= len(macho_slice.symbols_by_index):
                continue
            symbol = macho_slice.symbols_by_index[symbol_index]
            if symbol and symbol.get("name"):
                resolved[raw_address] = str(symbol["name"])
    macho_slice.relocations_by_address = resolved


def _parse_thin(data: bytes, slice_offset: int, slice_size: int) -> MachOSlice:
    if slice_offset < 0 or slice_size < 4 or slice_offset + slice_size > len(data):
        raise MachOError("Mach-O slice bounds are invalid")
    magic_bytes = data[slice_offset:slice_offset + 4]
    if magic_bytes not in MAGIC_TABLE:
        raise MachOError(f"Unsupported Mach-O magic: {magic_bytes.hex()}")
    endian, bits, magic_name = MAGIC_TABLE[magic_bytes]
    header_size = 32 if bits == 64 else 28
    if slice_size < header_size:
        raise MachOError("Mach-O header is truncated")
    if bits == 64:
        header_fmt = endian + "IiiIIIII"
        magic, cpu_type, cpu_subtype, file_type, ncmds, sizeofcmds, flags, reserved = struct.unpack_from(
            header_fmt, data, slice_offset
        )
    else:
        header_fmt = endian + "IiiIIII"
        magic, cpu_type, cpu_subtype, file_type, ncmds, sizeofcmds, flags = struct.unpack_from(
            header_fmt, data, slice_offset
        )
        reserved = None
    del magic
    if header_size + sizeofcmds > slice_size:
        raise MachOError("Mach-O load commands exceed slice bounds")
    result = MachOSlice(
        data, slice_offset, slice_size, endian, bits, magic_name, cpu_type, cpu_subtype,
        file_type, ncmds, sizeofcmds, flags, reserved,
    )
    command_offset = header_size
    command_region_end = header_size + sizeofcmds
    for index in range(ncmds):
        cmd, cmdsize = result.unpack("II", command_offset, f"load command {index}")
        if cmdsize < 8 or command_offset + cmdsize > command_region_end:
            raise MachOError(f"Load command {index} has invalid size {cmdsize}")
        base_cmd = cmd & 0x7FFFFFFF
        command_name = LOAD_COMMANDS.get(base_cmd, f"LC_UNKNOWN_0x{base_cmd:x}")
        detail: dict[str, Any] = {
            "index": index,
            "command": command_name,
            "command_value": cmd,
            "size": cmdsize,
            "required_by_dynamic_linker": bool(cmd & 0x80000000),
        }
        if base_cmd == 0x1:
            detail.update(_parse_segment(result, command_offset, cmdsize, False))
        elif base_cmd == 0x19:
            detail.update(_parse_segment(result, command_offset, cmdsize, True))
        elif base_cmd == 0x2:
            _, _, symoff, nsyms, stroff, strsize = result.unpack("IIIIII", command_offset, "LC_SYMTAB")
            result.symbol_table = {
                "symbol_offset": symoff, "symbol_count": nsyms,
                "string_offset": stroff, "string_size": strsize,
            }
            detail.update(result.symbol_table)
        elif base_cmd == 0xB:
            values = result.unpack("" + "I" * 20, command_offset, "LC_DYSYMTAB")
            fields = (
                "command_value", "size", "local_symbol_index", "local_symbol_count",
                "external_symbol_index", "external_symbol_count", "undefined_symbol_index",
                "undefined_symbol_count", "toc_offset", "toc_count", "module_table_offset",
                "module_table_count", "external_reference_offset", "external_reference_count",
                "indirect_symbol_offset", "indirect_symbol_count", "external_relocation_offset",
                "external_relocation_count", "local_relocation_offset", "local_relocation_count",
            )
            parsed = dict(zip(fields, values))
            parsed.pop("command_value")
            parsed.pop("size")
            result.dynamic_symbol_table = parsed
            detail.update(parsed)
        elif base_cmd in DYLIB_COMMANDS:
            _, _, name_offset, timestamp, current, compatibility = result.unpack("IIIIII", command_offset, command_name)
            blob = result.bytes_at(command_offset, cmdsize, command_name)
            path = _read_lc_string(blob, name_offset)
            kind, name = _library_kind(path)
            library = {
                "path": path,
                "name": name,
                "kind": kind,
                "command": command_name,
                "timestamp": timestamp,
                "current_version": _version(current),
                "compatibility_version": _version(compatibility),
            }
            result.linked_libraries.append(library)
            detail.update(library)
        elif base_cmd in STRING_COMMANDS:
            _, _, string_offset = result.unpack("III", command_offset, command_name)
            blob = result.bytes_at(command_offset, cmdsize, command_name)
            detail["value"] = _read_lc_string(blob, string_offset)
        elif base_cmd in (0x21, 0x2C):
            if base_cmd == 0x2C:
                _, _, cryptoff, cryptsize, cryptid, padding = result.unpack("IIIIII", command_offset, command_name)
                detail["padding"] = padding
            else:
                _, _, cryptoff, cryptsize, cryptid = result.unpack("IIIII", command_offset, command_name)
            result.encryption = {
                "command_present": True,
                "command": command_name,
                "crypt_offset": cryptoff,
                "crypt_size": cryptsize,
                "crypt_id": cryptid,
                "is_encrypted": cryptid != 0,
            }
            detail.update(result.encryption)
        elif base_cmd in (0x24, 0x25, 0x2F, 0x30):
            _, _, version, sdk = result.unpack("IIII", command_offset, command_name)
            platform = {0x24: "macOS", 0x25: "iOS", 0x2F: "tvOS", 0x30: "watchOS"}[base_cmd]
            result.deployment_target = {"platform": platform, "minimum_version": _version(version), "sdk": _version(sdk)}
            detail.update(result.deployment_target)
        elif base_cmd == 0x32:
            _, _, platform, minimum, sdk, tool_count = result.unpack("IIIIII", command_offset, command_name)
            platform_name = {1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 6: "macCatalyst", 7: "iOSSimulator"}.get(platform, f"platform-{platform}")
            result.deployment_target = {"platform": platform_name, "minimum_version": _version(minimum), "sdk": _version(sdk)}
            detail.update({**result.deployment_target, "tool_count": tool_count})
        elif base_cmd == 0x1B:
            raw_uuid = result.bytes_at(command_offset + 8, 16, command_name)
            result.binary_uuid = str(uuidlib.UUID(bytes=raw_uuid))
            detail["uuid"] = result.binary_uuid
        elif base_cmd == 0x28:
            _, _, entryoff, stacksize = result.unpack("IIQQ", command_offset, command_name)
            result.entrypoint = entryoff
            detail.update({"entrypoint_file_offset": entryoff, "stack_size": stacksize})
        elif base_cmd in LINKEDIT_DATA_COMMANDS:
            _, _, dataoff, datasize = result.unpack("IIII", command_offset, command_name)
            detail.update({"data_offset": dataoff, "data_size": datasize})
        elif base_cmd == 0x2A:
            _, _, source_version = result.unpack("IIQ", command_offset, command_name)
            detail["source_version"] = _source_version(source_version)
        result.load_commands.append(detail)
        command_offset += cmdsize
    if command_offset > command_region_end:
        raise MachOError("Parsed load commands overran their declared region")
    _parse_symbols(result)
    _parse_relocations(result)
    return result


def parse_macho_bytes(data: bytes) -> MachOAnalysis:
    if len(data) < 4:
        raise MachOError("Executable is too small to contain a Mach-O header")
    magic = data[:4]
    if magic in MAGIC_TABLE:
        return MachOAnalysis("thin", [_parse_thin(data, 0, len(data))])
    if magic not in FAT_MAGIC_TABLE:
        raise MachOError(f"Executable is not a supported Mach-O file (magic={magic.hex()})")
    endian, fat_bits, container = FAT_MAGIC_TABLE[magic]
    if len(data) < 8:
        raise MachOError("Fat Mach-O header is truncated")
    arch_count = struct.unpack_from(endian + "I", data, 4)[0]
    if arch_count == 0 or arch_count > 128:
        raise MachOError(f"Fat Mach-O architecture count is invalid: {arch_count}")
    entry_size = 32 if fat_bits == 64 else 20
    if 8 + arch_count * entry_size > len(data):
        raise MachOError("Fat Mach-O architecture table is truncated")
    slices: list[MachOSlice] = []
    occupied: list[tuple[int, int]] = []
    for index in range(arch_count):
        offset = 8 + index * entry_size
        if fat_bits == 64:
            _cpu, _subtype, slice_offset, slice_size, _align, _reserved = struct.unpack_from(endian + "iiQQII", data, offset)
        else:
            _cpu, _subtype, slice_offset, slice_size, _align = struct.unpack_from(endian + "iiIII", data, offset)
        if slice_offset + slice_size > len(data) or slice_size < 4:
            raise MachOError(f"Fat Mach-O slice {index} has invalid bounds")
        for existing_start, existing_end in occupied:
            if slice_offset < existing_end and existing_start < slice_offset + slice_size:
                raise MachOError("Fat Mach-O slices overlap")
        occupied.append((slice_offset, slice_offset + slice_size))
        slices.append(_parse_thin(data, slice_offset, slice_size))
    return MachOAnalysis(container, slices)


def parse_macho_file(path: Path) -> MachOAnalysis:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise MachOError(f"Cannot read executable {path}: {exc}") from exc
    return parse_macho_bytes(data)
