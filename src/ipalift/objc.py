"""Recovery of Objective-C 2 metadata from parsed Mach-O slices."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .macho import MachOAnalysis, MachOSlice, Section


MAX_METADATA_ITEMS = 200_000


def _symbol_class_name(symbol: str | None) -> str | None:
    if not symbol:
        return None
    for prefix in ("_OBJC_CLASS_$_", "OBJC_CLASS_$_", ".objc_class_name_"):
        if symbol.startswith(prefix):
            return symbol[len(prefix):]
    return None


@dataclass
class ObjCSliceResult:
    architecture: str
    runtime: str
    classes: list[dict[str, Any]] = field(default_factory=list)
    categories: list[dict[str, Any]] = field(default_factory=list)
    protocols: list[dict[str, Any]] = field(default_factory=list)
    selectors: list[str] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    hypotheses: list[dict[str, Any]] = field(default_factory=list)

    def facts(self) -> dict[str, Any]:
        return {
            "architecture": self.architecture,
            "runtime": self.runtime,
            "class_count": len(self.classes),
            "category_count": len(self.categories),
            "protocol_count": len(self.protocols),
            "selector_count": len(self.selectors),
            "classes": self.classes,
            "categories": self.categories,
            "protocols": self.protocols,
            "selectors": self.selectors,
        }


class ObjC2Parser:
    def __init__(self, macho_slice: MachOSlice):
        self.slice = macho_slice
        self.ptr_size = macho_slice.pointer_size
        self.ptr_fmt = "Q" if self.ptr_size == 8 else "I"
        self.result = ObjCSliceResult(macho_slice.architecture_name, "objc2")
        self.class_shells: dict[int, dict[str, Any]] = {}
        self.protocol_cache: dict[int, dict[str, Any]] = {}
        self.selectors: set[str] = set()

    def _error(self, code: str, message: str, address: int | None = None) -> None:
        record: dict[str, Any] = {"code": code, "message": message, "architecture": self.slice.architecture_name}
        if address is not None:
            record["address"] = address
        self.result.errors.append(record)

    def _pointer(self, address: int) -> int | None:
        values = self.slice.unpack_vm(self.ptr_fmt, address, "Objective-C pointer")
        return None if values is None else int(values[0])

    def _uint32(self, address: int) -> int | None:
        values = self.slice.unpack_vm("I", address, "Objective-C uint32")
        return None if values is None else int(values[0])

    def _cstring(self, address: int) -> str | None:
        if not address:
            return None
        value = self.slice.read_cstring_vm(address)
        if value is None or not value:
            return None
        return value

    def _pointers_in_section(self, section: Section) -> list[int]:
        if section.size % self.ptr_size:
            self._error(
                "objc_section_alignment",
                f"{section.segment_name},{section.section_name} size is not pointer-aligned",
                section.address,
            )
        count = section.size // self.ptr_size
        if count > MAX_METADATA_ITEMS:
            self._error("objc_section_count", f"Objective-C section contains too many pointers: {count}", section.address)
            return []
        result: list[int] = []
        for index in range(count):
            values = self.slice.unpack(self.ptr_fmt, section.offset + index * self.ptr_size, "Objective-C section pointer")
            pointer = int(values[0])
            if pointer:
                result.append(pointer)
        return result

    def _class_ro(self, address: int) -> dict[str, Any] | None:
        if self.ptr_size == 8:
            values = self.slice.unpack_vm("IIIIQQQQQQQ", address, "class_ro_t")
            if values is None:
                return None
            (flags, instance_start, instance_size, _reserved, ivar_layout, name, methods,
             protocols, ivars, weak_layout, properties) = values
        else:
            values = self.slice.unpack_vm("IIIIIIIIII", address, "class_ro_t")
            if values is None:
                return None
            (flags, instance_start, instance_size, ivar_layout, name, methods,
             protocols, ivars, weak_layout, properties) = values
        class_name = self._cstring(int(name))
        if not class_name:
            return None
        return {
            "address": address,
            "flags": int(flags),
            "instance_start": int(instance_start),
            "instance_size": int(instance_size),
            "ivar_layout_address": int(ivar_layout),
            "name": class_name,
            "methods_address": int(methods),
            "protocols_address": int(protocols),
            "ivars_address": int(ivars),
            "weak_ivar_layout_address": int(weak_layout),
            "properties_address": int(properties),
        }

    def _class_shell(self, address: int) -> dict[str, Any] | None:
        if address in self.class_shells:
            return self.class_shells[address]
        values = self.slice.unpack_vm(self.ptr_fmt * 5, address, "class_t")
        if values is None:
            self._error("objc_class_unmapped", "Class record is not mapped in the executable", address)
            return None
        isa, superclass, cache, vtable, data_bits = (int(value) for value in values)
        # objc4 reserves two low flag bits in 32-bit class_data_bits_t and
        # three in the 64-bit form. A 4-byte-aligned 32-bit ro pointer may
        # legitimately have bit 2 set.
        ro_address = data_bits & (~0x7 if self.ptr_size == 8 else ~0x3)
        ro = self._class_ro(ro_address)
        if ro is None:
            self._error("objc_class_ro_invalid", "Class has an unreadable class_ro_t record", address)
            return None
        shell = {
            "address": address,
            "isa_address": isa,
            "superclass_address": superclass,
            "cache_address": cache,
            "vtable_address": vtable,
            "data_address": ro_address,
            "ro": ro,
        }
        self.class_shells[address] = shell
        return shell

    def _method_list(self, address: int, kind: str) -> list[dict[str, Any]]:
        if not address:
            return []
        header = self.slice.unpack_vm("II", address, "method_list_t")
        if header is None:
            self._error("objc_method_list_unmapped", "Method list is not mapped", address)
            return []
        entry_flags, count = (int(value) for value in header)
        if count > MAX_METADATA_ITEMS:
            self._error("objc_method_count", f"Method list count is unsafe: {count}", address)
            return []
        relative = bool(entry_flags & 0x80000000)
        entry_size = entry_flags & 0xFFFF
        minimum = 12 if relative else self.ptr_size * 3
        if entry_size < minimum:
            entry_size = minimum
        methods: list[dict[str, Any]] = []
        for index in range(count):
            entry_address = address + 8 + index * entry_size
            if relative:
                values = self.slice.unpack_vm("iii", entry_address, "relative method_t")
                if values is None:
                    self._error("objc_method_unmapped", "Relative method entry is not mapped", entry_address)
                    break
                name_relative, types_relative, imp_relative = (int(value) for value in values)
                name_address = entry_address + name_relative
                types_address = entry_address + 4 + types_relative
                implementation = entry_address + 8 + imp_relative
            else:
                values = self.slice.unpack_vm(self.ptr_fmt * 3, entry_address, "method_t")
                if values is None:
                    self._error("objc_method_unmapped", "Method entry is not mapped", entry_address)
                    break
                name_address, types_address, implementation = (int(value) for value in values)
            name = self._cstring(name_address)
            if not name and relative:
                indirect = self._pointer(name_address)
                name = self._cstring(indirect or 0)
            if not name:
                self._error("objc_method_name", "Method selector string is unreadable", entry_address)
                continue
            self.selectors.add(name)
            methods.append({
                "selector": name,
                "type_encoding": self._cstring(types_address),
                "implementation_address": implementation,
                "metadata_address": entry_address,
                "kind": kind,
            })
        return sorted(methods, key=lambda item: (item["selector"], item["implementation_address"]))

    def _method_descriptions(self, address: int, kind: str, required: bool) -> list[dict[str, Any]]:
        if not address:
            return []
        header = self.slice.unpack_vm("II", address, "protocol method list")
        if header is None:
            self._error("objc_protocol_methods_unmapped", "Protocol method list is not mapped", address)
            return []
        entry_size, count = (int(value) for value in header)
        minimum = self.ptr_size * 2
        entry_size &= 0xFFFF
        if entry_size < minimum:
            entry_size = minimum
        if count > MAX_METADATA_ITEMS:
            self._error("objc_protocol_method_count", f"Protocol method count is unsafe: {count}", address)
            return []
        methods: list[dict[str, Any]] = []
        for index in range(count):
            entry_address = address + 8 + index * entry_size
            values = self.slice.unpack_vm(self.ptr_fmt * 2, entry_address, "method_description_t")
            if values is None:
                break
            name_address, types_address = (int(value) for value in values)
            name = self._cstring(name_address)
            if not name:
                continue
            self.selectors.add(name)
            methods.append({
                "selector": name,
                "type_encoding": self._cstring(types_address),
                "kind": kind,
                "required": required,
            })
        return sorted(methods, key=lambda item: item["selector"])

    def _protocol_addresses(self, address: int) -> list[int]:
        if not address:
            return []
        count_values = self.slice.unpack_vm(self.ptr_fmt, address, "protocol_list_t count")
        if count_values is None:
            return []
        count = int(count_values[0])
        if count > MAX_METADATA_ITEMS:
            self._error("objc_protocol_count", f"Protocol list count is unsafe: {count}", address)
            return []
        pointers: list[int] = []
        for index in range(count):
            pointer = self._pointer(address + self.ptr_size * (index + 1))
            if pointer:
                pointers.append(pointer)
        return pointers

    def _protocol(self, address: int) -> dict[str, Any] | None:
        if address in self.protocol_cache:
            return self.protocol_cache[address]
        values = self.slice.unpack_vm(self.ptr_fmt * 8, address, "protocol_t")
        if values is None:
            self._error("objc_protocol_unmapped", "Protocol record is not mapped", address)
            return None
        (_isa, name_address, inherited_address, instance_methods, class_methods,
         optional_instance, optional_class, properties) = (int(value) for value in values)
        name = self._cstring(name_address)
        if not name:
            self._error("objc_protocol_name", "Protocol name is unreadable", address)
            return None
        record: dict[str, Any] = {
            "name": name,
            "address": address,
            "inherited_protocol_addresses": self._protocol_addresses(inherited_address),
            "inherited_protocols": [],
            "methods": [],
            "properties": self._property_list(properties),
        }
        self.protocol_cache[address] = record
        record["methods"] = sorted(
            self._method_descriptions(instance_methods, "instance", True)
            + self._method_descriptions(class_methods, "class", True)
            + self._method_descriptions(optional_instance, "instance", False)
            + self._method_descriptions(optional_class, "class", False),
            key=lambda item: (item["selector"], item["kind"], not item["required"]),
        )
        inherited_names = []
        for inherited in record["inherited_protocol_addresses"]:
            parsed = self._protocol(inherited)
            if parsed:
                inherited_names.append(parsed["name"])
        record["inherited_protocols"] = sorted(set(inherited_names))
        return record

    def _protocol_names(self, address: int) -> list[str]:
        names = []
        for protocol_address in self._protocol_addresses(address):
            parsed = self._protocol(protocol_address)
            if parsed:
                names.append(parsed["name"])
        return sorted(set(names))

    def _ivar_list(self, address: int) -> list[dict[str, Any]]:
        if not address:
            return []
        header = self.slice.unpack_vm("II", address, "ivar_list_t")
        if header is None:
            return []
        entry_size, count = (int(value) for value in header)
        minimum = self.ptr_size * 3 + 8
        entry_size &= 0xFFFF
        if entry_size < minimum:
            entry_size = minimum
        if count > MAX_METADATA_ITEMS:
            self._error("objc_ivar_count", f"Ivar list count is unsafe: {count}", address)
            return []
        ivars: list[dict[str, Any]] = []
        for index in range(count):
            current = address + 8 + index * entry_size
            values = self.slice.unpack_vm(self.ptr_fmt * 3 + "II", current, "ivar_t")
            if values is None:
                break
            offset_pointer, name_pointer, type_pointer, alignment, size = (int(value) for value in values)
            name = self._cstring(name_pointer)
            if not name:
                continue
            ivar_offset = self._uint32(offset_pointer) if offset_pointer else None
            ivars.append({
                "name": name,
                "type_encoding": self._cstring(type_pointer),
                "offset": ivar_offset,
                "size": size,
                "alignment_log2": alignment,
                "metadata_address": current,
            })
        return sorted(ivars, key=lambda item: (item["offset"] is None, item["offset"] or 0, item["name"]))

    def _property_list(self, address: int) -> list[dict[str, Any]]:
        if not address:
            return []
        header = self.slice.unpack_vm("II", address, "property_list_t")
        if header is None:
            return []
        entry_size, count = (int(value) for value in header)
        minimum = self.ptr_size * 2
        entry_size &= 0xFFFF
        if entry_size < minimum:
            entry_size = minimum
        if count > MAX_METADATA_ITEMS:
            self._error("objc_property_count", f"Property list count is unsafe: {count}", address)
            return []
        properties: list[dict[str, Any]] = []
        for index in range(count):
            current = address + 8 + index * entry_size
            values = self.slice.unpack_vm(self.ptr_fmt * 2, current, "property_t")
            if values is None:
                break
            name_pointer, attributes_pointer = (int(value) for value in values)
            name = self._cstring(name_pointer)
            if name:
                properties.append({
                    "name": name,
                    "attributes": self._cstring(attributes_pointer),
                    "metadata_address": current,
                })
        return sorted(properties, key=lambda item: item["name"])

    def _superclass(self, shell: dict[str, Any], known_classes: dict[int, str]) -> dict[str, Any] | None:
        pointer = int(shell["superclass_address"])
        if pointer in known_classes:
            return {"name": known_classes[pointer], "address": pointer, "source": "class_pointer"}
        field_address = int(shell["address"]) + self.ptr_size
        symbol = self.slice.relocations_by_address.get(field_address)
        symbol_name = _symbol_class_name(symbol)
        if symbol_name:
            return {"name": symbol_name, "address": pointer or None, "source": "external_relocation"}
        if pointer:
            symbol_by_address = {
                int(symbol_record["value"]): _symbol_class_name(str(symbol_record["name"]))
                for symbol_record in self.slice.symbols_by_index
                if symbol_record and symbol_record.get("value")
            }
            if symbol_by_address.get(pointer):
                return {"name": symbol_by_address[pointer], "address": pointer, "source": "symbol_table"}
            return {"name": None, "address": pointer, "source": "unresolved_pointer"}
        return None

    def _parse_classes(self) -> None:
        class_sections = self.slice.sections_named("__objc_classlist")
        addresses = sorted({pointer for section in class_sections for pointer in self._pointers_in_section(section)})
        shells = [shell for address in addresses if (shell := self._class_shell(address)) is not None]
        known = {int(shell["address"]): str(shell["ro"]["name"]) for shell in shells}
        classes: list[dict[str, Any]] = []
        for shell in shells:
            ro = shell["ro"]
            meta = self._class_shell(int(shell["isa_address"])) if shell["isa_address"] else None
            class_methods = self._method_list(int(meta["ro"]["methods_address"]), "class") if meta else []
            classes.append({
                "name": ro["name"],
                "address": shell["address"],
                "metaclass_address": shell["isa_address"] or None,
                "superclass": self._superclass(shell, known),
                "instance_start": ro["instance_start"],
                "instance_size": ro["instance_size"],
                "flags": ro["flags"],
                "protocols": self._protocol_names(int(ro["protocols_address"])),
                "ivars": self._ivar_list(int(ro["ivars_address"])),
                "properties": self._property_list(int(ro["properties_address"])),
                "instance_methods": self._method_list(int(ro["methods_address"]), "instance"),
                "class_methods": class_methods,
            })
        self.result.classes = sorted(classes, key=lambda item: item["name"])

    def _category_target(self, address: int, pointer: int) -> dict[str, Any] | None:
        if pointer and pointer in self.class_shells:
            return {"name": self.class_shells[pointer]["ro"]["name"], "address": pointer, "source": "class_pointer"}
        symbol = self.slice.relocations_by_address.get(address + self.ptr_size)
        name = _symbol_class_name(symbol)
        if name:
            return {"name": name, "address": pointer or None, "source": "external_relocation"}
        return {"name": None, "address": pointer or None, "source": "unresolved"}

    def _parse_categories(self) -> None:
        sections = self.slice.sections_named("__objc_catlist")
        records: list[dict[str, Any]] = []
        for address in sorted({pointer for section in sections for pointer in self._pointers_in_section(section)}):
            values = self.slice.unpack_vm(self.ptr_fmt * 6, address, "category_t")
            if values is None:
                self._error("objc_category_unmapped", "Category record is not mapped", address)
                continue
            name_ptr, class_ptr, instance_methods, class_methods, protocols, properties = (int(value) for value in values)
            name = self._cstring(name_ptr)
            if not name:
                self._error("objc_category_name", "Category name is unreadable", address)
                continue
            records.append({
                "name": name,
                "address": address,
                "target_class": self._category_target(address, class_ptr),
                "protocols": self._protocol_names(protocols),
                "properties": self._property_list(properties),
                "instance_methods": self._method_list(instance_methods, "instance"),
                "class_methods": self._method_list(class_methods, "class"),
            })
        self.result.categories = sorted(records, key=lambda item: (item["target_class"]["name"] or "", item["name"]))

    def _parse_protocol_section(self) -> None:
        sections = self.slice.sections_named("__objc_protolist")
        for address in sorted({pointer for section in sections for pointer in self._pointers_in_section(section)}):
            self._protocol(address)
        self.result.protocols = sorted(self.protocol_cache.values(), key=lambda item: item["name"])

    def _parse_selector_sections(self) -> None:
        for section in self.slice.sections_named("__objc_selrefs"):
            for pointer in self._pointers_in_section(section):
                selector = self._cstring(pointer)
                if selector:
                    self.selectors.add(selector)
        for section in self.slice.sections_named("__objc_methname"):
            raw = self.slice.bytes_at(section.offset, section.size, "Objective-C method names")
            for value in raw.split(b"\0"):
                if value:
                    self.selectors.add(value.decode("utf-8", errors="replace"))

    def parse(self) -> ObjCSliceResult:
        self._parse_classes()
        self._parse_categories()
        self._parse_protocol_section()
        self._parse_selector_sections()
        self.result.selectors = sorted(self.selectors)
        self.result.errors.sort(key=lambda item: (item["code"], item.get("address", -1), item["message"]))
        return self.result


def analyze_objective_c(macho: MachOAnalysis) -> dict[str, Any]:
    slices: list[ObjCSliceResult] = []
    errors: list[dict[str, Any]] = []
    hypotheses: list[dict[str, Any]] = []
    for macho_slice in macho.slices:
        if macho_slice.section("__objc_classlist") is not None:
            parsed = ObjC2Parser(macho_slice).parse()
        elif any(section.segment_name == "__OBJC" for section in macho_slice.sections):
            parsed = ObjCSliceResult(macho_slice.architecture_name, "objc1-unsupported")
            parsed.errors.append({
                "code": "objc1_not_implemented",
                "message": "Legacy Objective-C 1 sections were detected but cannot yet be decoded",
                "architecture": macho_slice.architecture_name,
            })
        else:
            parsed = ObjCSliceResult(macho_slice.architecture_name, "not_detected")
        slices.append(parsed)
        errors.extend(parsed.errors)
        hypotheses.extend(parsed.hypotheses)
    facts = {
        "architecture_count": len(slices),
        "architectures": [parsed.facts() for parsed in slices],
        "total_classes": sum(len(parsed.classes) for parsed in slices),
        "total_categories": sum(len(parsed.categories) for parsed in slices),
        "total_protocols": sum(len(parsed.protocols) for parsed in slices),
        "total_selectors": sum(len(parsed.selectors) for parsed in slices),
    }
    return {"facts": facts, "hypotheses": hypotheses, "errors": errors}
