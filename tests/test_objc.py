from __future__ import annotations

import struct
import unittest

from ipalift.macho import MachOSlice, Section, Segment
from ipalift.objc import ObjC2Parser


class ObjectiveCTests(unittest.TestCase):
    def _slice(self) -> MachOSlice:
        data = bytearray(0x600)

        def put(offset: int, fmt: str, *values: int) -> None:
            struct.pack_into("<" + fmt, data, offset, *values)

        put(0x000, "I", 0x1100)  # __objc_classlist
        put(0x100, "IIIII", 0x1120, 0, 0, 0, 0x1140)
        put(0x120, "IIIII", 0x1120, 0, 0, 0, 0x1170)
        put(0x140, "IIIIIIIIII", 0, 0, 8, 0, 0x1200, 0x11A0, 0, 0, 0, 0)
        put(0x170, "IIIIIIIIII", 0, 0, 8, 0, 0x1200, 0x11C0, 0, 0, 0, 0)
        put(0x1A0, "IIIII", 12, 1, 0x1210, 0x1220, 0x2100)
        put(0x1C0, "IIIII", 12, 1, 0x1230, 0x1220, 0x2200)
        data[0x200:0x20D] = b"FixtureClass\0"
        data[0x210:0x21A] = b"doThing:\0"
        data[0x220:0x228] = b"v12@0:4\0"
        data[0x230:0x23A] = b"sharedOne\0"

        segment = Segment("__DATA", 0x1000, len(data), 0, len(data), 7, 3, 0)
        section = Section("__objc_classlist", "__DATA", 0x1000, 4, 0, 2, 0, 0, 0, 0, 0)
        return MachOSlice(
            bytes(data), 0, len(data), "<", 32, "MH_MAGIC", 12, 6, 2,
            0, 0, 0, None, segments=[segment], sections=[section]
        )

    def test_recovers_class_and_method_implementation_addresses(self) -> None:
        result = ObjC2Parser(self._slice()).parse()
        self.assertEqual([], result.errors)
        self.assertEqual(1, len(result.classes))
        recovered = result.classes[0]
        self.assertEqual("FixtureClass", recovered["name"])
        self.assertEqual("doThing:", recovered["instance_methods"][0]["selector"])
        self.assertEqual(0x2100, recovered["instance_methods"][0]["implementation_address"])
        self.assertEqual("sharedOne", recovered["class_methods"][0]["selector"])
        self.assertEqual(0x2200, recovered["class_methods"][0]["implementation_address"])


if __name__ == "__main__":
    unittest.main()

