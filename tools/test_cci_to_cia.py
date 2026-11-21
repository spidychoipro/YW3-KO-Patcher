"""CCI -> 실기용 CIA 변환 구조 테스트."""

import hashlib
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import yw3convert as converter  # noqa: E402
import yw3external as external  # noqa: E402


def fake_ncch(title_id: int) -> bytes:
    head = bytearray(0x200)
    head[0x100:0x104] = b"NCCH"
    head[0x104:0x108] = (1).to_bytes(4, "little")
    head[0x118:0x120] = title_id.to_bytes(8, "little")
    head[0x18F] = 0x04  # no crypto
    return bytes(head)


class CciToCiaTest(unittest.TestCase):
    def test_builds_plain_cia_with_hashes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            base_title = 0x00040000001AF400
            heads = [fake_ncch(base_title), fake_ncch(0x00050000001AF400)]
            header = converter._build_ncsd_header([(head, len(head)) for head in heads])
            cci = root / "test.cci"
            cia = root / "test.cia"
            with cci.open("wb") as handle:
                handle.write(header)
                for head in heads:
                    handle.write(head)

            converter.cci_to_cia(cci, cia, lambda _message: None)

            info = converter.read_cia(cia)
            self.assertEqual(info.title_id, base_title)
            self.assertFalse(info.needs_key)
            self.assertEqual(len(info.contents), 2)
            self.assertEqual([item.index for item in info.contents], [0, 1])

            with cia.open("rb") as handle:
                header = handle.read(converter.CIA_HEADER_SIZE)
            self.assertEqual(header[0x20] & 0xC0, 0xC0)  # content 0, 1 present
            ticket_sig = converter._sig_data_size(int.from_bytes(info.ticket[0:4], "big"))
            self.assertTrue(any(info.ticket[ticket_sig + 0x7F:ticket_sig + 0x8F]))

            sig = converter._sig_data_size(int.from_bytes(info.tmd[0:4], "big"))
            records = info.tmd[sig + 0xC4 + 64 * 0x24:]
            with cia.open("rb") as handle:
                for item in info.contents:
                    handle.seek(item.offset)
                    raw = handle.read(item.size)
                    record = records[item.index * 0x30:(item.index + 1) * 0x30]
                    self.assertEqual(hashlib.sha256(raw).digest(), record[16:48])
                    self.assertEqual(int.from_bytes(record[8:16], "big"), item.size)


    def test_locked_destination_uses_alternate_name(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            head = fake_ncch(0x00040000001AF400)
            header = converter._build_ncsd_header([(head, len(head))])
            cci = root / "test.cci"
            cia = root / "test.cia"
            with cci.open("wb") as handle:
                handle.write(header)
                handle.write(head)
            cia.write_bytes(b"old locked file")

            with external.protect_source(cia):
                created = converter.cci_to_cia(cci, cia, lambda _message: None)

            self.assertEqual(created.name, "test_2.cia")
            self.assertTrue(created.is_file())
            self.assertEqual(cia.read_bytes(), b"old locked file")
            self.assertFalse((root / "test.cia.part").exists())


if __name__ == "__main__":
    unittest.main()
