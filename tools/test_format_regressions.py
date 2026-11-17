"""Offline format regressions; synthetic data only, no console keys or ROMs."""
import struct
import tempfile
import unittest
from pathlib import Path

import smoke_test as smoke

app = smoke.app
converter = smoke.converter


class FormatRegressions(unittest.TestCase):
    def test_cia_content_precedes_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            title = app.YW3_BASE_TITLE
            ncch = smoke.make_fake_ncch(title)
            title_key = bytes(range(16))
            common = bytes(range(16, 32))
            for encrypted in (False, True):
                with self.subTest(encrypted=encrypted):
                    path = smoke.build_fake_cia(root / 'input.cia', ncch, title,
                                                title_key, common, encrypted)
                    data = bytearray(path.read_bytes())
                    content_offset = converter.read_cia(path).content_area
                    # Standard CIA: header/cert/ticket/TMD/content/meta (GM9 GetCiaInfo).
                    struct.pack_into('<I', data, 0x14, 0x3AC0)
                    data.extend(b'M' * 0x3AC0)
                    path.write_bytes(data)
                    info = converter.read_cia(path, converter.Keys(common=common))
                    self.assertEqual(info.content_area, content_offset)
                    self.assertEqual(info.title_key, title_key if encrypted else None)
                    self.assertEqual(info.needs_key, encrypted)
                    out = converter.cia_to_cci(path, root / 'out.cci',
                                               converter.Keys(common=common), lambda _: None)
                    expected = bytearray(ncch)
                    expected[0x18F] |= 0x04
                    self.assertEqual(out.read_bytes()[0x4000:0x4000 + len(ncch)], expected)

    def test_little_endian_program_id_passes_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            title = app.YW3_BASE_TITLE
            data = bytearray(smoke.make_crypto_ncch(title, None))
            # Literal on-disk bytes, independent of application ID serialization.
            data[0x118:0x120] = bytes.fromhex('00f41a0000000400')
            path = root / 'input.app'
            path.write_bytes(data)
            self.assertEqual(app.inspect_rom(path).title_id, title)
            self.assertEqual(converter.ncch_crypto_info(data).program_id, title)
            specs = tuple(app.profiles.RegionSpec(r.name, r.size,
                          smoke.sha256_bytes(data[r.offset:r.offset + r.size]))
                          for r in converter.ncch_regions(data))
            profile = app.profiles.Profile('base', (
                app.profiles.PartSpec(0, title, '', specs),))
            from unittest.mock import patch
            with patch.dict(app.profiles.PROFILES, {'base': profile}):
                self.assertEqual(app.check_source_profile(path, app.BASE, converter.Keys(),
                                 lambda _: None, lambda _: None), [])


if __name__ == '__main__':
    unittest.main()

