"""Inner-encrypted CIA must fall back to the external decryptor, not blame the user."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import smoke_test as smoke

app = smoke.app
c = smoke.converter


def profile_for(path: Path, key: str):
    data = path.read_bytes()
    parts = []
    for part in app._actual_parts(path, c.Keys()):
        head = data[part.offset:part.offset + 0x200]
        regions = tuple(app.profiles.RegionSpec(
            r.name, r.size,
            hashlib.sha256(data[part.offset + r.offset:part.offset + r.offset + r.size]).hexdigest())
            for r in c.ncch_regions(head))
        parts.append(app.profiles.PartSpec(
            part.index, int.from_bytes(head[0x118:0x120], 'little'), '', regions))
    return app.profiles.Profile(key, tuple(parts))


class Issue18Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.title = app.YW3_BASE_TITLE
        self.common = bytes.fromhex('ffeeddccbbaa99887766554433221100')
        self.title_key = bytes.fromhex('00112233445566778899aabbccddeeff')
        self.good_ncch = smoke.make_crypto_ncch(self.title, None)
        self.good = self.root / 'good.cci'
        header = c._build_ncsd_header([(self.good_ncch[:0x200], len(self.good_ncch))])
        self.good.write_bytes(header + self.good_ncch)
        self.role = app.Role(
            key='base', label='본편', patch_name='p.xdelta', patch_size=1,
            patch_sha256='0' * 64, result_name='result.cci',
            result_size=self.good.stat().st_size, result_sha256='0' * 64,
            source_size=self.good.stat().st_size,
            source_profile=profile_for(self.good, 'base'),
            source_sha256='1' * 64)
        object.__setattr__(self.role, 'target_profile', profile_for(self.good, 'base'))

    def bad_cia(self):
        wrong = bytearray(self.good_ncch)
        wrong[0x1250] ^= 0x5A  # ExeFS payload, still a well formed NCCH header
        return smoke.build_fake_cia(self.root / 'double.cia', bytes(wrong), self.title,
                                    self.title_key, self.common, True)

    def test_profile_mismatch_retries_external_once(self):
        source = self.bad_cia()
        calls = []

        def fake_prepare(path, key, work, cache, download, log, min_size=0):
            calls.append((path, key))
            return self.good

        keys = c.Keys(common=self.common)
        with patch.object(app.external, 'prepare', side_effect=fake_prepare):
            prepared = app.prepare_source(
                self.role, source, self.root, keys, lambda _: None, lambda _: None,
                lambda _: None)
        self.assertEqual(len(calls), 1, calls)
        self.assertEqual(prepared.path, self.good)
        self.assertTrue(prepared.profile_verified)

    def test_second_mismatch_keeps_diagnostic(self):
        source = self.bad_cia()
        calls = []
        bad_cci = self.root / 'still_bad.cci'
        data = bytearray(self.good.read_bytes())
        data[0x4000 + 0x1250] ^= 0x5A
        bad_cci.write_bytes(data)

        def fake_prepare(path, key, work, cache, download, log, min_size=0):
            calls.append((path, key))
            return bad_cci

        cache = self.root / 'cache'
        with patch.dict(os.environ, {app.CACHE_ENV: str(cache)}):
            with patch.object(app.external, 'prepare', side_effect=fake_prepare):
                with self.assertRaises(app.PatchError) as caught:
                    app.prepare_source(
                        self.role, source, self.root, c.Keys(common=self.common),
                        lambda _: None, lambda _: None, lambda _: None)
        self.assertEqual(len(calls), 1, calls)
        self.assertIn('진단 기록', str(caught.exception))
        files = list(cache.glob('diagnostic_*.txt'))
        self.assertEqual(len(files), 1, files)
        text = files[0].read_text(encoding='utf-8')
        self.assertIn(app.APP_VERSION, text)
        self.assertIn('계산값', text)
        self.assertNotIn(self.common.hex(), text)


if __name__ == '__main__':
    unittest.main()
