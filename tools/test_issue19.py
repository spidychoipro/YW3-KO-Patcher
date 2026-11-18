"""Patched CCI must stay recognizable as NCSD by GodMode9."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

import smoke_test as smoke

app = smoke.app
c = smoke.converter
EXE = Path(os.environ.get('YW3KO_TEST_XDELTA', str(app.cache_dir() / 'xdelta3.exe')))


def make_cci(path: Path, mutate=None, stale_size: int | None = None) -> Path:
    title = app.YW3_BASE_TITLE
    ncch = bytearray(smoke.make_crypto_ncch(title, None))
    ncch[0x18F] |= 4
    target = bytearray(ncch)
    if mutate is not None:
        mutate(target)
    header = bytearray(c._build_ncsd_header([(bytes(ncch[:512]), len(ncch))] * 2))
    if stale_size is not None:
        header[0x104:0x108] = stale_size.to_bytes(4, 'little')
        header[0x300:0x304] = (stale_size * c.MEDIA_UNIT).to_bytes(4, 'little')
    path.write_bytes(bytes(header) + ncch + target)
    return path


def profile(path: Path, key: str):
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


class Issue19Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_stale_size_repaired_without_touching_game_regions(self):
        path = make_cci(self.root / 'stale.cci', stale_size=0x30)
        info = c.read_ncsd_container(path)
        self.assertEqual(info.size_units, 0x30)
        self.assertEqual(info.structural_issues(), [])
        before = bytearray(path.read_bytes())
        old_size, new_size = c.repair_ncsd_size(path, lambda _: None)
        self.assertEqual(old_size, 0x30)
        self.assertEqual(new_size, 0x50)
        after = path.read_bytes()
        for offset in (0x104, 0x300):
            before[offset:offset + 4] = after[offset:offset + 4]
        self.assertEqual(bytes(before), after, '게임 영역이 바뀌었습니다')
        fixed = c.validate_ncsd_container(path)
        self.assertEqual(fixed.size_units, fixed.partition_end_units)
        self.assertEqual(fixed.size_bytes, path.stat().st_size)
        self.assertEqual(fixed.card_size_bytes, path.stat().st_size)
        self.assertEqual(c.repair_ncsd_size(path), (new_size, new_size))

    def test_bad_container_structure_is_rejected(self):
        valid = make_cci(self.root / 'valid.cci')
        mutations = {
            'media_id': lambda data: data.__setitem__(slice(0x108, 0x110), bytes(8)),
            'fs_type': lambda data: data.__setitem__(0x112, 1),
            'overlap': lambda data: data.__setitem__(slice(0x128, 0x12C), (2).to_bytes(4, 'little')),
            'out_of_range': lambda data: data.__setitem__(slice(0x124, 0x128), (0x10000).to_bytes(4, 'little')),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                path = self.root / (name + '.cci')
                data = bytearray(valid.read_bytes())
                mutate(data)
                path.write_bytes(data)
                with self.assertRaises(c.ConvertError):
                    c.repair_ncsd_size(path)

    def test_apply_patch_repairs_stale_result_header(self):
        if not EXE.is_file():
            self.skipTest('Run smoke_test.py first or set YW3KO_TEST_XDELTA')
        self.assertEqual(app.sha256_file(EXE), app.XDETTA_EXE_SHA256)
        source = make_cci(self.root / 'source.cci')
        target = make_cci(self.root / 'target.cci',
                          mutate=lambda data: data.__setitem__(0x1250, data[0x1250] ^ 0x55),
                          stale_size=0x30)
        role = app.Role(
            key='base', label='본편', patch_name='p.xdelta', patch_size=1,
            patch_sha256='0' * 64, result_name='YW3_Sukiyaki_KO_base.cci',
            result_size=target.stat().st_size, result_sha256=app.sha256_file(target),
            source_size=source.stat().st_size,
            source_profile=profile(source, 'base'), source_sha256=app.sha256_file(source),
            target_profile=profile(target, 'base'))
        delta = self.root / 'p.xdelta'
        app.subprocess.run([str(EXE), '-e', '-f', '-W', '16384',
                            '-s', str(source), str(target), str(delta)],
                           capture_output=True, check=True)
        original = source.read_bytes()
        report = {}
        result = app.apply_patch(role, source, self.root, EXE, delta, True, True,
                                 lambda _: None, lambda _: None, lambda _: None,
                                 strict=False, report=report, source_verified=True)
        self.assertEqual(source.read_bytes(), original)
        info = c.validate_ncsd_container(result)
        self.assertEqual(info.size_units, info.partition_end_units)
        self.assertEqual(info.size_bytes, result.stat().st_size)
        self.assertTrue(report.get('ncsd_size_repaired'))
        self.assertEqual(app.check_source_profile(result, role, c.Keys(),
                                                  lambda _: None, lambda _: None, target=True), [])


if __name__ == '__main__':
    unittest.main()
