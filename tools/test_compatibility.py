"""Metadata-only source variants must pass payload verification, never bypass it."""
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import struct
import tempfile
import unittest

import smoke_test as smoke

app = smoke.app
c = smoke.converter
EXE = Path(os.environ.get('YW3KO_TEST_XDELTA', str(app.cache_dir() / 'xdelta3.exe')))


def profile(data, key, parts):
    result = []
    for index, offset, size in parts:
        head = data[offset:offset + 0x200]
        regions = tuple(app.profiles.RegionSpec(r.name, r.size,
            hashlib.sha256(data[offset + r.offset:offset + r.offset + r.size]).hexdigest())
            for r in c.ncch_regions(head))
        result.append(app.profiles.PartSpec(index, int.from_bytes(head[0x118:0x120], 'little'),
                                           '', regions))
    return app.profiles.Profile(key, tuple(result))


def fix_fixture_tmd(path):
    data = bytearray(path.read_bytes())
    tmd = c._align(c._align(c._align(0x2020, 64) + struct.unpack_from('<I', data, 8)[0], 64)
                   + struct.unpack_from('<I', data, 12)[0], 64)
    body = tmd + 0x140
    at = body + 0x9c4
    start = c._align(tmd + struct.unpack_from('<I', data, 16)[0], 64)
    size = int.from_bytes(data[at + 8:at + 16], 'big')
    data[at + 16:at + 48] = hashlib.sha256(data[start:start + size]).digest()
    data[body + 0xc4:body + 0xc8] = bytes.fromhex('00000001')
    data[body + 0xc8:body + 0xe8] = hashlib.sha256(data[at:at + 48]).digest()
    data[body + 0xa4:body + 0xc4] = hashlib.sha256(data[body + 0xc4:body + 0x9c4]).digest()
    path.write_bytes(data)


class CompatibilityTests(unittest.TestCase):
    def setUp(self):
        if not EXE.is_file():
            self.skipTest('Run smoke_test.py first or set YW3KO_TEST_XDELTA to the official xdelta3.exe')
        self.assertEqual(app.sha256_file(EXE), app.XDETTA_EXE_SHA256)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def case(self, key, target_mutator=None):
        title = app.YW3_BASE_TITLE if key == 'base' else app.YW3_UPDATE_TITLE
        ncch = bytearray(smoke.make_crypto_ncch(title, None))
        ncch[0x18f] |= 4
        target_ncch = bytearray(ncch)
        target_ncch[0x1250] ^= 0x55
        source, target = self.root / 'source.bin', self.root / 'target.bin'
        if key == 'base':
            # A second NCCH signature is inside a later xdelta window, outside 0x4000.
            header = c._build_ncsd_header([(bytes(ncch[:512]), len(ncch))] * 2)
            source.write_bytes(header + ncch + ncch)
            target.write_bytes(header + target_ncch + ncch)
        else:
            for path, payload in ((source, ncch), (target, target_ncch)):
                smoke.build_fake_cia(path, bytes(payload), title, bytes(range(16)), bytes(range(16)), False)
                fix_fixture_tmd(path)
        if target_mutator:
            data = bytearray(target.read_bytes())
            target_mutator(data, app._actual_parts(target, c.Keys()))
            target.write_bytes(data)
        parts = [(p.index, p.offset, p.size) for p in app._actual_parts(source, c.Keys())]
        role = app.Role(key=key, label='본편' if key == 'base' else '업데이트', patch_name='p.xdelta',
                        patch_size=1, patch_sha256='0' * 64, result_name='result.' + ('cci' if key == 'base' else 'cia'),
                        result_size=target.stat().st_size, result_sha256=app.sha256_file(target),
                        source_size=source.stat().st_size,
                        source_profile=profile(source.read_bytes(), key, parts))
        # setattr keeps the reproducer runnable against v1.5.0, which ignores these fields.
        object.__setattr__(role, 'source_sha256', app.sha256_file(source))
        object.__setattr__(role, 'target_profile', profile(target.read_bytes(), key, parts))
        delta = self.root / 'p.xdelta'
        app.subprocess.run([str(EXE), '-e', '-f', '-W', '16384', '-s', str(source), str(target), str(delta)],
                           capture_output=True, check=True)
        role = replace(role, patch_size=delta.stat().st_size, patch_sha256=app.sha256_file(delta))
        object.__setattr__(role, 'source_sha256', app.sha256_file(source))
        object.__setattr__(role, 'target_profile', profile(target.read_bytes(), key, parts))
        variant = bytearray(source.read_bytes())
        meta = parts[-1][1] + 0x20
        variant[meta] ^= 0x66  # NCCH RSA signature, outside all game regions.
        source.write_bytes(variant)
        return role, source, delta

    def run_case(self, key, certificate_difference=False):
        role, source, delta = self.case(key)
        if certificate_difference:
            data = bytearray(source.read_bytes())
            data[0x2050] ^= 0x11
            source.write_bytes(data)
        prepared = app.prepare_source(role, source, self.root, c.Keys(), lambda _: None,
                                      lambda _: None, lambda _: None)
        original = source.read_bytes()
        self.assertEqual(app.check_source_profile(source, role, c.Keys(), lambda _: None, lambda _: None), [])
        report = {}
        result = app.apply_patch(role, prepared.path, self.root, EXE, delta, True, True,
            lambda _: None, lambda _: None, lambda _: None,
            strict=not (prepared.converted or getattr(prepared, 'compatibility', False)),
            report=report, allow_header=prepared.allow_header, padded_from=prepared.padded_from)
        self.assertTrue(result.is_file())
        self.assertEqual(source.read_bytes(), original)
        self.assertTrue(report.get('payload_verified'))
        return role, result, report

    def test_update_metadata_does_not_trigger_xdelta_checksum_failure(self):
        _, result, _ = self.run_case('update')
        app.container_verify.update_cia_tmd(result)
        before = result.read_bytes()
        fix_fixture_tmd(result)
        self.assertEqual(result.read_bytes(), before)

    def test_base_later_ncch_signature_is_not_mistaken_for_bad_payload(self):
        self.run_case('base')

    def test_update_certificate_difference_is_compatible(self):
        self.run_case('update', certificate_difference=True)

    def test_modified_source_game_data_is_rejected(self):
        role, source, _ = self.case('update')
        info = c.read_cia(source)
        data = bytearray(source.read_bytes())
        data[info.contents[0].offset + 0x1250] ^= 1
        source.write_bytes(data)
        with self.assertRaisesRegex(app.PatchError, 'ExeFS'):
            app.prepare_source(role, source, self.root, c.Keys(), lambda _: None,
                               lambda _: None, lambda _: None)

    def bad_target(self, mutator):
        role, source, delta = self.case('update', mutator)
        final = self.root / role.result_name
        final.write_bytes(b'previous output')
        with self.assertRaises(app.PatchError):
            app.apply_patch(role, source, self.root, EXE, delta, True, True,
                            lambda _: None, lambda _: None, lambda _: None, strict=False)
        self.assertEqual(final.read_bytes(), b'previous output')
        self.assertFalse(final.with_name(final.name + '.part').exists())

    def test_ncch_header_hash_link_mismatch_is_rejected(self):
        def mutate(data, parts):
            data[parts[0].offset + 0x1c0] ^= 1
        self.bad_target(mutate)

    def test_invalid_tmd_ranges_are_rejected(self):
        def mutate(data, parts):
            tmd = c._align(c._align(c._align(0x2020, 64) + struct.unpack_from('<I', data, 8)[0], 64)
                          + struct.unpack_from('<I', data, 12)[0], 64)
            data[tmd + 0x140 + 0xc4:tmd + 0x140 + 0xc8] = bytes.fromhex('00000002')
        self.bad_target(mutate)

    def test_incorrect_target_payload_profile_is_rejected(self):
        role, source, delta = self.case('base')
        first = role.target_profile.parts[0]
        regions = tuple(replace(r, sha256='0' * 64) if r.name == 'romfs' else r
                        for r in first.regions)
        role = replace(role, target_profile=replace(role.target_profile,
                       parts=(replace(first, regions=regions), *role.target_profile.parts[1:])))
        with self.assertRaisesRegex(app.PatchError, '결과 게임 영역'):
            app.apply_patch(role, source, self.root, EXE, delta, True, True,
                            lambda _: None, lambda _: None, lambda _: None, strict=False)
        self.assertFalse((self.root / role.result_name).exists())

    def test_padded_file_does_not_skip_truncated_main_game_region(self):
        role, source, _ = self.case('base')
        issues = app.check_source_profile(source, role, c.Keys(), lambda _: None,
                                          lambda _: None, padded_from=0x5000)
        self.assertTrue(any('잘렸' in s for s in issues), issues)


if __name__ == '__main__':
    unittest.main()
