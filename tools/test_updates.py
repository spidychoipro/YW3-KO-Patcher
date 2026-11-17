"""Offline release selection, validation, cache and worker regressions."""
import hashlib
from dataclasses import replace
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock
import urllib.error
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import yw3updates as updates
import yw3ko_patcher as app


def manifest(version):
    patches = []
    for key, title, ext in (("base", "00040000001af400", "cci"),
                            ("update", "0004000e001af400", "cia")):
        payload = (version + key).encode()
        patches.append(dict(role=key, source_size=8192,
            patch_file=f'{key}.xdelta', patch_size=len(payload),
            patch_sha256=hashlib.sha256(payload).hexdigest(),
            target_file=f'{key}.{ext}', target_size=4096,
            target_sha256=hashlib.sha256((version + 'result').encode()).hexdigest(),
            source_profile=dict(role=key, parts=[dict(index=0, program_id=title,
                product_code='', regions=[dict(name=n, size=512, sha256='1' * 64)
                                           for n in ('exefs', 'romfs')])])))
    return dict(package_version=version, format=updates.FORMAT,
                xdelta_version='3.2.2', xdelta_sha256=updates.XDELTA_SHA256,
                patches=patches)


class UpdatesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.env = patch.dict(os.environ, {app.CACHE_ENV: str(self.root / 'cache')})
        self.env.start()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.env.stop)
        self.log = Mock()
        self.fetch = patch.object(updates, 'fetch_latest')
        self.latest = self.fetch.start()
        self.addCleanup(self.fetch.stop)

    def release(self, version='v1.02', modify=None):
        data = manifest(version)
        if modify:
            modify(data)
        archive = self.root / (version + '.zip')
        with zipfile.ZipFile(archive, 'w') as z:
            z.writestr('package/manifest.json', json.dumps(data))
            for key in ('base', 'update'):
                z.writestr(f'package/{key}.xdelta', (version + key).encode())
        asset = dict(name=f'YW3S_Korean_Patch_{version}.zip', size=archive.stat().st_size,
            digest='sha256:' + updates.sha256(archive),
            browser_download_url=f'https://github.com/{updates.REPO}/releases/download/{version}/patch.zip')
        self.latest.return_value = dict(tag_name=version, assets=[asset])
        def download(url, dest, progress=None):
            dest.write_bytes(archive.read_bytes())
        return data, download

    def resolve(self, download):
        return updates.resolve(app.cache_dir(), download, self.log)

    def test_latest_manifest_controls_hashes_and_profiles(self):
        data, download = self.release()
        with patch.object(app, 'download', download):
            roles, label = app.resolve_patch_roles(self.log)
        self.assertIn('v1.02', label)
        self.assertEqual(roles[0].result_sha256, data['patches'][0]['target_sha256'])
        self.assertEqual(roles[0].source_profile.parts[0].program_id, app.YW3_BASE_TITLE)
        self.assertEqual(roles[0].patch_version, 'v1.02')
        for role in roles:
            self.assertEqual(app.ensure_patch(role, self.log).read_bytes(),
                             ('v1.02' + role.key).encode())

    def test_current_release_also_uses_manifest(self):
        _, download = self.release('v1.01')
        bundle, label = self.resolve(download)
        self.assertEqual(bundle.version, 'v1.01')
        self.assertIn('공식 최신', label)

    def test_versions_do_not_share_same_named_patch_cache(self):
        paths = []
        for version in ('v1.01', 'v1.02'):
            _, download = self.release(version)
            with patch.object(app, 'download', download):
                roles, _ = app.resolve_patch_roles(self.log)
            paths.append(app.ensure_patch(roles[0], self.log))
        self.assertNotEqual(paths[0], paths[1])
        self.assertEqual(paths[0].read_bytes(), b'v1.01base')
        self.assertEqual(paths[1].read_bytes(), b'v1.02base')

    def test_network_failure_reuses_verified_cache_with_notice(self):
        _, download = self.release()
        first, _ = self.resolve(download)
        self.latest.side_effect = urllib.error.URLError('offline')
        bundle, label = self.resolve(Mock(side_effect=AssertionError('download offline')))
        self.assertEqual(bundle, first)
        self.assertIn('최신 확인 실패', label)
        self.assertIn('v1.02', label)

    def test_first_offline_run_discloses_builtin_version(self):
        self.latest.side_effect = urllib.error.URLError('offline')
        bundle, label = self.resolve(Mock())
        self.assertIsNone(bundle)
        self.assertIn('최신 확인 실패', label)
        self.assertIn('v1.01', label)

    def test_corrupt_cached_archive_cannot_fall_back(self):
        _, download = self.release()
        bundle, _ = self.resolve(download)
        bundle.archive.write_bytes(b'corrupt')
        self.latest.side_effect = urllib.error.URLError('offline')
        with self.assertRaises(updates.UpdateError):
            self.resolve(Mock())

    def test_unsupported_new_release_remains_blocked_offline(self):
        _, download = self.release('v1.01')
        self.resolve(download)
        _, download = self.release('v1.02', lambda d: d.update(xdelta_version='99'))
        with self.assertRaisesRegex(updates.UpdateError, 'v1.02'):
            self.resolve(download)
        self.latest.side_effect = urllib.error.URLError('offline')
        with self.assertRaises(updates.UpdateError):
            self.resolve(Mock())

    def test_archive_digest_mismatch_stops(self):
        _, download = self.release()
        self.latest.return_value['assets'][0]['digest'] = 'sha256:' + '0' * 64
        with self.assertRaisesRegex(updates.UpdateError, 'SHA-256'):
            self.resolve(download)

    def test_missing_digest_or_external_url_is_unsupported(self):
        for change in ({'digest': None}, {'browser_download_url': 'https://example.com/patch.zip'}):
            with self.subTest(change=change):
                _, download = self.release()
                self.latest.return_value['assets'][0].update(change)
                with self.assertRaises(updates.UpdateError):
                    self.resolve(download)

    def test_invalid_manifest_never_uses_builtin_validation(self):
        changes = [lambda d: d['patches'].pop(),
                   lambda d: d['patches'][0].update(patch_file='../evil.xdelta'),
                   lambda d: d['patches'][0].update(target_sha256='bad'),
                   lambda d: d['patches'][0]['source_profile'].update(parts=[]),
                   lambda d: d.update(package_version='v1.01')]
        for change in changes:
            with self.subTest(change=change):
                _, download = self.release(modify=change)
                with self.assertRaises(updates.UpdateError):
                    self.resolve(download)

    def test_patch_digest_is_checked_after_extraction(self):
        _, download = self.release(modify=lambda d: d['patches'][0].update(patch_sha256='0' * 64))
        with patch.object(app, 'download', download):
            roles, _ = app.resolve_patch_roles(self.log)
        with self.assertRaises(app.PatchError):
            app.ensure_patch(roles[0], self.log)

    def test_source_profile_comes_from_selected_release(self):
        import smoke_test
        data = smoke_test.make_crypto_ncch(app.YW3_BASE_TITLE, None)
        source = self.root / 'source.app'
        source.write_bytes(data)
        regions = tuple(app.profiles.RegionSpec(r.name, r.size,
                        hashlib.sha256(data[r.offset:r.offset + r.size]).hexdigest())
                        for r in app.converter.ncch_regions(data))
        profile = app.profiles.Profile('base', (
            app.profiles.PartSpec(0, app.YW3_BASE_TITLE, '', regions),))
        role = replace(app.BASE, source_profile=profile)
        with patch.dict(app.profiles.PROFILES, {'base': None}):
            self.assertEqual(app.check_source_profile(source, role, app.converter.Keys(),
                                                     self.log, Mock()), [])
            damaged = bytearray(data)
            damaged[0x1010] ^= 0xff
            source.write_bytes(damaged)
            self.assertTrue(app.check_source_profile(source, role, app.converter.Keys(),
                                                    self.log, Mock()))

    def test_worker_uses_selected_roles_for_preparation_and_output(self):
        _, download = self.release()
        with patch.object(app, 'download', download):
            roles, _ = app.resolve_patch_roles(self.log)
        gui = Mock()
        out = self.root / 'output'
        out.mkdir()
        prepared = Mock(path=self.root / 'prepared', converted=False,
                        allow_header=False, padded_from=None)
        with patch.object(app, 'resolve_patch_roles', return_value=(roles, 'v1.02')), \
                patch.object(app, 'ensure_xdelta'), patch.object(app, 'ensure_patch'), \
                patch.object(app, 'prepare_source', return_value=prepared) as prepare, \
                patch.object(app, 'apply_patch') as apply:
            app.PatcherApp._worker(gui, self.root / 'base', self.root / 'update',
                                  out, app.converter.Keys())
        self.assertEqual([c.args[0] for c in prepare.call_args_list], list(roles))
        self.assertEqual([c.args[0] for c in apply.call_args_list], list(roles))
        self.assertTrue(any(c.args[:2] == ('done', True) for c in gui._emit.call_args_list))


if __name__ == '__main__':
    unittest.main()
