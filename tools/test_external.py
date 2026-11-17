"""No real ROMs or console keys; helper isolation and input protection tests."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import smoke_test as smoke
app = smoke.app
c = smoke.converter
ext = app.external


class ExternalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.log = Mock()
        self.tools = {}
        for name in ext.FILES:
            path = self.root / name
            path.write_bytes(b'test tool')
            self.tools[name] = path

    def input(self, key='base'):
        title = app.YW3_BASE_TITLE if key == 'base' else app.YW3_UPDATE_TITLE
        payload = bytearray(smoke.make_fake_ncch(title))
        payload[0x18f] |= 4
        source = self.root / '日本語 한글.cia'
        smoke.build_fake_cia(source, bytes(payload), title, bytes(range(16)), bytes(range(16)), True)
        info = c.read_cia(source)
        data = bytearray(source.read_bytes())
        data[info.tmd_offset + 0x140 + 0x9c:info.tmd_offset + 0x140 + 0x9e] = (5248).to_bytes(2, 'big')
        source.write_bytes(data)
        return source, bytes(payload)

    def mocked_run(self, source, payload, calls):
        def run(command, folder, phase, log):
            calls.append(command)
            # Both original and hardlink must remain protected while the helper reads them.
            if phase == '복호화':
                self.assertEqual(Path(command[1]).name, 'input.cia')
                with self.assertRaises(PermissionError):
                    with source.open('r+b'):
                        pass
                if os.path.samefile(source, command[1]):
                    with self.assertRaises(PermissionError):
                        with Path(command[1]).open('r+b'):
                            pass
                (folder / 'input.0.ncch').write_bytes(payload)
            else:
                output = Path(command[command.index('-o') + 1])
                smoke.build_fake_cia(output, payload, app.YW3_UPDATE_TITLE,
                                     bytes(range(16)), bytes(range(16)), False)
        return run

    def test_read_lock_denies_write_and_delete(self):
        source = self.root / 'source'
        source.write_bytes(b'original')
        with ext.protect_source(source):
            self.assertEqual(source.read_bytes(), b'original')
            with self.assertRaises(PermissionError):
                with source.open('r+b'):
                    pass
            with self.assertRaises(PermissionError):
                source.unlink()
        self.assertEqual(source.read_bytes(), b'original')

    def test_tools_are_pinned_verified_and_cached(self):
        digest = hashlib.sha256(b'tool').hexdigest()
        download = Mock(side_effect=lambda url, dest: dest.write_bytes(b'tool'))
        with patch.dict(ext.FILES, {'decrypt.exe': digest}, clear=True):
            result = ext.ensure_tools(self.root / 'cache', download, self.log)
            self.assertIn(ext.REVISION, download.call_args.args[0])
            self.assertEqual(result['decrypt.exe'].read_bytes(), b'tool')
            ext.ensure_tools(self.root / 'cache', download, self.log)
        self.assertEqual(download.call_count, 1)

    def test_tool_hash_failure_stops_before_execution(self):
        with patch.dict(ext.FILES, {'decrypt.exe': '0' * 64}, clear=True), \
                patch.object(ext, '_run') as run:
            with self.assertRaisesRegex(ext.ExternalError, 'SHA-256'):
                ext.prepare(self.root / 'missing.cia', 'base', self.root, self.root / 'cache',
                            lambda url, dest: dest.write_bytes(b'bad'), self.log)
        run.assert_not_called()

    def test_in_place_wrap_preserves_data_across_chunk_boundary(self):
        main = self.root / 'main.ncch'
        manual = self.root / 'manual.ncch'
        payload = bytearray(smoke.make_fake_ncch(app.YW3_BASE_TITLE, c.CHUNK + 0x4000))
        payload[0x18f] |= 4
        other = bytearray(smoke.make_fake_ncch(app.YW3_BASE_TITLE))
        other[0x18f] |= 4
        main.write_bytes(payload)
        manual.write_bytes(other)
        total = 0x4000 + len(payload) + len(other) + 0x200
        expected = c._build_ncsd_header([(bytes(payload[:512]), len(payload)),
                                       (bytes(other[:512]), len(other))], total)
        output = self.root / 'result.cci'
        ext._wrap_in_place(main, [main, manual], output, total)
        self.assertEqual(output.read_bytes(), expected + payload + other + bytes(0x200))

    def test_base_unicode_input_is_isolated_and_preserved(self):
        source, payload = self.input()
        before = source.read_bytes()
        calls = []
        with patch.object(ext, 'ensure_tools', return_value=self.tools), \
                patch.object(ext, '_run', side_effect=self.mocked_run(source, payload, calls)):
            output = ext.prepare(source, 'base', self.root, self.root / 'cache', Mock(), self.log)
        self.assertEqual(output.read_bytes()[0x4000:], payload)
        self.assertEqual(source.read_bytes(), before)
        self.assertFalse((output.parent / 'input.cia').exists())
        self.assertEqual(list(output.parent.glob('*.ncch')), [])

    def test_update_preserves_version_and_content_ids(self):
        source, payload = self.input('update')
        calls = []
        with patch.object(ext, 'ensure_tools', return_value=self.tools), \
                patch.object(ext, '_run', side_effect=self.mocked_run(source, payload, calls)):
            output = ext.prepare(source, 'update', self.root, self.root / 'cache', Mock(), self.log)
        args = calls[1]
        self.assertEqual(args[args.index('-ver') + 1], '5248')
        self.assertTrue(args[args.index('-i') + 1].endswith(':0:0'))
        self.assertFalse(c.read_cia(output).needs_key)

    def test_helper_failure_removes_only_input_alias(self):
        source, payload = self.input()
        before = source.read_bytes()
        with patch.object(ext, 'ensure_tools', return_value=self.tools), \
                patch.object(ext, '_run', side_effect=ext.ExternalError('failed')):
            with self.assertRaises(ext.ExternalError):
                ext.prepare(source, 'base', self.root, self.root / 'cache', Mock(), self.log)
        self.assertEqual(source.read_bytes(), before)
        self.assertFalse((self.root / 'external_base/input.cia').exists())

    def test_missing_or_encrypted_ncch_result_is_rejected(self):
        for mode in ('missing', 'encrypted'):
            with self.subTest(mode=mode):
                work = self.root / mode
                work.mkdir()
                source, payload = self.input()
                def run(command, folder, phase, log):
                    if mode == 'encrypted':
                        data = bytearray(payload)
                        data[0x18f] = 0
                        (folder / 'input.0.ncch').write_bytes(data)
                with patch.object(ext, 'ensure_tools', return_value=self.tools), patch.object(ext, '_run', run):
                    with self.assertRaises(ext.ExternalError):
                        ext.prepare(source, 'base', work, self.root / 'cache', Mock(), self.log)

    def test_cross_volume_copy_fallback_preserves_original(self):
        source, payload = self.input()
        calls = []
        with patch.object(ext, 'ensure_tools', return_value=self.tools), \
                patch.object(ext.os, 'link', side_effect=OSError('different volumes')), \
                patch.object(ext, '_run', side_effect=lambda cmd, folder, phase, log:
                             (folder / 'input.0.ncch').write_bytes(payload)):
            output = ext.prepare(source, 'base', self.root, self.root / 'cache', Mock(), self.log)
        self.assertEqual(output.read_bytes()[0x4000:], payload)
        self.assertTrue(source.is_file())

    def test_app_routes_keyless_cia_then_still_validates_profile(self):
        source, _ = self.input()
        ready = self.root / 'prepared.cci'
        ready.write_bytes(b'bad output')
        with patch.object(ext, 'prepare', return_value=ready) as prepare:
            with self.assertRaises(app.PatchError):
                app.prepare_source(app.BASE, source, self.root, c.Keys(), self.log, Mock(), Mock())
        prepare.assert_called_once()

    def test_existing_valid_keys_keep_native_path(self):
        source, _ = self.input()
        keys = c.Keys(common=bytes(range(16)))
        with patch.object(ext, 'prepare') as prepare:
            app.prepare_source(app.BASE, source, self.root, keys, self.log, Mock(), Mock(), check_profile=False)
        prepare.assert_not_called()

    def test_wrong_keys_retry_helper_without_skipping_final_profile_check(self):
        source, _ = self.input()
        ready = self.root / 'bad-result.cci'
        ready.write_bytes(b'invalid result')
        with patch.object(ext, 'prepare', return_value=ready) as prepare:
            with self.assertRaises(app.PatchError):
                app.prepare_source(app.BASE, source, self.root, c.Keys(common=bytes([255]) * 16),
                                   self.log, Mock(), Mock())
        prepare.assert_called_once()

    def test_gui_offers_automatic_cia_processing_without_key_requirement(self):
        files = []
        for key, title in (('base', app.YW3_BASE_TITLE), ('update', app.YW3_UPDATE_TITLE)):
            path = self.root / (key + '.cia')
            smoke.build_fake_cia(path, smoke.make_fake_ncch(title), title,
                                 bytes(range(16)), bytes(range(16)), True)
            files.append(path)
        gui = app.PatcherApp()
        gui.withdraw()
        try:
            gui._load_keys = Mock(return_value=c.Keys())
            gui.base_var.set(str(files[0]))
            gui.update_var.set(str(files[1]))
            gui.update_idletasks()
            self.assertEqual(str(gui.start_button['state']), 'normal')
            self.assertIn('자동 복호화', gui.ready_var.get())
            self.assertNotIn('common 키가 필요', gui.ready_var.get())
        finally:
            gui.destroy()

    def test_low_disk_space_is_visible_and_stops_before_worker(self):
        source, _ = self.input()
        update = self.root / 'update.cia'
        smoke.build_fake_cia(update, smoke.make_fake_ncch(app.YW3_UPDATE_TITLE),
                             app.YW3_UPDATE_TITLE, bytes(range(16)), bytes(range(16)), True)
        gui = app.PatcherApp()
        gui.withdraw()
        try:
            gui._load_keys = Mock(return_value=c.Keys())
            gui.base_var.set(str(source))
            gui.update_var.set(str(update))
            gui.out_var.set(str(self.root / 'results'))
            with patch.object(app.shutil, 'disk_usage', return_value=Mock(free=0)), \
                    patch.object(app.threading, 'Thread') as thread:
                gui._start()
            thread.assert_not_called()
            self.assertIn('저장 공간이 부족', gui.ready_var.get())
            self.assertFalse(gui._busy)
        finally:
            gui.destroy()


if __name__ == '__main__':
    unittest.main()
