"""앱 자체 업데이트 확인, 검증, 설치 손잡이 회귀 테스트."""
import hashlib
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import yw3appupdate as appupdate
import yw3ko_patcher as app


def digest_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def release_data(version='v1.7.0', payload=b'new-exe', **changes):
    tag = version
    data = {
        'tag_name': tag,
        'draft': False,
        'prerelease': False,
        'assets': [{
            'name': appupdate.ASSET_NAME,
            'size': len(payload),
            'digest': 'sha256:' + digest_of(payload),
            'browser_download_url': (
                f'https://github.com/{appupdate.APP_REPO}/releases/download/'
                f'{tag}/{appupdate.ASSET_NAME}'),
        }],
    }
    data.update(changes)
    return data


class AppUpdateTests(unittest.TestCase):
    def test_version_compare(self):
        self.assertEqual(appupdate.parse_version('v1.6.3'), (1, 6, 3))
        self.assertEqual(appupdate.parse_version('1.7'), (1, 7, 0))
        self.assertTrue(appupdate.is_newer('1.6.3', 'v1.7.0'))
        self.assertFalse(appupdate.is_newer('1.7.0', 'v1.6.3'))
        self.assertFalse(appupdate.is_newer('1.7.0', '1.7.0'))
        with self.assertRaises(appupdate.AppUpdateError):
            appupdate.parse_version('최신')

    def test_release_validation(self):
        good = release_data()
        release = appupdate.parse_release(good)
        self.assertEqual(release.version, '1.7.0')
        self.assertEqual(release.digest, digest_of(b'new-exe'))
        self.assertTrue(release.page.endswith('/releases/tag/v1.7.0'))

        bad_asset = release_data()
        bad_asset['assets'][0]['name'] = 'other.exe'
        bad_digest = release_data()
        bad_digest['assets'][0]['digest'] = 'sha256:abcdef'
        bad_url = release_data()
        bad_url['assets'][0]['browser_download_url'] = bad_url['assets'][0][
            'browser_download_url'].replace('github.com', 'evil.example')
        prerelease = release_data(prerelease=True)
        for name, data in (('asset', bad_asset), ('digest', bad_digest),
                           ('url', bad_url), ('prerelease', prerelease)):
            with self.subTest(name=name), self.assertRaises(appupdate.AppUpdateError):
                appupdate.parse_release(data)

    def test_check_returns_only_newer_release(self):
        with patch.object(appupdate, 'fetch_latest',
                          return_value=release_data()) as fetch:
            release = appupdate.check('1.6.3')
        self.assertIsNotNone(release)
        self.assertEqual(release.version, '1.7.0')
        fetch.assert_called_once_with()

        with patch.object(appupdate, 'fetch_latest', return_value=release_data('v1.6.2')):
            self.assertIsNone(appupdate.check('1.6.3'))

    def test_prepare_download_verifies_hash_and_caches(self):
        payload = b'official-new-exe'
        release = appupdate.parse_release(release_data(payload=payload))
        with tempfile.TemporaryDirectory() as folder:
            cache = Path(folder)
            stale = cache / 'app-updates' / '1.6.0' / 'old' / appupdate.ASSET_NAME
            stale.parent.mkdir(parents=True)
            stale.write_bytes(b'old-exe')
            called = []

            def download(url, dest, progress=None):
                called.append(url)
                dest.write_bytes(payload)

            first = appupdate.prepare_download(cache, release, download)
            self.assertEqual(first.read_bytes(), payload)
            self.assertEqual(len(called), 1)
            self.assertFalse(stale.exists(), '오래된 앱 업데이트 캐시가 남았습니다')
            # 검증된 캐시는 그대로 재사용한다.
            appupdate.prepare_download(cache, release, Mock(side_effect=AssertionError()))
            self.assertEqual(first.read_bytes(), payload)

            bad = appupdate.parse_release(release_data(payload=b'other'))
            with self.assertRaises(appupdate.AppUpdateError):
                appupdate.prepare_download(
                    cache, bad, lambda url, dest, progress=None: dest.write_bytes(b'tampered'))
            self.assertFalse(appupdate.staged_path(cache, bad).exists())

    def test_launch_updater_is_hidden_and_waits_for_parent(self):
        release = appupdate.parse_release(release_data())
        with tempfile.TemporaryDirectory() as folder:
            cache = Path(folder)
            with patch.object(appupdate, 'can_self_update', return_value=True), \
                    patch.object(appupdate.subprocess, 'Popen') as popen:
                appupdate.launch_updater(
                    cache, Path(r'C:\Apps\YW3-KO-Patcher.exe'),
                    cache / 'new.exe', release, parent_pid=4321)
            script = cache / 'app-updates' / 'updater.ps1'
            self.assertTrue(script.is_file())
            self.assertIn('$ParentPid', script.read_text(encoding='utf-8'))
            args = popen.call_args.args[0]
            self.assertIn('-WindowStyle', args)
            self.assertIn('Hidden', args)
            self.assertIn('-ParentPid', args)
            self.assertIn('4321', args)
            self.assertTrue(popen.call_args.kwargs['creationflags'] & appupdate.CREATE_NO_WINDOW)

    def test_gui_has_update_button_and_manual_check(self):
        gui = app.PatcherApp()
        try:
            gui.update()
            self.assertEqual(gui.update_button.cget('text'), '업데이트 확인')
            gui._set_busy(True)
            self.assertEqual(str(gui.update_button['state']), 'disabled')
            gui._set_busy(False)
            self.assertEqual(str(gui.update_button['state']), 'normal')

            with patch.object(appupdate, 'check', return_value=None), \
                    patch.object(app.messagebox, 'showinfo') as info:
                gui._start_update_check()
                deadline = time.time() + 5
                while gui._update_check_running and time.time() < deadline:
                    gui.update()
                    time.sleep(0.02)
                gui.update()
            self.assertTrue(info.called, '최신 버전 안내가 뜨지 않았습니다')
            self.assertIn('최신', info.call_args.args[1])
            self.assertEqual(str(gui.update_button['state']), 'normal')
        finally:
            gui.destroy()

    def test_gui_update_prompt_opens_page_when_not_packaged(self):
        release = appupdate.parse_release(release_data())
        gui = app.PatcherApp()
        try:
            with patch.object(appupdate, 'can_self_update', return_value=False), \
                    patch.object(app.messagebox, 'askyesno', return_value=True) as ask, \
                    patch.object(app.webbrowser, 'open') as open_page:
                gui._finish_update_check(release, '', True)
            self.assertTrue(ask.called)
            self.assertIn('1.7.0', ask.call_args.args[1])
            open_page.assert_called_once_with(release.page)
        finally:
            gui.destroy()


if __name__ == '__main__':
    unittest.main()
