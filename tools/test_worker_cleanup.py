"""Compatibility flags must never authorize deleting user inputs."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import yw3ko_patcher as app


class WorkerCleanupTests(unittest.TestCase):
    def run_worker(self, inside_old_work=False, fail=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / 'results'
            out.mkdir()
            old_work = out / '_YW3_KO_work'
            old_work.mkdir()
            keep = old_work / 'user-document.txt'
            keep.write_bytes(b'preserve existing folder')
            base = (old_work if inside_old_work else root) / 'base.cci'
            update = root / 'update.cia'
            base.write_bytes(b'original base')
            update.write_bytes(b'original update')
            gui = Mock()
            seen = []
            def prepare(role, source, work_dir, *args, **kwargs):
                seen.append(work_dir)
                return app.PreparedSource(source, role.key == 'base', compatibility=True,
                                          profile_verified=True)
            with patch.object(app, 'resolve_patch_roles', return_value=(app.ROLES, 'test')), \
                    patch.object(app, 'ensure_xdelta'), patch.object(app, 'ensure_patch'), \
                    patch.object(app, 'prepare_source', side_effect=prepare), \
                    patch.object(app, 'apply_patch', side_effect=app.PatchError('test failure') if fail else None):
                app.PatcherApp._worker(gui, base, update, out, app.converter.Keys())
            self.assertTrue(base.is_file(), 'user CCI was deleted')
            self.assertEqual(base.read_bytes(), b'original base')
            self.assertEqual(update.read_bytes(), b'original update')
            self.assertEqual(keep.read_bytes(), b'preserve existing folder')
            self.assertTrue(all(p != old_work and not p.exists() for p in seen))
            self.assertTrue(any(c.args[:2] == ('done', not fail) for c in gui._emit.call_args_list))

    def test_success_preserves_plain_cci_original(self):
        self.run_worker()

    def test_existing_old_work_folder_is_preserved(self):
        self.run_worker(inside_old_work=True)

    def test_failure_preserves_inputs_and_existing_folder(self):
        self.run_worker(inside_old_work=True, fail=True)


if __name__ == '__main__':
    unittest.main()
