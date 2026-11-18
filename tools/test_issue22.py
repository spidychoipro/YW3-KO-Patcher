"""Role-specific error text must not tell update users to bring a v0 file."""
import unittest

import smoke_test as smoke

app = smoke.app


class Issue22Tests(unittest.TestCase):
    def test_profile_error_names_the_required_update_version(self):
        update = app._profile_error(app.UPDATE, ["ExeFS 내용이 공식 원본과 다릅니다"])
        self.assertIn("업데이트 원본이 공식 배포본(Update 4.0)과 다릅니다.", update)
        self.assertNotIn("공식 배포본(v0)", update)
        base = app._profile_error(app.BASE, ["ExeFS 내용이 공식 원본과 다릅니다"])
        self.assertIn("본편 원본이 공식 배포본(일본판 요괴워치3 스키야키 v0)과 다릅니다.", base)

    def test_xdelta_failure_names_the_required_update_version(self):
        update = app._explain_failure(app.UPDATE, 1, b"source file mismatch")
        self.assertIn("Update 4.0인지 확인해 주세요.", update)
        self.assertNotIn("v0인지", update)
        base = app._explain_failure(app.BASE, 1, b"source file mismatch")
        self.assertIn("일본판 요괴워치3 스키야키 v0인지 확인해 주세요.", base)

    def test_window_mismatch_names_the_required_update_version(self):
        update = app._explain_mismatch(app.UPDATE, [(0x1000, 0x200)])
        self.assertIn("Update 4.0이 맞는지 확인해 주세요.", update)
        self.assertNotIn("v0이 맞는지", update)
        base = app._explain_mismatch(app.BASE, [(0x1000, 0x200)])
        self.assertIn("일본판 요괴워치3 스키야키 v0이 맞는지 확인해 주세요.", base)


if __name__ == '__main__':
    unittest.main()
