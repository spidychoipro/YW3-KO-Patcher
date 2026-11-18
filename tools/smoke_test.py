"""핵심 기능 점검용 스모크 테스트.

실제 게임 롬 없이도 다음을 확인한다.
1. xdelta3 내려받기/지문 확인
2. 공식 패치 압축에서 패치 파일 추출/지문 확인 (캐시에 zip이 있으면 오프라인)
3. xdelta3 적용 + 결과 SHA-256 검증 + 실패 시 임시 파일 정리
4. GUI 객체 생성

실행: python tools/smoke_test.py [--with-download]
"""

from __future__ import annotations

import hashlib
import os
import shutil
import struct
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import yw3ko_patcher as app  # noqa: E402
import yw3convert as converter  # noqa: E402

LOCAL_ZIP_CANDIDATES = [
    Path(r"C:\Users\swpar\AppData\Local\Temp\opencode\yw3\YW3S_Korean_Patch_v1.01.zip"),
    ROOT / "YW3S_Korean_Patch_v1.01.zip",
]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_xdelta(log) -> Path:
    exe = app.ensure_xdelta(log)
    assert exe.is_file(), "xdelta3.exe 없음"
    assert app.sha256_file(exe) == app.XDETTA_EXE_SHA256, "xdelta3 지문 불일치"
    print(f"[ok] xdelta3 준비: {exe}")
    return exe


def test_patch_extract(log) -> Path:
    for candidate in LOCAL_ZIP_CANDIDATES:
        if candidate.is_file():
            cache = app.cache_dir()
            cached = cache / app.PATCH_ZIP_NAME
            if not cached.is_file():
                shutil.copyfile(candidate, cached)
                print(f"[info] 로컬 zip을 캐시로 복사: {candidate}")
            break
    patch = app.ensure_patch(app.BASE, log)
    assert patch.stat().st_size == app.BASE.patch_size
    assert app.sha256_file(patch) == app.BASE.patch_sha256
    print(f"[ok] 본편 패치 준비: {patch} ({app.human_size(patch.stat().st_size)})")

    patch2 = app.ensure_patch(app.UPDATE, log)
    assert app.sha256_file(patch2) == app.UPDATE.patch_sha256
    print(f"[ok] 업데이트 패치 준비: {patch2} ({app.human_size(patch2.stat().st_size)})")
    return patch


def test_apply_roundtrip(exe: Path, work: Path) -> None:
    source = work / "가짜 원본.bin"
    source.write_bytes((b"sukiyaki-source-block-" * 40000) + os.urandom(4096))
    diff = work / "가짜 패치.xdelta"
    subprocess_result = app.subprocess.run(
        [str(exe), "-e", "-f", "-s", str(source), str(source), str(diff)],
        capture_output=True,
    )
    assert subprocess_result.returncode == 0, subprocess_result.stdout

    patched = work / "원하는 결과.bin"
    subprocess_result = app.subprocess.run(
        [str(exe), "-d", "-f", "-s", str(source), str(diff), str(patched)],
        capture_output=True,
    )
    assert subprocess_result.returncode == 0

    expected = patched.read_bytes()
    patched.unlink()

    fake = app.Role(
        key="test", label="테스트", patch_name=diff.name, patch_size=diff.stat().st_size,
        patch_sha256=sha256_bytes(diff.read_bytes()), result_name="결과물.bin",
        result_size=len(expected), result_sha256=sha256_bytes(expected),
    )
    out_dir = work / "out"
    out_dir.mkdir()
    statuses: list[str] = []
    percents: list[float] = []

    result = app.apply_patch(
        fake, source, out_dir, exe, diff, overwrite=True, verify=True,
        log=lambda m: None, progress=percents.append, status=statuses.append,
    )
    assert result.is_file() and result.read_bytes() == expected, "결과 내용 불일치"
    assert not result.with_name(result.name + ".part").exists(), "임시 파일이 남음"
    assert percents and max(percents) >= 99, f"진행률 콜백 이상: {percents[-3:]}"
    print(f"[ok] 적용/검증 라운드트립, 진행률 {percents[-1]:.0f}%")

    # 1) 원본이 다를 때 -> 친절한 오류 + 임시 파일 정리
    wrong = work / "다른 원본.bin"
    wrong.write_bytes(b"not the right source" * 1000)
    try:
        app.apply_patch(fake, wrong, out_dir, exe, diff, overwrite=True, verify=True,
                        log=lambda m: None, progress=lambda p: None, status=lambda s: None)
    except app.PatchError as exc:
        message = str(exc)
        assert "다릅니다" in message, message
        print("[ok] 잘못된 원본 거부")
    else:
        raise AssertionError("잘못된 원본인데 성공했다")
    assert not (out_dir / "결과물.bin.part").exists(), "실패 후 임시 파일이 남음"

    # 2) 결과 지문이 다를 때 -> 실패 처리
    bad = app.Role(**{**fake.__dict__, "result_sha256": "0" * 64})
    try:
        app.apply_patch(bad, source, out_dir, exe, diff, overwrite=True, verify=True,
                        log=lambda m: None, progress=lambda p: None, status=lambda s: None)
    except app.PatchError as exc:
        assert "지문" in str(exc), str(exc)
        print("[ok] 결과 지문 불일치 감지")
    else:
        raise AssertionError("지문이 다른데 성공했다")

    # 3) 변환본으로 패치한 경우 -> 지문이 달라도 결과를 남긴다
    report: dict = {}
    kept = app.apply_patch(bad, source, out_dir, exe, diff, overwrite=True, verify=True,
                           log=lambda m: None, progress=lambda p: None, status=lambda s: None,
                           strict=False, report=report)
    assert kept.is_file() and report.get("verified") is False, "변환본 결과 처리 실패"
    kept.unlink()
    print("[ok] 변환본 결과는 지문이 달라도 저장")


def test_gui() -> None:
    gui = app.PatcherApp()
    gui.update()
    gui._show_key_help()
    gui.update()
    for child in gui.winfo_children():
        if isinstance(child, app.tk.Toplevel):
            child.destroy()
    gui.destroy()
    print("[ok] GUI 생성/종료, 키 안내 창")


def test_gui_flow(exe: Path, work: Path) -> None:
    """GUI 버튼 흐름(검증 → 스레드 → 진행률 → 완료)을 실제로 돌려본다."""
    source_a = work / "gui_a.bin"
    source_b = work / "gui_b.bin"
    source_a.write_bytes(b"gui-source-a" * 50000)
    source_b.write_bytes(b"gui-source-b" * 20000)
    outputs = {}
    roles = []
    for key, source, name in (("base", source_a, "GUI_base.cci"), ("update", source_b, "GUI_update.cia")):
        patch = work / f"gui_{key}.xdelta"
        app.subprocess.run([str(exe), "-e", "-f", "-s", str(source), str(source), str(patch)],
                           capture_output=True, check=True)
        target = work / f"gui_{key}_expected.bin"
        app.subprocess.run([str(exe), "-d", "-f", "-s", str(source), str(patch), str(target)],
                           capture_output=True, check=True)
        data = target.read_bytes()
        roles.append(app.Role(
            key=key, label=key, patch_name=patch.name, patch_size=patch.stat().st_size,
            patch_sha256=sha256_bytes(patch.read_bytes()), result_name=name,
            result_size=len(data), result_sha256=sha256_bytes(data),
        ))
        outputs[key] = (data, patch)

    original = (app.BASE, app.UPDATE, app.ROLES, app.ensure_xdelta, app.ensure_patch,
                app.messagebox.askyesno, app.resolve_patch_roles)
    app.BASE, app.UPDATE, app.ROLES = roles[0], roles[1], tuple(roles)
    app.ensure_xdelta = lambda log, progress=None: exe
    app.ensure_patch = lambda role, log, progress=None: outputs[role.key][1]
    app.resolve_patch_roles = lambda log, progress=None: (tuple(roles), "테스트 한글 패치")
    app.messagebox.askyesno = lambda *args, **kwargs: True
    out_dir = work / "gui_out"
    out_dir.mkdir()
    gui = None
    try:
        gui = app.PatcherApp()
        gui._open_folder = lambda: None
        gui.base_var.set(str(source_a))
        gui.update_var.set(str(source_b))
        gui.out_var.set(str(out_dir))
        gui._start()
        deadline = time.time() + 60
        while gui._busy and time.time() < deadline:
            gui.update()
            time.sleep(0.02)
        gui.update()
        assert not gui._busy, "GUI 작업이 끝나지 않음"
        for role in roles:
            result = out_dir / role.result_name
            assert result.is_file(), f"{result} 없음"
            assert result.read_bytes() == outputs[role.key][0], f"{role.key} 내용 불일치"
        assert gui.progress["value"] == 100, gui.progress["value"]
        assert gui.patch_version_var.get() == "테스트 한글 패치", gui.patch_version_var.get()
        assert "완료" in gui.ready_var.get(), gui.ready_var.get()
        assert gui.open_button.winfo_manager() == "pack", "완료 후 폴더 열기 버튼이 없음"
        print(f"[ok] GUI 흐름 완료 (진행률 {gui.progress['value']:.0f}%)")
    finally:
        if gui is not None:
            gui.destroy()
        (app.BASE, app.UPDATE, app.ROLES, app.ensure_xdelta, app.ensure_patch,
         app.messagebox.askyesno, app.resolve_patch_roles) = original


def write_fake_ncch(buffer: bytearray, offset: int, title_id: int, encrypted: bool) -> None:
    buffer[offset + 0x100:offset + 0x104] = b"NCCH"
    buffer[offset + 0x18F] = 0x00 if encrypted else 0x04
    buffer[offset + 0x118:offset + 0x120] = title_id.to_bytes(8, "little")


def make_fake_cci(work: Path, name: str, title_id: int, encrypted: bool) -> Path:
    data = bytearray(0x4000)
    data[0x100:0x104] = b"NCSD"
    struct.pack_into("<I", data, 0x104, 0x20)  # 파일 크기(미디어 유닛)
    data[0x108:0x110] = title_id.to_bytes(8, "big")  # GodMode9이 요구하는 미디어 ID
    struct.pack_into("<I", data, 0x120, 1)  # 파티션 0은 미디어 유닛 1(0x200)
    struct.pack_into("<I", data, 0x124, 0x1F)  # 파티션 끝 = 파일 끝
    write_fake_ncch(data, 0x200, title_id, encrypted)
    path = work / name
    path.write_bytes(data)
    return path


def _cia_layout(header_size: int, cert_size: int, ticket_size: int, tmd_size: int,
                meta_size: int = 0, aligned: bool = True,
                content_size: int = 0) -> tuple[int, int, int, int, int]:
    """CIA 각 구간 위치. 실제 CIA는 0x40 경계에 맞춰 놓는다."""
    def step(offset: int) -> int:
        return _align(offset, 0x40) if aligned else offset

    cert_offset = step(header_size)
    ticket_offset = step(cert_offset + cert_size)
    tmd_offset = step(ticket_offset + ticket_size)
    content_offset = _align(tmd_offset + tmd_size, 0x40)
    meta_offset = _align(content_offset + content_size, 0x40) if meta_size else 0
    return cert_offset, ticket_offset, tmd_offset, meta_offset, content_offset


def make_fake_cia(work: Path, name: str, title_id: int, encrypted: bool) -> Path:
    header_size, cert_size, ticket_size, tmd_size, meta_size = 0x2020, 0xA00, 0x350, 0xB34, 0x3AC0
    cert_offset, ticket_offset, tmd_offset, _meta_offset, content = _cia_layout(
        header_size, cert_size, ticket_size, tmd_size, meta_size, content_size=0x400)
    data = bytearray(content + 0x400 + meta_size)
    struct.pack_into("<I", data, 0x00, header_size)
    struct.pack_into("<I", data, 0x08, cert_size)
    struct.pack_into("<I", data, 0x0C, ticket_size)
    struct.pack_into("<I", data, 0x10, tmd_size)
    struct.pack_into("<I", data, 0x14, meta_size)
    struct.pack_into("<Q", data, 0x18, 0x400)
    data[cert_offset:cert_offset + 4] = (0x00010003).to_bytes(4, "big")
    data[ticket_offset:ticket_offset + 4] = (0x00010004).to_bytes(4, "big")
    data[tmd_offset:tmd_offset + 4] = (0x00010004).to_bytes(4, "big")
    tmd_header = tmd_offset + 0x140
    data[tmd_header + 0x4C:tmd_header + 0x54] = title_id.to_bytes(8, "big")
    data[tmd_header + 0x9E:tmd_header + 0xA0] = (1).to_bytes(2, "big")
    record = tmd_header + 0xC4 + 0x24 * 64
    data[record + 0x06:record + 0x08] = (1 if encrypted else 0).to_bytes(2, "big")
    data[record + 0x08:record + 0x10] = (0x400).to_bytes(8, "big")
    write_fake_ncch(data, content, title_id, encrypted)
    path = work / name
    path.write_bytes(data)
    return path


def test_rom_detection(work: Path) -> None:
    """컨테이너/암호화/타이틀 판별이 맞는지 가짜 헤더로 확인한다."""
    base_ok = make_fake_cci(work, "가짜 본편.cci", app.YW3_BASE_TITLE, encrypted=False)
    update_ok = make_fake_cia(work, "가짜 업데이트.cia", app.YW3_UPDATE_TITLE, encrypted=False)
    encrypted = make_fake_cia(work, "암호화 업데이트.cia", app.YW3_UPDATE_TITLE, encrypted=True)
    base_cia = make_fake_cia(work, "가짜 본편 CIA.cia", app.YW3_BASE_TITLE, encrypted=False)
    other_title = make_fake_cci(work, "다른 게임.cci", 0x0004000000123400, encrypted=False)
    enc_cci = make_fake_cci(work, "암호화 본편.cci", app.YW3_BASE_TITLE, encrypted=True)
    junk = work / "그냥 파일.bin"
    junk.write_bytes(os.urandom(0x1000))

    checks = [
        ("base", base_ok, "ok"),
        ("update", update_ok, "ok"),
        ("update", encrypted, "info"),
        ("base", base_cia, "info"),
        ("base", enc_cci, "info"),
        ("base", other_title, "warn"),
        ("base", junk, "info"),
        ("update", junk, "info"),
    ]
    for role_key, path, expected in checks:
        info = app.inspect_rom(path)
        message, level = app.describe_rom(role_key, info)
        assert level == expected, f"{path.name}: {level} != {expected} / {message}"
        print(f"[ok] 판별 {path.name}: {level} — {message}")

    assert "암호화" in app.describe_rom("update", app.inspect_rom(encrypted))[0]
    assert "바꿔" in app.describe_rom("update", app.inspect_rom(base_ok))[0]
    print("[ok] 교차 선택 안내")


def test_ui_states(work: Path) -> None:
    """시작 버튼 활성/비활성, 준비 문구, 진행 기록 토글을 확인한다."""
    base_ok = make_fake_cci(work, "ui 본편.cci", app.YW3_BASE_TITLE, encrypted=False)
    update_ok = make_fake_cia(work, "ui 업데이트.cia", app.YW3_UPDATE_TITLE, encrypted=False)
    base_cia = make_fake_cia(work, "ui 본편 CIA.cia", app.YW3_BASE_TITLE, encrypted=False)

    gui = app.PatcherApp()
    try:
        gui.update()
        assert str(gui.start_button["state"]) == "disabled", "처음부터 시작 버튼이 눌린다"
        assert "골라" in gui.ready_var.get(), gui.ready_var.get()

        gui.base_var.set(str(base_ok))
        gui.update()
        assert str(gui.start_button["state"]) == "disabled", "한 파일만 골랐는데 시작 가능"

        gui.update_var.set(str(update_ok))
        gui.update()
        assert str(gui.start_button["state"]) == "normal", "두 파일을 골랐는데 시작 불가"
        assert "준비 완료" in gui.ready_var.get(), gui.ready_var.get()

        gui.base_var.set(str(base_cia))
        gui.update()
        assert "CIA" in gui.ready_var.get(), gui.ready_var.get()
        assert str(gui.start_button["state"]) == "normal", "경고 상황에서도 시작은 가능해야 함"

        gui.keys_var.set(str(work / "없는키.txt"))
        gui.update()
        assert "고른 키 파일" in gui.ready_var.get(), gui.ready_var.get()
        gui.keys_var.set("")
        gui.update()

        gui._toggle_log()
        gui.update()
        assert gui.log_frame.winfo_manager() == "grid", "진행 기록이 안 열림"
        gui._toggle_log()
        gui.update()
        assert not gui.log_frame.winfo_manager(), "진행 기록이 안 닫힘"
        print("[ok] GUI 상태(시작 버튼/준비 문구/기록 토글)")
    finally:
        gui.destroy()


def _align(value: int, align: int) -> int:
    return (value + align - 1) // align * align


def make_fake_ncch(title_id: int, size: int = 0x4000) -> bytes:
    data = bytearray(size)
    data[0x100:0x104] = b"NCCH"
    data[0x104:0x108] = (size // 0x200).to_bytes(4, "little")
    data[0x108:0x110] = title_id.to_bytes(8, "big")
    data[0x112:0x114] = (4).to_bytes(2, "big")
    data[0x118:0x120] = title_id.to_bytes(8, "little")
    data[0x160:0x180] = bytes(range(32))
    data[0x18F] = 0x00
    for index in range(0x400, size, 0x100):
        data[index:index + 4] = (index * 7).to_bytes(4, "little")
    return bytes(data)


def build_fake_cia(path: Path, ncch: bytes, title_id: int, title_key: bytes,
                   common_key: bytes, encrypt: bool, aligned: bool = True,
                   plain_ticket_key: bool = False) -> Path:
    header_size = 0x2020
    cert = bytearray(0x400)
    cert[0:4] = (0x00010003).to_bytes(4, "big")
    cert = bytes(cert)
    ticket = bytearray(0x140 + 0x210)
    ticket[0:4] = (0x00010004).to_bytes(4, "big")
    iv = title_id.to_bytes(8, "big") + b"\x00" * 8
    stored = title_key if plain_ticket_key else converter.cbc_encrypt(common_key, iv, title_key)
    ticket[0x140 + 0x7F:0x140 + 0x8F] = stored
    ticket[0x140 + 0x9C:0x140 + 0xA4] = title_id.to_bytes(8, "big")
    ticket = bytes(ticket)

    tmd = bytearray(0x140 + 0xC4 + 0x24 * 64 + 0x30)
    tmd[0:4] = (0x00010004).to_bytes(4, "big")
    tmd[0x140 + 0x4C:0x140 + 0x54] = title_id.to_bytes(8, "big")
    tmd[0x140 + 0x9E:0x140 + 0xA0] = (1).to_bytes(2, "big")
    record = 0x140 + 0xC4 + 0x24 * 64
    tmd[record + 0x04:record + 0x06] = (0).to_bytes(2, "big")
    tmd[record + 0x06:record + 0x08] = (1 if encrypt else 0).to_bytes(2, "big")
    tmd[record + 0x08:record + 0x10] = len(ncch).to_bytes(8, "big")
    tmd = bytes(tmd)

    cert_offset, ticket_offset, tmd_offset, _meta_offset, content_offset = _cia_layout(
        header_size, len(cert), len(ticket), len(tmd), aligned=aligned)
    payload = converter.cbc_encrypt(title_key, b"\x00" * 16, ncch) if encrypt else ncch
    head = bytearray(header_size)
    struct.pack_into("<I", head, 0x00, header_size)
    struct.pack_into("<I", head, 0x08, len(cert))
    struct.pack_into("<I", head, 0x0C, len(ticket))
    struct.pack_into("<I", head, 0x10, len(tmd))
    struct.pack_into("<I", head, 0x14, 0)
    struct.pack_into("<Q", head, 0x18, len(payload))
    blob = bytearray(content_offset)
    blob[0:header_size] = head
    blob[cert_offset:cert_offset + len(cert)] = cert
    blob[ticket_offset:ticket_offset + len(ticket)] = ticket
    blob[tmd_offset:tmd_offset + len(tmd)] = tmd
    path.write_bytes(bytes(blob) + payload)
    return path


def check_cci(path: Path, ncch_plain: bytes, title_id: int) -> None:
    data = path.read_bytes()
    assert data[0x100:0x104] == b"NCSD", "CCI 매직 없음"
    assert int.from_bytes(data[0x104:0x108], "little") * 0x200 == len(data), "CCI 크기 필드 불일치"
    assert int.from_bytes(data[0x120:0x124], "little") == 0x20, "파티션 0 위치가 0x4000이 아님"
    part = data[0x4000:]
    expected = bytearray(ncch_plain)
    expected[0x18F] |= 0x04
    assert part[:len(expected)] == bytes(expected), "CCI 안의 NCCH 내용이 다름"
    assert int.from_bytes(data[0x190:0x198], "big") == title_id, "파티션 ID 테이블 불일치"


def test_converter(work: Path) -> None:
    """AES/CIA 복호화/CCI 변환을 가짜 파일로 확인한다."""
    title_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    common_key = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    title_id = app.YW3_UPDATE_TITLE

    keys_file = work / "keys.txt"
    keys_file.write_text(f"# test\ncommon: {common_key.hex()}\n", encoding="utf-8")
    keys = converter.find_keys([work])
    assert keys.common == common_key, "keys.txt에서 common 키를 못 읽음"
    print("[ok] keys.txt 읽기")

    bare = work / "bare_keys.txt"
    bare.write_text(common_key.hex().upper() + "\n", encoding="utf-8")
    assert converter.load_keys_file(bare).common == common_key, "16진수 한 줄 형식 실패"
    print("[ok] keys.txt 16진수 한 줄 형식")

    ncch = make_fake_ncch(title_id)
    plain_cia = build_fake_cia(work / "평문.cia", ncch, title_id, title_key, common_key, False)
    enc_cia = build_fake_cia(work / "암호.cia", ncch, title_id, title_key, common_key, True)

    info = app.inspect_rom(enc_cia)
    assert info.kind == "cia" and info.encrypted is True, f"암호화 CIA 판별 실패: {info}"
    assert info.title_id == title_id, f"암호화 CIA 타이틀 판별 실패: {info.title_id:016X}"
    print("[ok] 암호화된 CIA 판별(헤더가 안 보여도 티켓으로 확인)")

    try:
        converter.decrypt_cia(enc_cia, work / "실패.cia", converter.Keys())
    except converter.ConvertError as exc:
        assert "keys.txt" in str(exc), str(exc)
        print("[ok] 키 없을 때 안내")
    else:
        raise AssertionError("키가 없는데 복호화가 됐다")

    decrypted = converter.decrypt_cia(enc_cia, work / "복호화.cia", keys, lambda p: None)
    plain_info = converter.read_cia(plain_cia)
    enc_info = converter.read_cia(enc_cia)
    with plain_cia.open("rb") as a, decrypted.open("rb") as b:
        a.seek(plain_info.program.offset)
        b.seek(enc_info.program.offset)
        assert a.read(plain_info.program.size) == b.read(enc_info.program.size), \
            "복호화한 내용이 원본 평문과 다름"
    print("[ok] 암호화 CIA 복호화 라운드트립")

    cci_from_plain = converter.cia_to_cci(plain_cia, work / "평문.cci", keys, lambda m: None, lambda p: None)
    check_cci(cci_from_plain, ncch, title_id)
    print("[ok] 평문 CIA → CCI 변환")

    cci_from_enc = converter.cia_to_cci(enc_cia, work / "암호.cci", keys, lambda m: None, lambda p: None)
    check_cci(cci_from_enc, ncch, title_id)
    assert cci_from_enc.read_bytes() == cci_from_plain.read_bytes(), "암호화 CIA 변환 결과가 다름"
    print("[ok] 암호화 CIA → CCI 변환")

    legacy = build_fake_cia(work / "정렬안함.cia", ncch, title_id, title_key, common_key,
                            True, aligned=False)
    legacy_info = converter.read_cia(legacy, keys)
    assert legacy_info.title_id == title_id, f"예전 CIA 타이틀: {legacy_info.title_id:016X}"
    legacy_cci = converter.cia_to_cci(legacy, work / "정렬안함.cci", keys,
                                      lambda m: None, lambda p: None)
    check_cci(legacy_cci, ncch, title_id)
    assert legacy_cci.read_bytes() == cci_from_plain.read_bytes(), "예전 CIA 변환 결과가 다름"
    print("[ok] 0x40 정렬 안 한 예전 CIA도 읽음")

    # 티켓에 타이틀 키가 평문으로 들어 있는 CIA (common 키 없이도 풀려야 함)
    plain_key_cia = build_fake_cia(
        work / "평문키.cia", ncch, title_id, title_key, common_key, True,
        plain_ticket_key=True)
    plain_key_info = converter.read_cia(plain_key_cia, converter.Keys())
    assert plain_key_info.title_key == title_key, "평문 타이틀 키를 못 찾음"
    assert plain_key_info.title_key_origin == "평문 타이틀 키", plain_key_info.title_key_origin
    plain_key_cci = converter.cia_to_cci(
        plain_key_cia, work / "평문키.cci", converter.Keys(),
        lambda m: None, lambda p: None)
    check_cci(plain_key_cci, ncch, title_id)
    print("[ok] 티켓에 평문으로 든 타이틀 키도 사용")

    # 티켓 타이틀 ID와 TMD 타이틀 ID가 다른 CIA (TMD 쪽으로도 풀어야 함)
    raw = bytearray(enc_cia.read_bytes())
    head = raw[:0x2020]
    layout = _cia_layout(0x2020,
                         int.from_bytes(head[0x08:0x0C], "little"),
                         int.from_bytes(head[0x0C:0x10], "little"),
                         int.from_bytes(head[0x10:0x14], "little"))
    ticket_at = layout[1]
    other_title = 0x00040000001AF401
    raw[ticket_at + 0x140 + 0x9C:ticket_at + 0x140 + 0xA4] = other_title.to_bytes(8, "big")
    mismatch_cia = work / "티켓불일치.cia"
    mismatch_cia.write_bytes(bytes(raw))
    mismatch_info = converter.read_cia(mismatch_cia, keys)
    assert mismatch_info.title_key == title_key, "TMD 타이틀 ID로 타이틀 키를 못 풀음"
    assert mismatch_info.key_verified, "키 검증이 통과로 기록되지 않음"
    assert f"0x{title_id:016X}" in mismatch_info.title_key_origin, mismatch_info.title_key_origin
    print("[ok] 티켓/TMD 타이틀 ID가 달라도 맞는 쪽으로 복호화")

    ncch_file = work / "본편.app"
    ncch_file.write_bytes(ncch)
    cci_from_ncch = converter.ncch_to_cci(ncch_file, work / "ncch.cci", lambda m: None, lambda p: None)
    check_cci(cci_from_ncch, ncch, title_id)
    print("[ok] NCCH → CCI 변환")

    assert converter.roundtrip_check(work / "dummy"), "AES 자체 점검 실패"
    print("[ok] AES-CBC 자체 점검")


def make_crypto_ncch(title_id: int, seed: bytes | None, version: int = 0,
                     flags3: int = 0x0A, size: int = 0x3000) -> bytes:
    """복호화된 상태의 가짜 NCCH(확장 헤더/ExeFS/RomFS 포함)를 만든다."""
    data = bytearray(size)
    for index in range(size):
        data[index] = (index * 7 + 0x11) & 0xFF

    header = bytearray(0x200)
    header[0:16] = bytes(range(16))
    header[0x100:0x104] = b"NCCH"
    header[0x104:0x108] = (size // 0x200).to_bytes(4, "little")
    header[0x108:0x110] = title_id.to_bytes(8, "big")
    header[0x112:0x114] = version.to_bytes(2, "little")
    if seed is not None:
        header[0x114:0x118] = converter._seed_hash(seed, title_id)
    header[0x118:0x120] = title_id.to_bytes(8, "little")

    exthdr = bytearray(0x800)
    for index in range(len(exthdr)):
        exthdr[index] = (index * 3) & 0xFF
    header[0x160:0x180] = hashlib.sha256(exthdr[:0x400]).digest()
    header[0x180:0x184] = (0x400).to_bytes(4, "little")

    header[0x190:0x194] = (5).to_bytes(4, "little")   # 평문 영역 0xA00
    header[0x194:0x198] = (3).to_bytes(4, "little")

    header[0x1A0:0x1A4] = (8).to_bytes(4, "little")   # ExeFS 0x1000
    header[0x1A4:0x1A8] = (4).to_bytes(4, "little")
    header[0x1A8:0x1AC] = (1).to_bytes(4, "little")
    exefs_header = bytearray(0x200)
    files = ((b"code", 0x000, 0x180), (b"icon", 0x200, 0x100), (b"banner", 0x400, 0x200))
    for index, (name, offset, length) in enumerate(files):
        entry = index * 0x10
        exefs_header[entry:entry + 8] = name.ljust(8, b"\x00")
        struct.pack_into("<I", exefs_header, entry + 8, offset)
        struct.pack_into("<I", exefs_header, entry + 12, length)
    header[0x1C0:0x1E0] = hashlib.sha256(exefs_header).digest()

    header[0x1B0:0x1B4] = (16).to_bytes(4, "little")  # RomFS 0x2000
    header[0x1B4:0x1B8] = (8).to_bytes(4, "little")
    header[0x1B8:0x1BC] = (1).to_bytes(4, "little")
    romfs_head = bytearray(0x200)
    romfs_head[0:4] = b"IVFC"
    for index in range(4, 0x200):
        romfs_head[index] = (index * 5) & 0xFF
    header[0x1E0:0x200] = hashlib.sha256(romfs_head).digest()

    data[0:0x200] = header
    data[0x200:0xA00] = exthdr
    data[0x1000:0x1200] = exefs_header
    data[0x2000:0x2200] = romfs_head
    return bytes(data)


def build_crypto_cci(work: Path, name: str, plain: bytes, version: int,
                     flags3: int, seed: bytes | None) -> tuple[Path, bytes, converter.Keys]:
    """평문 NCCH를 표준 암호로 다시 암호화한 CCI를 만든다."""
    title_id = int.from_bytes(plain[0x118:0x120], "little")
    keyx = {
        0x2C: bytes.fromhex("00112233445566778899aabbccddeeff"),
        0x18: bytes.fromhex("ffeeddccbbaa99887766554433221100"),
        0x25: bytes.fromhex("0123456789abcdef0123456789abcdef"),
    }
    keys = converter.Keys(keyx=keyx, seeds={title_id: seed} if seed else {})
    key_menu = converter.normal_key(keyx[0x2C], plain[0:16])
    key_y = (plain[0:16] if seed is None
             else hashlib.sha256(plain[0:16] + seed).digest()[:16])
    key_content = converter.normal_key(keyx[0x18], key_y)

    def ctr_of(section: int, start: int) -> int:
        partition_id = plain[0x108:0x110]
        if version == 1:
            return (int.from_bytes(partition_id, "big") << 64) | start
        return (int.from_bytes(partition_id, "little") << 64) | (section << 56)

    total = 0x4000 + len(plain)
    cci_head = converter._build_ncsd_header([(plain[:0x200], len(plain))], total)
    data = bytearray(cci_head) + bytearray(plain)
    part = 0x4000
    data[part + 0x18B] = flags3
    data[part + 0x18F] = 0x20 if seed is not None else 0

    def crypt(start: int, size: int, key: bytes, base: int, offset: int) -> None:
        data[part + start:part + start + size] = converter.ctr_decrypt(
            key, base, offset, bytes(data[part + start:part + start + size]))

    crypt(0x200, 0x800, key_menu, ctr_of(1, 0x200), 0)
    crypt(0x1000, 0x200, key_menu, ctr_of(2, 0x1000), 0)
    crypt(0x1200, 0x180, key_content, ctr_of(2, 0x1000), 0x200)
    crypt(0x1380, 0x80, key_menu, ctr_of(2, 0x1000), 0x380)
    crypt(0x1400, 0x100, key_menu, ctr_of(2, 0x1000), 0x400)
    crypt(0x1500, 0x100, key_menu, ctr_of(2, 0x1000), 0x500)
    crypt(0x1600, 0x200, key_menu, ctr_of(2, 0x1000), 0x600)
    crypt(0x2000, 0x1000, key_content, ctr_of(3, 0x2000), 0)

    expected = bytearray(cci_head) + bytearray(plain)
    expected[part + 0x18B] = 0
    expected[part + 0x18F] = 0x04
    path = work / name
    path.write_bytes(bytes(data))
    return path, bytes(expected), keys


def test_cci_decrypt(work: Path) -> None:
    """암호화 CCI를 풀어 평문과 같은지 확인한다(표준/시드/version 1)."""
    title_id = app.YW3_BASE_TITLE
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    wrong_seed = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    cases = (
        (0, None, "표준 암호"),
        (0, seed, "시드 암호"),
        (1, seed, "version 1 + 시드"),
    )
    enc_paths = {}
    for version, seed_value, label in cases:
        plain = make_crypto_ncch(title_id, seed_value, version=version)
        name = f"crypto_{version}_{'seed' if seed_value else 'std'}"
        enc_path, expected, keys = build_crypto_cci(
            work, name + ".cci", plain, version, 0x0A, seed_value)
        enc_paths[name] = (enc_path, expected, keys)
        out = converter.decrypt_cci(
            enc_path, work / (name + "_dec.cci"), keys,
            lambda message: None, lambda percent: None)
        assert out.read_bytes() == expected, f"{label}: 복호화 결과가 평문과 다름"
        info = app.inspect_rom(enc_path)
        assert info.kind == "cci" and info.encrypted is True, f"{label}: 판별 실패"
        assert info.key_slots == (0x2C, 0x18), f"{label}: 키 슬롯 {info.key_slots}"
        print(f"[ok] CCI 복호화 — {label}")

    enc_path, std_expected, keys = enc_paths["crypto_0_std"]
    try:
        converter.decrypt_cci(enc_path, work / "no_key.cci", converter.Keys(),
                              lambda message: None, lambda percent: None)
    except converter.ConvertError as exc:
        assert "slot0x2CKeyX" in str(exc), str(exc)
        print("[ok] keyX 없을 때 안내")
    else:
        raise AssertionError("keyX가 없는데 복호화가 됐다")

    seed_path, _expected, seed_keys = enc_paths["crypto_0_seed"]
    try:
        converter.decrypt_cci(seed_path, work / "no_seed.cci",
                              converter.Keys(keyx=seed_keys.keyx),
                              lambda message: None, lambda percent: None)
    except converter.ConvertError as exc:
        assert "seeddb.bin" in str(exc), str(exc)
        print("[ok] 시드 없을 때 안내")
    else:
        raise AssertionError("시드가 없는데 복호화가 됐다")

    try:
        converter.decrypt_cci(seed_path, work / "bad_seed.cci",
                              converter.Keys(keyx=seed_keys.keyx, seeds={title_id: wrong_seed}),
                              lambda message: None, lambda percent: None)
    except converter.ConvertError as exc:
        assert "맞지 않" in str(exc), str(exc)
        print("[ok] 시드가 틀릴 때 안내")
    else:
        raise AssertionError("시드가 틀렸는데 복호화가 됐다")

    bad_keys = {slot: bytes(16) for slot in keys.keyx}
    try:
        converter.decrypt_cci(enc_path, work / "bad_key.cci",
                              converter.Keys(keyx=bad_keys),
                              lambda message: None, lambda percent: None)
    except converter.ConvertError as exc:
        assert "확장 헤더" in str(exc), str(exc)
        print("[ok] keyX가 틀릴 때 안내")
    else:
        raise AssertionError("keyX가 틀렸는데 복호화가 됐다")

    # 외부 변환 도구가 헤더의 암호 플래그만 지운 파일: 플래그를 믿지 말고
    # 실제 확장 헤더를 보고 다시 풀어야 한다.
    fake = work / "fake_plain.cci"
    data = bytearray(enc_path.read_bytes())
    data[0x4000 + 0x18F] |= 0x04
    fake.write_bytes(bytes(data))
    messages: list[str] = []
    fixed = converter.decrypt_cci(
        fake, work / "fake_plain_dec.cci", keys,
        messages.append, lambda percent: None)
    assert fixed.read_bytes() == std_expected, "플래그만 바뀐 CCI를 다시 풀지 못함"
    assert any("다시 풀어" in message for message in messages), messages
    print("[ok] 암호 플래그만 바뀐 CCI는 내용을 확인해 다시 복호화")

    repair_role = app.Role(
        key="base", label="본편", patch_name="x", patch_size=1,
        patch_sha256="0" * 64, result_name="repair.cci", result_size=1,
        result_sha256="0" * 64)
    prepared = app.prepare_source(
        repair_role, fake, work, keys,
        lambda m: None, lambda s: None, lambda p: None, check_profile=False)
    assert prepared.converted, prepared
    assert prepared.path.read_bytes() == std_expected, "prepare_source가 다시 풀지 못함"
    print("[ok] prepare_source가 플래그만 바뀐 CCI를 자동 복호화")

    decrypted = work / "crypto_0_std_dec.cci"
    try:
        converter.decrypt_cci(decrypted, work / "again.cci", keys,
                              lambda message: None, lambda percent: None)
    except converter.ConvertError as exc:
        assert "이미 복호화" in str(exc), str(exc)
        print("[ok] 이미 복호화된 CCI 안내")
    else:
        raise AssertionError("이미 복호화된 CCI를 또 풀었다")


def test_ctr_stream(work: Path) -> None:
    """CTR 키스트림이 1MiB 배치 경계와 비정렬 오프셋에서도 맞는지 확인한다."""
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    size = converter.CTR_BATCH_BLOCKS * 16 * 2 + 0x1234  # 배치 두 개 + 자투리
    data = bytes((index * 31 + 7) & 0xFF for index in range(size))
    base = (0x00040000001AF400 << 64) | (2 << 56)

    blocks = (size + 15) // 16
    with converter.AesEcb(key) as aes:
        stream = aes.encrypt_blocks(converter._counters_general(base, blocks))
    expected = converter._xor_bytes(data, stream[:size])

    assert converter.ctr_decrypt(key, base, 0, data) == expected, "배치 경계에서 어긋남"
    with converter.CtrCipher(key, base) as cipher:
        assert cipher.decrypt(0, data) == expected
        for offset in (5, 16, 0x1000):
            begin = offset
            end = min(size, begin + 0x2345)
            piece = data[begin:end]
            assert cipher.decrypt(begin, piece) == expected[begin:end], f"오프셋 {offset} 어긋남"

    # NIST SP 800-38A AES-128-CTR 첫 블록(카운터는 128비트 빅엔디언)
    kat_key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    kat_ctr = int.from_bytes(bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"), "big")
    kat_plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    kat_cipher = bytes.fromhex("874d6191b620e3261bef6864990db6ce")
    assert converter.ctr_decrypt(kat_key, kat_ctr, 0, kat_cipher) == kat_plain, "NIST CTR 벡터 불일치"
    print("[ok] CTR 키스트림 (1MiB 배치 경계/비정렬 오프셋/NIST 벡터)")


def test_key_files(work: Path) -> None:
    """keys.txt의 keyX/seed 줄과 seeddb.bin 병합을 확인한다."""
    title_id = app.YW3_BASE_TITLE
    keyx_2c = bytes.fromhex("00112233445566778899aabbccddeeff")
    keyx_18 = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    key_dir = work / "key_dir"
    key_dir.mkdir()
    (key_dir / "keys.txt").write_text(
        f"slot0x2CKeyX: {keyx_2c.hex()}\n"
        f"keyX18 = {keyx_18.hex().upper()}\n"
        f"common: {'11' * 16}\n",
        encoding="utf-8",
    )
    parsed = converter.load_keys_file(key_dir / "keys.txt")
    assert parsed.keyx[0x2C] == keyx_2c and parsed.keyx[0x18] == keyx_18, parsed.keyx
    assert parsed.common == bytes.fromhex("11" * 16)

    seed_dir = work / "seed_dir"
    seed_dir.mkdir()
    seeddb = bytearray(16 + 0x20)
    struct.pack_into("<I", seeddb, 0, 1)
    seeddb[16:24] = title_id.to_bytes(8, "little")
    seeddb[24:40] = seed
    (seed_dir / "seeddb.bin").write_bytes(bytes(seeddb))
    assert converter.load_seeddb(seed_dir / "seeddb.bin")[title_id] == seed

    merged = converter.load_keys([key_dir, seed_dir])
    assert merged.keyx[0x2C] == keyx_2c and merged.seeds[title_id] == seed, merged

    other_dir = work / "other_keys"
    other_dir.mkdir()
    (other_dir / "keys.txt").write_text(
        f"slot0x3DKey0: {keyx_2c.hex()}\n"
        f"common01: {keyx_18.hex()}\n",
        encoding="utf-8",
    )
    other = converter.load_keys_file(other_dir / "keys.txt")
    assert other.common_keys[0] == keyx_2c, f"slot0x3DKey0: {other}"
    assert other.common_keys[1] == keyx_18, f"common01: {other}"
    print("[ok] keys.txt keyX/seed 줄, seeddb.bin 병합")


def test_common_key_derivation(work: Path) -> None:
    """keys.txt의 common0(KeyY)와 slot0x3DKeyX로 normal key를 만드는지 확인한다."""
    key_x = bytes.fromhex("617085719b7cfb316df4df2e8362c6e2")
    key_y = bytes.fromhex("D07B337F9CA4385932A2E25723232EB9")
    expected = bytes.fromhex("64c5fd55dd3ad988325baaec5243db98")
    assert converter.normal_key(key_x, key_y) == expected, "공통 키 스크램블러 불일치"

    key_dir = work / "common_keys"
    key_dir.mkdir()
    (key_dir / "keys.txt").write_text(
        f"slot0x3DKeyX: {key_x.hex()}\ncommon0: {key_y.hex()}\n", encoding="utf-8")
    parsed = converter.load_keys_file(key_dir / "keys.txt")
    assert parsed.common_y[0] == key_y and parsed.keyx[0x3D] == key_x, parsed
    candidates = parsed.common_candidates(0)
    assert candidates and candidates[0] == (0, expected), candidates
    assert parsed.has_common(), "common 키가 있다고 보지 않음"
    print("[ok] common0(KeyY) + slot0x3DKeyX → normal key")

    title_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    ncch = make_fake_ncch(app.YW3_BASE_TITLE, 0x8000)
    cia = build_fake_cia(work / "keyy.cia", ncch, app.YW3_BASE_TITLE, title_key, expected, True)
    info = converter.read_cia(cia, parsed)
    assert info.key_verified and info.title_key_index == 0, info
    assert info.title_key == title_key, "타이틀 키가 다름"

    reference = converter.cia_to_cci(
        build_fake_cia(work / "keyy_plain.cia", ncch, app.YW3_BASE_TITLE,
                       title_key, expected, False),
        work / "keyy_ref.cci", parsed, lambda m: None)
    converted = converter.cia_to_cci(cia, work / "keyy.cci", parsed, lambda m: None)
    assert converted.read_bytes() == reference.read_bytes(), "KeyY 경로 변환 결과가 다름"
    print("[ok] KeyY만 있는 keys.txt로 암호화 CIA 변환")

    # GodMode9 DumpKeys가 실제로 쓰는 형식(=, 주석 줄)도 그대로 읽어야 한다.
    dumpkeys = work / "aes_keys.txt"
    dumpkeys.write_text(
        "# Ticket Common KeyY (slot 0x3D)\n"
        f"slot0x3DKeyX={key_x.hex()}\n"
        f"common0={key_y.hex()}\n",
        encoding="utf-8")
    real_style = converter.load_keys_file(dumpkeys)
    assert real_style.common_y[0] == key_y and real_style.keyx[0x3D] == key_x, real_style
    again = converter.cia_to_cci(cia, work / "keyy_dump.cci", real_style, lambda m: None)
    assert again.read_bytes() == reference.read_bytes(), "DumpKeys 형식 변환 결과가 다름"
    print("[ok] GodMode9 aes_keys.txt 형식(=, 주석)도 읽음")

    wrong_dir = work / "wrong_keys"
    wrong_dir.mkdir()
    (wrong_dir / "keys.txt").write_text(
        f"slot0x3DKeyX: {key_x.hex()}\ncommon0: {'22' * 16}\n", encoding="utf-8")
    wrong = converter.load_keys([wrong_dir])
    try:
        converter.cia_to_cci(cia, work / "wrong.cci", wrong, lambda m: None)
    except converter.ConvertError as exc:
        assert "KeyY" in str(exc), str(exc)
        print("[ok] 틀린 common 키는 KeyY 안내로 거부")
    else:
        raise AssertionError("틀린 키인데 변환이 됐다")

    # TMD는 암호화라고 하는데 실제 내용은 평문인 CIA(hshop 등)
    plain_flag = build_fake_cia(work / "plain_flag.cia", ncch, app.YW3_BASE_TITLE,
                                title_key, expected, True)
    stub = converter.read_cia(plain_flag)
    with plain_flag.open("r+b") as handle:
        handle.seek(stub.program.offset)
        handle.write(ncch)
    info = converter.read_cia(plain_flag, parsed)
    assert info.needs_key is False, "평문 내용을 암호화로 봄"
    converted = converter.cia_to_cci(plain_flag, work / "plain_flag.cci", parsed, lambda m: None)
    assert converted.read_bytes() == reference.read_bytes(), "평문 플래그 CIA 변환 결과가 다름"
    print("[ok] 암호화 플래그만 남은 평문 CIA도 변환")

    picked = work / "picked_keys.txt"
    picked.write_text(f"slot0x3DKeyX: {key_x.hex()}\ncommon0: {key_y.hex()}\n",
                      encoding="utf-8")
    empty = work / "empty_keys_dir"
    empty.mkdir(exist_ok=True)
    chosen = converter.load_keys([empty], [picked])
    assert chosen.has_common() and chosen.path == picked, chosen
    print("[ok] 화면에서 고른 키 파일을 폴더 없이 바로 읽음")


def test_title_key_probe_any_content(work: Path) -> None:
    """첫 내용이 깨져 있어도 다른 내용으로 타이틀 키를 확인하는지 본다."""
    title_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    common_key = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    title_id = app.YW3_BASE_TITLE
    contents = [make_fake_ncch(title_id, 0x4000), make_fake_ncch(title_id, 0x4000)]
    cia = build_multi_cia(work / "probe_multi.cia", contents, title_id,
                          title_key, common_key, True)
    keys = converter.Keys(common=common_key)

    stub = converter.read_cia(cia)
    first = sorted(stub.contents, key=lambda item: item.index)[0]
    broken = bytearray(cia.read_bytes())
    broken[first.offset + 0x100] ^= 0xFF  # 암호문 한 블록을 건드려 NCCH 매직을 깨뜨림
    cia.write_bytes(bytes(broken))

    info = converter.read_cia(cia, keys)
    assert info.title_key == title_key, "다른 내용으로 타이틀 키를 못 찾음"
    assert info.key_verified, "타이틀 키 확인 실패로 기록됨"
    assert first.index in info.bad_contents, info.bad_contents

    try:
        converter.cia_to_cci(cia, work / "probe_multi.cci", keys, lambda m: None)
    except converter.ConvertError as exc:
        message = str(exc)
        assert "일부 내용이 NCCH로" in message, message
        assert "common" not in message, message
        print("[ok] 첫 내용이 깨져도 다른 내용으로 키 확인, 내용 문제로 안내")
    else:
        raise AssertionError("깨진 내용이 있는데 변환이 됐다")


def test_convert_levels(work: Path) -> None:
    """변환 대상 파일이 경고가 아니라 '변환해서 진행' 안내로 보이는지 확인한다."""
    title_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    common_key = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    ncch = make_fake_ncch(app.YW3_BASE_TITLE)
    base_cia = build_fake_cia(work / "본편 평문.cia", ncch, app.YW3_BASE_TITLE,
                              title_key, common_key, False)
    enc_cia = build_fake_cia(work / "업데이트 암호.cia", ncch, app.YW3_UPDATE_TITLE,
                             title_key, common_key, True)
    message, level = app.describe_rom("base", app.inspect_rom(base_cia))
    assert level == "info" and "CCI" in message, message
    message, level = app.describe_rom("update", app.inspect_rom(enc_cia))
    assert level == "info" and "암호" in message, message
    print("[ok] 변환 대상 안내 문구")


def test_prepare_pipeline(exe: Path, work: Path) -> None:
    """CIA → CCI 변환 후 바로 패치까지 이어지는지 확인한다."""
    title_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    common_key = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    title_id = app.YW3_BASE_TITLE
    keys = converter.Keys(common=common_key, path=work / "keys.txt")

    ncch_file = work / "pipe.app"
    ncch_file.write_bytes(make_fake_ncch(title_id, 0x8000))
    reference = converter.ncch_to_cci(ncch_file, work / "pipe_ref.cci", lambda m: None, lambda p: None)
    ncch = ncch_file.read_bytes()

    for encrypt in (False, True):
        cia = build_fake_cia(work / f"pipe_{encrypt}.cia", ncch, title_id, title_key, common_key, encrypt)
        prepared = app.prepare_source(
            app.BASE, cia, work, keys,
            lambda m: None, lambda s: None, lambda p: None, check_profile=False)
        assert prepared.converted, "CIA인데 변환으로 표시되지 않음"
        assert prepared.path.read_bytes() == reference.read_bytes(), "변환 결과가 기준 CCI와 다름"
        prepared.path.unlink()
    print("[ok] prepare_source: CIA → CCI (평문/암호문 모두)")

    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plain_ncch = make_crypto_ncch(title_id, seed)
    enc_cci, expected_cci, cci_keys = build_crypto_cci(
        work, "pipe_enc.cci", plain_ncch, 0, 0x0A, seed)
    prepared = app.prepare_source(
        app.BASE, enc_cci, work, cci_keys,
        lambda m: None, lambda s: None, lambda p: None, check_profile=False)
    assert prepared.converted, "암호화 CCI인데 변환으로 표시되지 않음"
    assert prepared.path.read_bytes() == expected_cci, "암호화 CCI 복호화 결과가 다름"
    prepared.path.unlink()
    print("[ok] prepare_source: 암호화 CCI → 복호화 CCI")

    target = work / "pipe_target.bin"
    data = bytearray(reference.read_bytes())
    data[0x6000:0x6010] = b"korean patch!!  "
    target.write_bytes(bytes(data))
    diff = work / "pipe.xdelta"
    app.subprocess.run([str(exe), "-e", "-f", "-s", str(reference), str(target), str(diff)],
                       capture_output=True, check=True)
    role = app.Role(
        key="base", label="본편", patch_name=diff.name, patch_size=diff.stat().st_size,
        patch_sha256=sha256_bytes(diff.read_bytes()), result_name="pipe_out.cci",
        result_size=len(data), result_sha256=sha256_bytes(bytes(data)),
    )
    out_dir = work / "pipe_out"
    out_dir.mkdir()
    report: dict = {}
    result = app.apply_patch(
        role, reference, out_dir, exe, diff, True, True,
        lambda m: None, lambda p: None, lambda s: None,
        strict=False, report=report,
    )
    assert result.read_bytes() == bytes(data), "패치 결과가 다름"
    assert report.get("verified") is True, "지문 검증이 통과로 기록되지 않음"
    print("[ok] 변환본 → 패치 → 지문 검증")


def test_trimmed_cci(exe: Path, work: Path) -> None:
    """다른 도구가 뒤쪽 빈 구간을 잘라낸 CCI도 크기를 맞춰 패치하는지 확인한다."""
    reference = make_fake_cci(work, "trim_ref.cci", app.YW3_BASE_TITLE, encrypted=False)
    data = bytearray(reference.read_bytes())
    data[0x300:0x310] = b"korean patch!!! "
    target = work / "trim_target.cci"
    target.write_bytes(bytes(data))
    diff = work / "trim.xdelta"
    app.subprocess.run([str(exe), "-e", "-f", "-s", str(reference), str(target), str(diff)],
                       capture_output=True, check=True)

    trimmed = work / "trim_input.cci"
    trimmed.write_bytes(reference.read_bytes()[:0x1000])
    role = app.Role(
        key="base", label="본편", patch_name=diff.name, patch_size=diff.stat().st_size,
        patch_sha256=sha256_bytes(diff.read_bytes()), result_name="trim_out.cci",
        result_size=target.stat().st_size, result_sha256=sha256_bytes(target.read_bytes()),
        source_size=reference.stat().st_size,
    )
    prepared = app.prepare_source(
        role, trimmed, work, converter.Keys(),
        lambda m: None, lambda s: None, lambda p: None, check_profile=False)
    assert prepared.converted and prepared.padded_from == 0x1000, prepared
    assert prepared.path.stat().st_size == reference.stat().st_size, "원본 크기로 못 채움"

    out_dir = work / "trim_out"
    out_dir.mkdir()
    report: dict = {}
    result = app.apply_patch(
        role, prepared.path, out_dir, exe, diff, True, True,
        lambda m: None, lambda p: None, lambda s: None,
        strict=False, report=report, allow_header=prepared.allow_header,
        padded_from=prepared.padded_from)
    assert result.read_bytes() == target.read_bytes(), "자른 CCI 패치 결과가 다름"
    assert report.get("verified") is True, report
    print("[ok] 뒤가 잘린 CCI는 0으로 채워 패치")



def build_multi_cia(path: Path, contents: list[bytes], title_id: int, title_key: bytes,
                    common_key: bytes, encrypt: bool) -> Path:
    """본편/설명서/DLP 내용을 여러 개 담은 CIA를 만든다(카트리지 덤프 흉내)."""
    header_size = 0x2020
    cert = bytearray(0x400)
    cert[0:4] = (0x00010003).to_bytes(4, "big")
    cert = bytes(cert)
    ticket = bytearray(0x140 + 0x210)
    ticket[0:4] = (0x00010004).to_bytes(4, "big")
    iv = title_id.to_bytes(8, "big") + b"\x00" * 8
    ticket[0x140 + 0x7F:0x140 + 0x8F] = converter.cbc_encrypt(common_key, iv, title_key)
    ticket[0x140 + 0x9C:0x140 + 0xA4] = title_id.to_bytes(8, "big")
    ticket = bytes(ticket)

    records = 0x30 * len(contents)
    tmd = bytearray(0x140 + 0xC4 + 0x24 * 64 + records)
    tmd[0:4] = (0x00010004).to_bytes(4, "big")
    tmd[0x140 + 0x4C:0x140 + 0x54] = title_id.to_bytes(8, "big")
    tmd[0x140 + 0x9E:0x140 + 0xA0] = len(contents).to_bytes(2, "big")
    base = 0x140 + 0xC4 + 0x24 * 64
    for index, ncch in enumerate(contents):
        record = base + index * 0x30
        tmd[record + 0x00:record + 0x04] = index.to_bytes(4, "big")
        tmd[record + 0x04:record + 0x06] = index.to_bytes(2, "big")
        tmd[record + 0x06:record + 0x08] = (1 if encrypt else 0).to_bytes(2, "big")
        tmd[record + 0x08:record + 0x10] = len(ncch).to_bytes(8, "big")
    tmd = bytes(tmd)

    cert_offset, ticket_offset, tmd_offset, _meta_offset, content_offset = _cia_layout(
        header_size, len(cert), len(ticket), len(tmd))
    payload = bytearray()
    for index, ncch in enumerate(contents):
        if encrypt:
            payload += converter.cbc_encrypt(title_key, converter._content_iv(index), ncch)
        else:
            payload += ncch
    head = bytearray(header_size)
    struct.pack_into("<I", head, 0x00, header_size)
    struct.pack_into("<I", head, 0x08, len(cert))
    struct.pack_into("<I", head, 0x0C, len(ticket))
    struct.pack_into("<I", head, 0x10, len(tmd))
    struct.pack_into("<I", head, 0x14, 0)
    struct.pack_into("<Q", head, 0x18, len(payload))
    blob = bytearray(content_offset)
    blob[0:header_size] = head
    blob[cert_offset:cert_offset + len(cert)] = cert
    blob[ticket_offset:ticket_offset + len(ticket)] = ticket
    blob[tmd_offset:tmd_offset + len(tmd)] = tmd
    path.write_bytes(bytes(blob) + bytes(payload))
    return path


def test_multi_content(work: Path) -> None:
    """카트리지처럼 본편·설명서·DLP를 담은 CIA가 CCI 파티션 3개로 묶이는지 확인한다."""
    title_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    common_key = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    title_id = app.YW3_BASE_TITLE
    keys = converter.Keys(common=common_key)

    contents = [
        make_fake_ncch(title_id, 0x8000),
        make_fake_ncch(title_id, 0x4000),
        make_fake_ncch(title_id, 0x2000),
    ]
    for encrypt in (False, True):
        cia = build_multi_cia(work / f"multi_{encrypt}.cia", contents, title_id,
                              title_key, common_key, encrypt)
        cci = converter.cia_to_cci(cia, work / f"multi_{encrypt}.cci", keys, lambda m: None)
        data = cci.read_bytes()
        partitions = converter.read_ncsd(cci)
        assert len(partitions) == 3, f"파티션 {len(partitions)}개"
        assert [item.size for item in partitions] == [0x8000, 0x4000, 0x2000], partitions
        assert int.from_bytes(data[0x104:0x108], "little") * 0x200 == len(data), "미디어 크기 필드"
        for partition, plain in zip(partitions, contents):
            expected = bytearray(plain)
            expected[0x18F] |= 0x04
            part = data[partition.offset:partition.offset + partition.size]
            assert part == bytes(expected), f"파티션 {partition.index} 내용 불일치"
        assert int.from_bytes(data[0x190:0x198], "big") == title_id, "파티션 0 ID"
        assert int.from_bytes(data[0x1A0:0x1A8], "big") == title_id, "파티션 2 ID"
        print(f"[ok] 다중 내용 CIA({len(contents)}개) → CCI, 암호화={encrypt}")

    cci = work / "multi_False.cci"
    packed = cci.stat().st_size
    padded = converter.cia_to_cci(
        work / "multi_False.cia", work / "multi_pad.cci", keys, lambda m: None,
        min_size=packed + 0x1000)
    assert padded.stat().st_size == _align(packed + 0x1000, 0x200), padded.stat().st_size
    assert converter.read_ncsd(padded)[-1].offset + converter.read_ncsd(padded)[-1].size <= packed
    print("[ok] 모자란 CCI는 카트리지 크기까지 0으로 채움")


def test_profile_check(work: Path) -> None:
    """공식 manifest 해시와 영역이 다르면 어디가 다른지 짚어 주는지 확인한다."""
    title_id = app.YW3_BASE_TITLE
    plain = make_crypto_ncch(title_id, None)
    ncch_file = work / "prof.app"
    ncch_file.write_bytes(plain)
    cci = converter.ncch_to_cci(ncch_file, work / "prof.cci",
                                lambda m: None, lambda p: None)

    specs = []
    for region in converter.ncch_regions(plain[:0x200]):
        digest = sha256_bytes(plain[region.offset:region.offset + region.size])
        specs.append(app.profiles.RegionSpec(region.name, region.size, digest))
    profile = app.profiles.Profile(
        role="base", parts=(app.profiles.PartSpec(0, title_id, "", tuple(specs)),))

    role = app.Role(
        key="base", label="본편", patch_name="x", patch_size=1,
        patch_sha256="0" * 64, result_name="prof_out.cci", result_size=1,
        result_sha256="0" * 64)

    saved = app.profiles.PROFILES
    app.profiles.PROFILES = {"base": profile}
    try:
        issues = app.check_source_profile(
            cci, role, converter.Keys(), lambda m: None, lambda s: None)
        assert not issues, issues
        prepared = app.prepare_source(
            role, cci, work, converter.Keys(),
            lambda m: None, lambda s: None, lambda p: None)
        assert prepared.path == cci, prepared
        print("[ok] 게임 영역 해시가 공식 manifest와 일치")

        part0 = converter.read_ncsd(cci)[0]
        bad = bytearray(cci.read_bytes())
        bad[part0.offset + 0x1000 + 0x10] ^= 0xFF  # ExeFS 첫 블록
        bad_path = work / "prof_bad.cci"
        bad_path.write_bytes(bytes(bad))
        issues = app.check_source_profile(
            bad_path, role, converter.Keys(), lambda m: None, lambda s: None)
        assert issues and "ExeFS" in issues[0], issues
        try:
            app.prepare_source(
                role, bad_path, work, converter.Keys(),
                lambda m: None, lambda s: None, lambda p: None)
        except app.PatchError as exc:
            assert "ExeFS" in str(exc) and "원본 해시" in str(exc), str(exc)
            print("[ok] ExeFS가 다르면 원본 영역 해시 불일치로 중단")
        else:
            raise AssertionError("영역이 다른데 prepare_source가 통과됨")
    finally:
        app.profiles.PROFILES = saved


def test_window_verify(exe: Path, work: Path) -> None:
    """변환본 패치 검사: 헤더만 다르면 통과, 내용이 다르면 거부."""
    source = work / "win_ref.bin"
    data = bytearray(os.urandom(0x4000 + 0xC00000))  # 12MB + 헤더
    data[0x1100:0x1200] = os.urandom(0x100)
    source.write_bytes(bytes(data))
    target = bytearray(data)
    target[0x2000:0x2010] = b"korean patch!!! "
    target[0x900000:0x900010] = b"deep content!!!!"
    target_path = work / "win_target.bin"
    target_path.write_bytes(bytes(target))

    diff = work / "win.xdelta"
    app.subprocess.run([str(exe), "-e", "-f", "-s", str(source), str(target_path), str(diff)],
                       capture_output=True, check=True)
    windows = converter.read_vcdiff_windows(diff)
    assert sum(length for _offset, length, _checksum in windows) == len(target), "창 크기 합"
    assert len(windows) == 2, f"창 {len(windows)}개"

    good = work / "win_good.bin"
    app.subprocess.run([str(exe), "-d", "-f", "-s", str(source), str(diff), str(good)],
                       capture_output=True, check=True)
    digest, bad = app._check_windows(good, windows, None)
    assert not bad, f"정상 원본인데 창이 다름: {bad}"
    assert digest == hashlib.sha256(bytes(target)).hexdigest()

    role = app.Role(
        key="base", label="본편", patch_name=diff.name, patch_size=diff.stat().st_size,
        patch_sha256=sha256_bytes(diff.read_bytes()), result_name="win_out.bin",
        result_size=len(target), result_sha256=sha256_bytes(bytes(target)),
    )
    out_dir = work / "win_out"
    out_dir.mkdir()

    header_diff = bytearray(data)
    header_diff[0x1100:0x1110] = b"DIFFERENTHEADER!"
    header_source = work / "win_header.bin"
    header_source.write_bytes(bytes(header_diff))
    report: dict = {}
    kept = app.apply_patch(
        role, header_source, out_dir, exe, diff, True, True,
        lambda m: None, lambda p: None, lambda s: None,
        strict=False, report=report, allow_header=True)
    assert kept.is_file() and report.get("verified") is False, "헤더 차이를 통과시키지 못함"
    assert report.get("windows_ok") is False, "창 검사 기록이 없음"
    kept.unlink()
    print("[ok] 변환본 패치: 헤더만 다르면 통과")

    content_diff = bytearray(data)
    content_diff[0xA00000] ^= 0xFF
    content_source = work / "win_content.bin"
    content_source.write_bytes(bytes(content_diff))
    try:
        app.apply_patch(
            role, content_source, out_dir, exe, diff, True, True,
            lambda m: None, lambda p: None, lambda s: None,
            strict=False, allow_header=True)
    except app.PatchError as exc:
        assert "달라서" in str(exc), str(exc)
        print("[ok] 변환본 패치: 내용이 다르면 거부")
    else:
        raise AssertionError("내용이 다른데 패치를 통과시켰다")
    assert not (out_dir / "win_out.bin.part").exists(), "실패 후 임시 파일이 남음"


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="yw3ko_test_"))
    os.environ[app.CACHE_ENV] = str(work / "cache")
    try:
        log = lambda message: print(f"  ... {message}")  # noqa: E731
        exe = test_xdelta(log)
        test_patch_extract(log)
        test_apply_roundtrip(exe, work)
        test_rom_detection(work)
        test_converter(work)
        test_key_files(work)
        test_common_key_derivation(work)
        test_title_key_probe_any_content(work)
        test_ctr_stream(work)
        test_cci_decrypt(work)
        test_convert_levels(work)
        test_prepare_pipeline(exe, work)
        test_trimmed_cci(exe, work)
        test_multi_content(work)
        test_profile_check(work)
        test_window_verify(exe, work)
        test_ui_states(work)
        test_gui()
        test_gui_flow(exe, work)
        print("\n전체 통과")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
