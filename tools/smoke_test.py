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
    Path(r"C:\Users\swpar\AppData\Local\Temp\opencode\yw3\YW3S_Korean_Patch_v1.0.zip"),
    ROOT / "YW3S_Korean_Patch_v1.0.zip",
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
    gui.destroy()
    print("[ok] GUI 생성/종료")


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
                app.messagebox.askyesno)
    app.BASE, app.UPDATE, app.ROLES = roles[0], roles[1], tuple(roles)
    app.ensure_xdelta = lambda log, progress=None: exe
    app.ensure_patch = lambda role, log, progress=None: outputs[role.key][1]
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
        assert "완료" in gui.ready_var.get(), gui.ready_var.get()
        assert gui.open_button.winfo_manager() == "pack", "완료 후 폴더 열기 버튼이 없음"
        print(f"[ok] GUI 흐름 완료 (진행률 {gui.progress['value']:.0f}%)")
    finally:
        if gui is not None:
            gui.destroy()
        (app.BASE, app.UPDATE, app.ROLES, app.ensure_xdelta, app.ensure_patch,
         app.messagebox.askyesno) = original


def write_fake_ncch(buffer: bytearray, offset: int, title_id: int, encrypted: bool) -> None:
    buffer[offset + 0x100:offset + 0x104] = b"NCCH"
    buffer[offset + 0x18F] = 0x00 if encrypted else 0x04
    buffer[offset + 0x118:offset + 0x120] = title_id.to_bytes(8, "big")


def make_fake_cci(work: Path, name: str, title_id: int, encrypted: bool) -> Path:
    data = bytearray(0x4000)
    data[0x100:0x104] = b"NCSD"
    struct.pack_into("<I", data, 0x120, 1)  # 파티션 0은 미디어 유닛 1(0x200)
    write_fake_ncch(data, 0x200, title_id, encrypted)
    path = work / name
    path.write_bytes(data)
    return path


def make_fake_cia(work: Path, name: str, title_id: int, encrypted: bool) -> Path:
    header_size, cert, ticket, tmd, meta = 0x2020, 0xA00, 0x2A00, 0x2000, 0x3AC0
    content = (header_size + cert + ticket + tmd + meta + 0x3F) & ~0x3F
    data = bytearray(content + 0x400)
    struct.pack_into("<I", data, 0x00, header_size)
    struct.pack_into("<I", data, 0x08, cert)
    struct.pack_into("<I", data, 0x0C, ticket)
    struct.pack_into("<I", data, 0x10, tmd)
    struct.pack_into("<I", data, 0x14, meta)
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
        ("base", enc_cci, "warn"),
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
    data[0x118:0x120] = title_id.to_bytes(8, "big")
    data[0x160:0x180] = bytes(range(32))
    data[0x18F] = 0x00
    for index in range(0x400, size, 0x100):
        data[index:index + 4] = (index * 7).to_bytes(4, "little")
    return bytes(data)


def build_fake_cia(path: Path, ncch: bytes, title_id: int, title_key: bytes,
                   common_key: bytes, encrypt: bool) -> Path:
    header_size = 0x2020
    cert = b"\x00" * 0x400
    ticket = bytearray(0x140 + 0x210)
    ticket[0:4] = (0x00010004).to_bytes(4, "big")
    iv = title_id.to_bytes(8, "big") + b"\x00" * 8
    ticket[0x140 + 0x7F:0x140 + 0x8F] = converter.cbc_encrypt(common_key, iv, title_key)
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

    content_offset = _align(header_size + len(cert) + len(ticket) + len(tmd), 0x40)
    payload = converter.cbc_encrypt(title_key, b"\x00" * 16, ncch) if encrypt else ncch
    head = bytearray(header_size)
    struct.pack_into("<I", head, 0x00, header_size)
    struct.pack_into("<I", head, 0x08, len(cert))
    struct.pack_into("<I", head, 0x0C, len(ticket))
    struct.pack_into("<I", head, 0x10, len(tmd))
    struct.pack_into("<I", head, 0x14, 0)
    struct.pack_into("<Q", head, 0x18, len(payload))
    blob = bytes(head) + cert + ticket + tmd
    blob += b"\x00" * (content_offset - len(blob))
    path.write_bytes(blob + payload)
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

    ncch_file = work / "본편.app"
    ncch_file.write_bytes(ncch)
    cci_from_ncch = converter.ncch_to_cci(ncch_file, work / "ncch.cci", lambda m: None, lambda p: None)
    check_cci(cci_from_ncch, ncch, title_id)
    print("[ok] NCCH → CCI 변환")

    assert converter.roundtrip_check(work / "dummy"), "AES 자체 점검 실패"
    print("[ok] AES-CBC 자체 점검")


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
    keys = converter.Keys(common_key, work / "keys.txt")

    ncch_file = work / "pipe.app"
    ncch_file.write_bytes(make_fake_ncch(title_id, 0x8000))
    reference = converter.ncch_to_cci(ncch_file, work / "pipe_ref.cci", lambda m: None, lambda p: None)
    ncch = ncch_file.read_bytes()

    for encrypt in (False, True):
        cia = build_fake_cia(work / f"pipe_{encrypt}.cia", ncch, title_id, title_key, common_key, encrypt)
        prepared, converted = app.prepare_source(
            app.BASE, cia, work, keys,
            lambda m: None, lambda s: None, lambda p: None)
        assert converted, "CIA인데 변환으로 표시되지 않음"
        assert prepared.read_bytes() == reference.read_bytes(), "변환 결과가 기준 CCI와 다름"
        prepared.unlink()
    print("[ok] prepare_source: CIA → CCI (평문/암호문 모두)")

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
        test_convert_levels(work)
        test_prepare_pipeline(exe, work)
        test_ui_states(work)
        test_gui()
        test_gui_flow(exe, work)
        print("\n전체 통과")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
