"""요괴워치3 스키야키 한국어 패치 적용기.

사용자가 가진 본편 ROM(CCI/CIA)과 업데이트 파일(CIA) 두 개를 고르면
제작팀 공식 릴리즈의 xdelta 패치를 내려받아 자동으로 적용한다.

- 원본 파일은 절대 수정하지 않고, 결과 파일을 새로 만든다.
- 원본이 지원 버전인지 미리 검사해서 막지 않는다(사용자 요청).
  맞지 않으면 xdelta3가 거부하고, 그때 이유를 알려준다.
- 패치 파일은 재배포 금지라서 exe에 넣지 않고 매번 공식 릴리즈에서 받는다.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import queue
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import urllib.request
import webbrowser
import zipfile
import zlib
from dataclasses import dataclass, replace
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import yw3convert as converter
import yw3profile as profiles
import yw3updates as updates
import yw3verify as container_verify

APP_NAME = "요괴워치3 스키야키 한국어 패치 적용기"
APP_VERSION = "1.5.1"
CACHE_ENV = "YW3KO_CACHE"

REPO = "TeamLimRyan/YW3_SUKIYAKI_KOREAN_LOCALIZATION_RELEASE"
RELEASE_TAG = "v1.01"
PATCH_ZIP_NAME = "YW3S_Korean_Patch_v1.01.zip"
PATCH_ZIP_SIZE = 82960189
PATCH_ZIP_URL = f"https://github.com/{REPO}/releases/download/{RELEASE_TAG}/{PATCH_ZIP_NAME}"

XDETTA_ZIP_URL = "https://github.com/jmacd/xdelta/releases/download/v3.2.2/xdelta3-3.2.2-windows-x86_64.zip"
XDETTA_ZIP_SHA256 = "d48f7651d86b78fdca397057b46601f89131f37219675df736db70af44ec3379"
XDETTA_EXE_MEMBER = "xdelta3-3.2.2-windows-x86_64/xdelta3.exe"
XDETTA_EXE_SHA256 = "732980d52f9220dc81817ccdd0c295eadce8a0048a24c2a771a73f791ac824e9"

CREATE_NO_WINDOW = 0x08000000
HASH_BLOCK = 8 * 1024 * 1024

KEY_DUMP_URL = "https://citra-emu.com/wiki/aes-keys/"
GODMODE9_URL = "https://3ds.hacks.guide/godmode9-usage.html"

KEY_HELP_TEXT = """암호화된 본편 CIA를 풀려면 콘솔에서 뽑은 키 파일이 필요합니다.
앱에는 키가 들어 있지 않고, 내려받지도 않습니다.

1. 3DS에 GodMode9이 설치되어 있어야 합니다.
   커펌이 안 되어 있으면 3ds.hacks.guide 순서를 먼저 따라 하세요.

2. Citra 키 덤프 스크립트(DumpKeys.gm9)를 내려받아
   SD 카드의 gm9/scripts 폴더에 넣습니다.
   아래 "키 덤프 스크립트 안내" 버튼으로 받을 수 있습니다.

3. 3DS에서 GodMode9을 실행하고 HOME → Scripts → DumpKeys를 고릅니다.
   최신 펌웨어(11.16/11.17) 기준이고, 끝나면 메뉴로 돌아옵니다.
   "read fail"이 뜨면 GodMode9을 다른 방법으로 실행해서 다시 해보세요.

4. SD 카드의 gm9/aes_keys.txt를 PC로 복사합니다.

5. 그 파일을 롬 파일과 같은 폴더에 keys.txt 또는 aes_keys.txt 이름으로 두거나,
   이 창을 닫고 "키 파일 (선택)" 칸에서 직접 고르면 됩니다.

필요한 줄은 slot0x3DKeyX와 common0~common5입니다. 앱이 이 둘로 normal key를
만들어서 CIA를 풉니다. aes_keys.txt에는 이 줄이 같이 들어 있습니다.
common0~common5만 있고 slot0x3DKeyX가 없으면 풀 수 없으니, 덤프를 다시 하거나
slot0x3DKeyX 줄을 같이 넣어 주세요.

SD 카드를 빼기 싫으면 3DS에 ftpd를 설치하고 PC에서 FTP로 aes_keys.txt만
받아도 됩니다. New 3DS는 무선 microSD 관리로도 접속됩니다.

남의 콘솔에서 뽑은 파일은 이 콘솔의 CIA와 안 맞을 수 있습니다.
본인 콘솔에서 뽑은 파일을 쓰세요.
"""


@dataclass(frozen=True)
class Role:
    """패치 한 벌(본편 또는 업데이트)의 고정 정보."""

    key: str
    label: str
    patch_name: str
    patch_size: int
    patch_sha256: str
    result_name: str
    result_size: int
    result_sha256: str
    source_size: int = 0  # 공식 원본 크기(변환본이 모자랄 때 채워 넣는다)
    source_profile: profiles.Profile | None = None
    patch_version: str = ""
    archive_path: Path | None = None
    source_sha256: str = ""
    target_profile: profiles.Profile | None = None


BASE = Role(
    key="base",
    label="본편",
    patch_name="YW3_Sukiyaki_KO_base_v1.01.xdelta",
    patch_size=76459565,
    patch_sha256="b1cdc077367c198f13b34fd60330fc7f8972f8f175f3a53159093cb6807623c4",
    result_name="YW3_Sukiyaki_KO_base.cci",
    result_size=3278712832,
    result_sha256="905b326fd6949054ac64dc5db9bbb6ef90510c5da824fc197dc8a8a69f0cdb34",
    source_size=3270860800,
    source_sha256=profiles.SOURCE_SHA256["base"],
    target_profile=profiles.TARGET_PROFILES["base"],
)
UPDATE = Role(
    key="update",
    label="업데이트",
    patch_name="YW3_Sukiyaki_KO_update_v1.01.xdelta",
    patch_size=12289902,
    patch_sha256="ba4c16dfa2a8e581c2969f43e3e73851e4300dbeb550a6242c9e072dac0a55b6",
    result_name="YW3_Sukiyaki_KO_update4.cia",
    result_size=196305920,
    result_sha256="d6b7c9a298790fbadff65782c82d17a183b1574d107529d054aa46a309bdb747",
    source_sha256=profiles.SOURCE_SHA256["update"],
    target_profile=profiles.TARGET_PROFILES["update"],
)
ROLES = (BASE, UPDATE)


def resolve_patch_roles(log, progress=None) -> tuple[tuple[Role, ...], str]:
    """공식 최신 배포의 패치/결과/원본 검증 정보를 한 벌로 고른다."""
    try:
        bundle, label = updates.resolve(cache_dir(), download, log, progress)
    except updates.UpdateError as exc:
        raise PatchError(str(exc)) from exc
    if bundle is None:
        log(label)
        return ROLES, label
    roles = tuple(Role(
        key=spec.key, label="본편" if spec.key == "base" else "업데이트",
        patch_name=spec.patch_name, patch_size=spec.patch_size,
        patch_sha256=spec.patch_sha256, result_name=spec.result_name,
        result_size=spec.result_size, result_sha256=spec.result_sha256,
        source_size=spec.source_size, source_profile=spec.source_profile,
        patch_version=bundle.version, archive_path=bundle.archive,
        source_sha256=spec.source_sha256, target_profile=spec.target_profile,
    ) for spec in bundle.patches)
    return roles, label

YW3_BASE_TITLE = 0x00040000001AF400
YW3_UPDATE_TITLE = 0x0004000E001AF400


@dataclass(frozen=True)
class RomInfo:
    """파일 헤더만 보고 판별한 컨테이너 종류/암호화 여부/타이틀."""

    kind: str  # "cci", "cia", "ncch", "unknown"
    encrypted: bool | None
    title_id: int | None
    note: str = ""
    seed: bool = False
    key_slots: tuple[int, ...] = ()


def _ncch_header(data: bytes, offset: int) -> tuple[bool, int, bool, bytes] | None:
    """NCCH 헤더 위치에서 (암호화 여부, 프로그램 ID, 시드 여부, 헤더)를 읽는다."""
    if offset < 0 or offset + 0x200 > len(data):
        return None
    if data[offset + 0x100: offset + 0x104] != b"NCCH":
        return None
    header = data[offset:offset + 0x200]
    flags7 = header[0x18F]
    title_id = int.from_bytes(header[0x118: 0x120], "little")
    return (not (flags7 & 0x04), title_id, bool(flags7 & 0x20), header)


def inspect_rom(path: Path) -> RomInfo:
    """3DS 컨테이너 헤더를 읽어 종류·암호화 여부를 판별한다. 키는 쓰지 않는다."""
    try:
        with path.open("rb") as handle:
            head = handle.read(0x2020 + 0x200000)
    except OSError as exc:
        return RomInfo("unknown", None, None, f"파일을 읽지 못했습니다: {exc}")
    if len(head) < 0x200:
        return RomInfo("unknown", None, None, "파일이 너무 작습니다.")

    found: tuple[bool, int, bool, bytes] | None = None
    if head[0x100:0x104] == b"NCSD":
        kind = "cci"
        media_units = int.from_bytes(head[0x120:0x124], "little")
        found = _ncch_header(head, media_units * 0x200)
    elif head[:4] == b"\x20\x20\x00\x00":
        kind = "cia"
        header_size = int.from_bytes(head[0x00:0x04], "little")
        cert_offset = (header_size + 0x3F) & ~0x3F
        ticket_offset = (cert_offset + int.from_bytes(head[0x08:0x0C], "little") + 0x3F) & ~0x3F
        tmd_offset = (ticket_offset + int.from_bytes(head[0x0C:0x10], "little") + 0x3F) & ~0x3F
        offset = (tmd_offset + int.from_bytes(head[0x10:0x14], "little") + 0x3F) & ~0x3F
        found = _ncch_header(head, offset)
        for delta in range(0x40, 0x400, 0x40):  # 정렬이 다를 때를 위한 여유 탐색
            if found:
                break
            found = _ncch_header(head, offset + delta)
        if found is None:
            # 내용이 암호화되어 있으면 NCCH가 그대로 보이지 않는다. 티켓/TMD로 판별.
            try:
                cia = converter.read_cia(path)
            except converter.ConvertError:
                pass
            else:
                return RomInfo("cia", cia.needs_key, cia.title_id)
    elif head[0x100:0x104] == b"NCCH":
        kind = "ncch"
        found = _ncch_header(head, 0)
    else:
        return RomInfo("unknown", None, None, "3DS 컨테이너 헤더(NCSD/NNCH/CIA)가 없습니다.")

    if found is None:
        return RomInfo(kind, None, None, "내부 NCCH 헤더를 찾지 못했습니다.")
    encrypted, title_id, seed, header = found
    slots: tuple[int, ...] = ()
    if encrypted:
        try:
            info = converter.ncch_crypto_info(header)
        except converter.ConvertError:
            pass
        else:
            slots = info.key_slots
    return RomInfo(kind, encrypted, title_id, seed=seed, key_slots=slots)


def describe_rom(role_key: str, info: RomInfo) -> tuple[str, str]:
    """판별 결과를 (짧은 설명, 수준)으로 바꾼다. 수준: ok/info/warn."""
    label = "본편" if role_key == "base" else "업데이트"
    kind_name = {"cci": "CCI", "cia": "CIA", "ncch": "NCCH"}.get(info.kind, info.kind.upper())

    if info.kind == "unknown":
        return f"{label}: 3DS 파일 형식을 알아보지 못했어요. 그대로 진행할 수 있어요.", "info"
    if info.kind == "cci" and info.encrypted is None:
        return (f"{label}: CCI인데 내부 NCCH 헤더를 찾지 못했어요. "
                "헤더 모양이 달라도 내용이 맞으면 진행됩니다."), "info"
    if info.title_id is not None and info.title_id not in (YW3_BASE_TITLE, YW3_UPDATE_TITLE):
        return (f"{label}: 요괴워치3 스키야키 일본판이 아니에요 "
                f"(타이틀 0x{info.title_id:016X}).\n"
                "   그래도 시작은 눌러볼 수 있어요. 내용이 다르면 패치 단계에서 거부됩니다."), "warn"
    if role_key == "base" and info.title_id == YW3_UPDATE_TITLE:
        return f"{label} 자리에 업데이트가 들어간 것 같아요. 두 칸을 서로 바꿔 보세요.", "warn"
    if role_key == "update" and info.title_id == YW3_BASE_TITLE:
        return f"{label} 자리에 본편이 들어간 것 같아요. 두 칸을 서로 바꿔 보세요.", "warn"

    if role_key == "base":
        if info.kind == "cia":
            if info.encrypted:
                return f"{label}: 암호화된 CIA예요. 암호를 풀어서 CCI로 바꾼 뒤 패치할게요.", "info"
            return f"{label}: CIA예요. CCI로 바꾼 뒤 패치할게요.", "info"
        if info.kind == "ncch":
            return f"{label}: NCCH예요. CCI로 감싼 뒤 패치할게요.", "info"
        if info.encrypted:
            seed_note = " (시드 암호라 seeddb.bin도 필요할 수 있어요)" if info.seed else ""
            return (f"{label}: 암호화된 CCI예요. NCCH 암호를 풀어서 패치할게요."
                    f"{seed_note}"), "info"
        return f"{label}: 정상 (복호화 CCI)", "ok"

    if info.kind in {"cci", "ncch"}:
        return f"{label}: CIA여야 하는데 {kind_name}이에요. 두 칸을 확인해 보세요.", "warn"
    if info.encrypted:
        return f"{label}: 암호화된 CIA예요. 암호를 푼 뒤 패치할게요.", "info"
    return f"{label}: 정상 (복호화 CIA)", "ok"


class PatchError(Exception):
    """사용자에게 그대로 보여줄 오류."""


def cache_dir() -> Path:
    override = os.environ.get(CACHE_ENV)
    if override:
        path = Path(override).expanduser()
    else:
        local = os.environ.get("LOCALAPPDATA") or str(Path.home())
        path = Path(local) / "YW3KoPatcher"
    path.mkdir(parents=True, exist_ok=True)
    return path


def human_size(value: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f}{unit}" if unit == "B" else f"{value:.1f}{unit}"
        value /= 1024
    return f"{value:.1f}TB"


def sha256_file(path: Path, progress=None) -> str:
    """파일 해시를 계산한다. progress(byte_done, byte_total)는 가끔 호출된다."""
    total = path.stat().st_size
    done = 0
    next_report = 0
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(HASH_BLOCK)
            if not block:
                break
            digest.update(block)
            done += len(block)
            if progress and done >= next_report:
                progress(done, total)
                next_report = done + 256 * 1024 * 1024
    if progress:
        progress(total, total)
    return digest.hexdigest().lower()


def download(url: str, dest: Path, progress=None) -> None:
    """URL을 받아 dest에 저장한다. 실패하면 curl.exe로 한 번 더 시도한다."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    part.unlink(missing_ok=True)
    try:
        _download_urllib(url, part, progress)
    except Exception as first:  # noqa: BLE001 - 어떤 이유든 curl로 재시도
        part.unlink(missing_ok=True)
        if not _download_curl(url, part, progress):
            raise PatchError(f"패치 파일을 내려받지 못했습니다.\n{url}\n{first}") from first
    os.replace(part, dest)


def _download_urllib(url: str, dest: Path, progress) -> None:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": f"YW3KoPatcher/{APP_VERSION}", "Accept": "*/*"},
    )
    with urllib.request.urlopen(request, timeout=60) as response, dest.open("wb") as out:
        total = int(response.headers.get("Content-Length") or 0)
        done = 0
        next_report = 0
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            out.write(block)
            done += len(block)
            if progress and done >= next_report:
                progress(done, total)
                next_report = done + 2 * 1024 * 1024
        if progress:
            progress(done, total or done)


def _download_curl(url: str, dest: Path, progress) -> bool:
    curl = shutil.which("curl.exe") or shutil.which("curl")
    if not curl:
        return False
    try:
        result = subprocess.run(
            [curl, "-L", "--fail", "--retry", "2", "-o", str(dest), url],
            capture_output=True,
            creationflags=CREATE_NO_WINDOW,
        )
    except OSError:
        return False
    return result.returncode == 0 and dest.is_file() and dest.stat().st_size > 0


def ensure_xdelta(log, progress=None) -> Path:
    """공식 xdelta3 3.2.2 바이너리를 준비한다."""
    exe = cache_dir() / "xdelta3.exe"
    if exe.is_file() and sha256_file(exe) == XDETTA_EXE_SHA256:
        return exe

    log("xdelta3 3.2.2 내려받는 중...")
    archive = cache_dir() / "xdelta3-3.2.2-windows-x86_64.zip"
    if not (archive.is_file() and sha256_file(archive) == XDETTA_ZIP_SHA256):
        archive.unlink(missing_ok=True)
        download(XDETTA_ZIP_URL, archive, progress)
        got = sha256_file(archive)
        if got != XDETTA_ZIP_SHA256:
            archive.unlink(missing_ok=True)
            raise PatchError("내려받은 xdelta3 압축 파일이 공식 배포본과 다릅니다. 다시 시도해 주세요.")

    temp_dir = Path(tempfile.mkdtemp(prefix="yw3ko_xd_", dir=str(cache_dir())))
    try:
        with zipfile.ZipFile(archive) as bundle:
            member = next((n for n in bundle.namelist() if n.endswith("xdelta3.exe")), None)
            if member is None:
                raise PatchError("xdelta3 압축 파일 안에 실행 파일이 없습니다.")
            extracted = Path(bundle.extract(member, temp_dir))
        if sha256_file(extracted) != XDETTA_EXE_SHA256:
            raise PatchError("추출한 xdelta3.exe가 공식 배포본과 다릅니다.")
        os.replace(extracted, exe)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
    archive.unlink(missing_ok=True)
    log(f"xdelta3 준비 완료: {exe}")
    return exe


def ensure_patch(role: Role, log, progress=None) -> Path:
    """역할별 xdelta 패치 파일을 준비한다. 캐시가 깨졌으면 다시 받는다."""
    target = cache_dir() / "patches" / role.patch_name
    if role.archive_path is not None:
        target = (cache_dir() / "patches" / role.patch_version
                  / role.patch_sha256 / role.patch_name)
    if target.is_file() and target.stat().st_size == role.patch_size:
        if sha256_file(target) == role.patch_sha256:
            return target
        target.unlink(missing_ok=True)

    archive = role.archive_path or (cache_dir() / PATCH_ZIP_NAME)
    for attempt in (1, 2):
        if not archive.is_file():
            if role.archive_path is not None:
                raise PatchError("선택한 패치 패키지가 없습니다. 다시 시작해 주세요.")
            log(f"한글 패치 v1.01 내려받는 중... ({human_size(PATCH_ZIP_SIZE)} 내외, 처음 한 번만)")
            download(PATCH_ZIP_URL, archive, progress)
            log("패치 압축 확인 중...")
        try:
            with zipfile.ZipFile(archive) as bundle:
                member = next((n for n in bundle.namelist() if n.endswith(role.patch_name)), None)
                if member is None:
                    raise PatchError(f"패치 압축 안에 {role.patch_name} 파일이 없습니다.")
                target.parent.mkdir(parents=True, exist_ok=True)
                temp = target.with_name(target.name + ".part")
                with bundle.open(member) as src, temp.open("wb") as dst:
                    shutil.copyfileobj(src, dst, length=1024 * 1024)
            if sha256_file(temp) == role.patch_sha256:
                os.replace(temp, target)
                log(f"{role.label} 패치 준비 완료")
                return target
            temp.unlink(missing_ok=True)
            raise PatchError("패치 파일 지문이 공식 배포본과 다릅니다.")
        except (zipfile.BadZipFile, PatchError) as exc:
            archive.unlink(missing_ok=True)
            if role.archive_path is not None:
                raise PatchError(f"한글 패치 {role.patch_version}를 검증하지 못했습니다: {exc}") from exc
            if attempt == 2:
                raise PatchError(f"{role.label} 패치를 준비하지 못했습니다.\n{exc}") from exc
    raise PatchError("패치 준비 실패")


def _check_windows(part: Path, windows, progress) -> tuple[str, list[tuple[int, int]]]:
    """패치 결과를 창 단위로 확인한다. SHA-256도 같은 읽기에서 계산한다."""
    digest = hashlib.sha256()
    bad: list[tuple[int, int]] = []
    total = sum(length for _offset, length, _checksum in windows)
    done = 0
    with part.open("rb") as handle:
        for offset, length, checksum in windows:
            data = handle.read(length)
            if len(data) != length:
                raise PatchError("패치 결과 파일이 예상보다 짧습니다.")
            digest.update(data)
            done += length
            if checksum is not None and (zlib.adler32(data) & 0xFFFFFFFF) != checksum:
                bad.append((offset, length))
            if progress and total:
                progress(80 + 20 * done / total)
    return digest.hexdigest().lower(), bad


def _explain_mismatch(role: Role, bad: list[tuple[int, int]]) -> str:
    ranges = ", ".join(f"0x{offset:X}" for offset, _length in bad[:4])
    return (
        f"{role.label} 패치 결과가 공식 원본과 달라서 저장하지 않았습니다.\n\n"
        f"크기는 맞지만 내용이 다른 구간이 있어요: {ranges}\n\n"
        "요괴워치3 스키야키 일본판 v0이 맞는지 확인해 주세요. "
        "본편 자리에 업데이트를 넣었거나, 다른 지역·버전 파일이면 이렇게 됩니다. "
        "이미 한글 패치한 파일을 원본으로 넣어도 이렇게 나옵니다.\n"
        "표시된 오프셋은 패치 창의 시작 위치입니다. 그 위치만으로 ExeFS 손상을 판단할 수 없습니다."
    )


def apply_patch(role: Role, source: Path, out_dir: Path, exe: Path, patch: Path, overwrite: bool,
                verify: bool, log, progress, status, strict: bool | None = None,
                report: dict | None = None, allow_header: bool = False,
                padded_from: int | None = None, source_verified: bool = False) -> Path:
    """xdelta3로 패치 하나를 적용하고 결과 경로를 돌려준다.

    strict=False면 변환본으로 패치한 것으로 보고 검사를 조금 풀어준다.
    xdelta의 창 지문 검사를 끄고(-n -a) 직접 창 단위로 확인한다.
    allow_header면 CCI 헤더(0x0~0x4000)가 달라도 넘어간다.
    """
    if strict is None:
        strict = verify
    tolerant = not strict
    payload_mode = tolerant and role.target_profile is not None
    if payload_mode and not verify:
        raise PatchError("호환 적용은 결과 게임 영역 검증을 끌 수 없습니다.")
    if payload_mode and not source_verified:
        issues = check_source_profile(source, role, converter.Keys(), log, status, padded_from)
        if issues:
            raise PatchError(_profile_error(role, issues))
    final = out_dir / role.result_name
    if final.exists() and not overwrite:
        raise PatchError(f"결과 파일이 이미 있습니다: {final}")

    part = final.with_name(final.name + ".part")
    part.unlink(missing_ok=True)

    status(f"{role.label}에 한글을 입히는 중...")
    log(f"[{role.label}] {source.name} → {role.result_name}")
    command = [str(exe), "-d", "-f"]
    if tolerant:
        command += ["-n", "-a"]
    command += ["-s", str(source), str(patch), str(part)]
    started = time.monotonic()
    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        creationflags=CREATE_NO_WINDOW,
    )
    try:
        last = -1
        while proc.poll() is None:
            if part.exists():
                percent = min(99.0, part.stat().st_size * 100.0 / role.result_size)
                if percent - last >= 0.4:
                    last = percent
                    progress(percent * 0.8)
                    status(f"{role.label}에 한글을 입히는 중... {percent:.0f}%")
            time.sleep(0.25)
        raw = proc.communicate()[0] or b""
        if proc.returncode != 0:
            raise PatchError(_explain_failure(role, proc.returncode, raw))
        progress(80)
        if not part.exists():
            raise PatchError("xdelta3가 출력 파일을 만들지 않았습니다.")

        if verify:
            status("결과 확인 중...")
            windows = converter.read_vcdiff_windows(patch) if tolerant and not payload_mode else []
            if payload_mode:
                if part.stat().st_size != role.result_size:
                    raise PatchError(f"{role.label} 결과 파일 크기가 공식 값과 다릅니다.")
                issues = check_source_profile(part, role, converter.Keys(), log, status, target=True)
                if issues:
                    raise PatchError(f"{role.label} 결과 게임 영역이 공식 완성본과 다릅니다.\n" + '\n'.join(issues))
                try:
                    container_verify.check_ncch_links(part, _actual_parts(part, converter.Keys()))
                    container_verify.update_cia_tmd(part, repair=True)
                    container_verify.update_cia_tmd(part, repair=False)
                except converter.ConvertError as exc:
                    raise PatchError(str(exc)) from exc
                got = sha256_file(part)
                if report is not None:
                    report["payload_verified"] = True
                log(f"[{role.label}] 완성본 게임 영역·NCCH 및 컨테이너 해시 검증 통과")
            elif windows:
                log(f"[{role.label}] 패치 창 {len(windows)}개로 결과를 확인합니다")
                if part.stat().st_size != role.result_size:
                    raise PatchError(
                        f"{role.label} 패치 결과 크기가 다릅니다.\n"
                        f"계산값: {part.stat().st_size:,}\n기대값: {role.result_size:,}\n"
                        "원본 파일이 지원 버전인지 확인해 주세요."
                    )
                if sum(length for _offset, length, _checksum in windows) != role.result_size:
                    raise PatchError(f"{role.label} 패치 파일의 창 크기 합이 결과 크기와 다릅니다.")
                got, bad = _check_windows(part, windows, progress)
                hard: list[tuple[int, int]] = []
                header_bad = padded_bad = 0
                for offset, length in bad:
                    if allow_header and offset < converter.CCI_HEADER_SIZE:
                        header_bad += 1
                    elif padded_from is not None and offset + length > padded_from:
                        padded_bad += 1
                    else:
                        hard.append((offset, length))
                if hard:
                    raise PatchError(_explain_mismatch(role, hard))
                if header_bad:
                    log(f"[{role.label}] 헤더가 원본 카트리지와 달라요(내용과 상관없는 부분)")
                if padded_bad:
                    log(f"[{role.label}] 원본에 없던 설명서/DLP 구간은 빈 채로 둡니다")
                if report is not None:
                    report["windows"] = len(windows)
                    report["windows_ok"] = not bad
            else:
                log(f"[{role.label}] SHA-256 검증 중...")
                got = sha256_file(part, lambda done, total: progress(80 + done * 20 / max(total, 1)))

            if got != role.result_sha256 and strict:
                raise PatchError(
                    f"{role.label} 결과 지문이 공식 배포본과 다릅니다.\n"
                    f"계산값: {got}\n기대값: {role.result_sha256}\n"
                    "이 파일은 설치하지 말고 원본이 지원 버전인지 확인해 주세요."
                )
            if got == role.result_sha256:
                if report is not None:
                    report["verified"] = True
                log(f"[{role.label}] SHA-256 일치")
            else:
                if report is not None:
                    report["verified"] = False
                log(f"[{role.label}] 지문이 공식 값과 달라요: {got}")
                log(f"[{role.label}] 게임 영역 검증을 통과한 호환 결과를 저장합니다." if payload_mode
                    else f"[{role.label}] 변환본의 창 단위 검사를 통과했습니다.")
        progress(100)
        os.replace(part, final)
    except Exception:
        part.unlink(missing_ok=True)
        raise
    log(f"[{role.label}] 완료: {final} ({human_size(final.stat().st_size)}, "
        f"{time.monotonic() - started:.0f}초)")
    return final


@dataclass(frozen=True)
class PreparedSource:
    """패치에 넣을 원본. 변환본이면 검사에서 봐줄 범위도 같이 알려준다."""

    path: Path
    converted: bool
    allow_header: bool = False
    padded_from: int | None = None
    compatibility: bool = False
    profile_verified: bool = False


def _packed_end(path: Path) -> int:
    """만들어 낸 CCI에서 실제 내용이 끝나는 위치. 그 뒤는 0으로 채운 구간이다."""
    try:
        partitions = converter.read_ncsd(path)
    except converter.ConvertError:
        return path.stat().st_size
    return max((item.offset + item.size for item in partitions), default=path.stat().st_size)


@dataclass(frozen=True)
class _ActualPart:
    index: int
    offset: int
    size: int
    header: bytes


_REGION_NAMES = {
    "exheader": "확장 헤더",
    "plain": "평문",
    "logo": "로고",
    "exefs": "ExeFS",
    "romfs": "RomFS",
}


def _actual_parts(path: Path, keys: converter.Keys) -> list[_ActualPart]:
    """CCI/CIA/NCCH에서 NCCH 파티션 목록과 각 헤더를 읽는다."""
    parts: list[_ActualPart] = []
    with path.open("rb") as handle:
        head = handle.read(0x400)
        if len(head) >= 0x104 and head[0x100:0x104] == b"NCSD":
            for item in converter.read_ncsd(path):
                parts.append(_ActualPart(item.index, item.offset, item.size, item.header))
            return parts

        if len(head) >= 4 and head[:4] == b"\x20\x20\x00\x00":
            info = converter.read_cia(path, keys)
            for content in info.contents:
                handle.seek(content.offset)
                header = handle.read(0x200)
                if len(header) == 0x200 and header[0x100:0x104] == b"NCCH":
                    parts.append(_ActualPart(content.index, content.offset,
                                             content.size, header))
            return parts

        if len(head) >= 0x200 and head[0x100:0x104] == b"NCCH":
            parts.append(_ActualPart(0, 0, path.stat().st_size, head[:0x200]))
    return parts


def _hash_at(handle, offset: int, size: int) -> str:
    handle.seek(offset)
    digest = hashlib.sha256()
    remaining = size
    while remaining > 0:
        block = handle.read(min(HASH_BLOCK, remaining))
        if not block:
            raise PatchError("원본을 읽는 도중에 끝났습니다. 파일이 잘렸을 수 있어요.")
        digest.update(block)
        remaining -= len(block)
    return digest.hexdigest().lower()


def check_source_profile(path: Path, role: Role, keys: converter.Keys,
                         log, status, padded_from: int | None = None,
                         target: bool = False) -> list[str]:
    """원본의 게임 영역 해시를 공식 manifest와 비교한다.

    돌려주는 목록이 비어 있으면 통과다. 문제가 있으면 어떤 영역이 왜 다른지
    사람이 읽을 수 있는 문장으로 돌려준다.
    """
    profile = role.target_profile if target else (role.source_profile or profiles.PROFILES.get(role.key))
    if profile is None:
        if role.target_profile is not None:
            return ["호환 적용에 필요한 원본 프로필이 없습니다"]
        return []
    try:
        actual_parts = _actual_parts(path, keys)
    except (converter.ConvertError, OSError) as exc:
        return [f"파일 구조를 읽지 못했습니다: {exc}"]

    by_index = {part.index: part for part in actual_parts}
    issues: list[str] = []
    if target and set(by_index) - {p.index for p in profile.parts}:
        issues.append("공식 결과에 없는 파티션이 있습니다")
    status(f"{role.label} {'결과' if target else '원본'} 게임 영역을 공식 배포본과 대조하는 중...")
    log(f"[{role.label}] 게임 영역 해시를 공식 manifest와 대조합니다")

    with path.open("rb") as handle:
        for expected in profile.parts:
            main_part = expected.index == 0
            actual = by_index.get(expected.index)
            if actual is None:
                if not main_part:
                    why = ("뒤쪽이 잘린 원본" if padded_from is not None
                           else "설명서/추가 파티션")
                    log(f"[{role.label}] 파티션 {expected.index}는 없음({why}), 건너뜁니다")
                    continue
                issues.append(f"파티션 {expected.index}가 없습니다")
                continue

            header = actual.header
            program_id = int.from_bytes(header[0x118:0x120], "little")
            product = header[0x150:0x160].rstrip(b"\x00").decode("ascii", "replace")
            soft: list[str] = []
            if program_id != expected.program_id:
                soft.append(
                    f"파티션 {expected.index}의 프로그램 ID가 다릅니다 "
                    f"(0x{program_id:016X}, 공식 0x{expected.program_id:016X})")
            if product and product != expected.product_code:
                soft.append(
                    f"파티션 {expected.index}의 제품 코드가 다릅니다 "
                    f"({product}, 공식 {expected.product_code})")

            regions = {region.name: region for region in converter.ncch_regions(header)}
            if target and set(regions) != {r.name for r in expected.regions}:
                soft.append(f"파티션 {expected.index}의 결과 영역 구성이 다릅니다")
            for wanted in expected.regions:
                name = _REGION_NAMES.get(wanted.name, wanted.name)
                found = regions.get(wanted.name)
                if found is None:
                    soft.append(f"{name} 영역이 없습니다")
                    continue
                if found.size != wanted.size:
                    soft.append(
                        f"{name} 크기가 다릅니다 "
                        f"({human_size(found.size)}, 공식 {human_size(wanted.size)})")
                    continue
                absolute = actual.offset + found.offset
                if (found.offset < 0x200 or found.offset + found.size > actual.size
                        or absolute + found.size > path.stat().st_size):
                    soft.append(f"{name} 영역이 파일/파티션 범위를 넘습니다")
                    continue
                if padded_from is not None and absolute + found.size > padded_from:
                    if main_part:
                        soft.append(f"{name} 게임 영역이 잘렸습니다")
                    log(f"[{role.label}] {name}는 잘린 뒤쪽 구간이라 건너뜁니다")
                    continue
                if issues and wanted.name == "romfs":
                    # 이미 앞쪽 영역에서 틀린 게 나왔으면 3GB를 더 읽지 않는다.
                    log(f"[{role.label}] 앞 영역이 이미 달라서 {name} 확인은 건너뜁니다")
                    continue
                log(f"[{role.label}] {name} 확인 중...")
                digest = _hash_at(handle, absolute, found.size)
                if digest != wanted.sha256:
                    soft.append(f"{name} 내용이 공식 원본과 다릅니다")

            if main_part or target:
                issues.extend(soft)
            else:
                # 설명서/DLP 같은 곁다리 파티션은 본편 패치와 상관없다.
                for line in soft:
                    log(f"[{role.label}] 참고: {line} (본편에는 영향 없음)")

    if not issues:
        log(f"[{role.label}] 게임 영역 해시가 공식 원본과 일치합니다")
    return issues


def _profile_error(role: Role, issues: list[str]) -> str:
    lines = [
        f"{role.label} 원본이 공식 배포본(v0)과 다릅니다.",
        "",
    ]
    lines += [f"- {issue}" for issue in issues]
    lines += [
        "",
        "이 상태로 패치하면 일부 구간이 원본과 섞여서 게임이 깨질 수 있어 저장하지 않았습니다.",
    ]
    if any("ExeFS" in issue for issue in issues):
        lines.append(
            "ExeFS 내용이 제작팀의 원본 해시와 일치하지 않습니다. "
            "다른 버전이거나, 변환 도구가 ExeFS를 제대로 복호화하지 못한 파일일 수 있어요.")
    lines += [
        "",
        "본편은 일본판 요괴워치3 스키야키 v0 복호화 CCI 또는 hshop 본편 CIA를, "
        "업데이트는 Update 4.0 복호화/암호화 CIA를 넣어 주세요. "
        "이미 한글 패치한 파일을 원본 칸에 넣으면 이렇게 됩니다.",
    ]
    return "\n".join(lines)


def _pad_to_size(path: Path, target_size: int, dst: Path, log) -> Path:
    """공식 카트리지보다 짧은 CCI를 target_size까지 0으로 채운 사본을 만든다.

    다른 도구로 CIA를 CCI로 바꾸면 뒤쪽 빈 구간을 잘라내는 경우가 있다.
    xdelta는 원본이 짧으면 복사할 위치를 못 찾아서 거부하므로 크기를 맞춘다.
    """
    size = path.stat().st_size
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(path, dst)
    with dst.open("r+b") as handle:
        handle.truncate(target_size)
    log(f"[본편] 원본이 {human_size(size)}라서 {human_size(target_size)}까지 0으로 채움")
    return dst


def _finish(role: Role, prepared: PreparedSource, keys: converter.Keys,
            log, status) -> PreparedSource:
    """준비한 원본이 공식 배포본과 같은 데이터인지 확인하고 넘긴다."""
    exact = bool(role.source_sha256) and sha256_file(prepared.path) == role.source_sha256
    if exact:
        log(f"[{role.label}] 원본 전체 SHA-256 일치")
        return replace(prepared, profile_verified=True)
    issues = check_source_profile(
        prepared.path, role, keys, log, status, prepared.padded_from)
    if issues:
        raise PatchError(_profile_error(role, issues))
    compatible = role.target_profile is not None
    if compatible:
        log(f"[{role.label}] 게임 영역이 동일한 호환 원본입니다. 결과 게임 영역도 검증합니다.")
    return replace(prepared, compatibility=compatible, profile_verified=True)


def prepare_source(role: Role, path: Path, work_dir: Path, keys: converter.Keys, log, status,
                   progress, check_profile: bool = True) -> PreparedSource:
    """패치에 쓸 파일을 준비한다. 필요하면 복호화·CCI 변환까지 한다."""
    info = inspect_rom(path)

    def finish(prepared: PreparedSource) -> PreparedSource:
        if not check_profile:
            return prepared
        return _finish(role, prepared, keys, log, status)

    try:
        if role.key == "base":
            if info.kind == "cia":
                status("본편 CIA를 CCI로 바꾸는 중...")
                log(f"[본편] CIA를 CCI로 변환합니다 ({human_size(path.stat().st_size)})")
                target = converter.cia_to_cci(
                    path, work_dir / "base_from_cia.cci", keys, log, progress,
                    min_size=role.source_size)
                real_end = _packed_end(target)
                padded = real_end if real_end < target.stat().st_size else None
                return finish(PreparedSource(
                    target, True, allow_header=True, padded_from=padded))
            if info.kind == "ncch":
                if info.encrypted:
                    status("본편 NCCH 암호를 푸는 중...")
                    log("[본편] NCCH를 CCI로 감싼 뒤 암호를 풉니다")
                    wrapped = converter.ncch_to_cci(
                        path, work_dir / "base_from_ncch.cci", log, progress)
                    result = converter.decrypt_cci(
                        wrapped, work_dir / "base_decrypted.cci", keys, log, progress)
                    return finish(PreparedSource(result, True, allow_header=True))
                status("본편 NCCH를 CCI로 감싸는 중...")
                log("[본편] NCCH를 CCI로 감쌉니다")
                result = converter.ncch_to_cci(path, work_dir / "base_from_ncch.cci", log, progress)
                return finish(PreparedSource(result, True, allow_header=True))
            if info.encrypted:
                status("본편 CCI 암호를 푸는 중...")
                log(f"[본편] 암호화된 CCI의 NCCH 암호를 풉니다 ({human_size(path.stat().st_size)})")
                result = converter.decrypt_cci(
                    path, work_dir / "base_decrypted.cci", keys, log, progress)
                return finish(PreparedSource(result, True, allow_header=True))
            if info.kind == "cci":
                # 밖에서 CIA를 CCI로 바꾼 파일은 헤더가 다르거나 뒤가 잘려 있을 수 있다.
                # 크기를 맞춘 뒤 창 단위로 내용을 확인하므로 그대로 진행한다.
                bad = converter.check_plaintext_cci(path)
                if bad and keys.keyx:
                    status("본편 CCI 내용이 실제로는 암호화되어 있어 다시 푸는 중...")
                    log(f"[본편] 헤더는 복호화됐다고 되어 있지만 "
                        f"{', '.join(bad)} 내용이 암호화 상태임. 키로 다시 풉니다")
                    try:
                        result = converter.decrypt_cci(
                            path, work_dir / "base_redecrypted.cci", keys, log, progress)
                        return finish(PreparedSource(result, True, allow_header=True))
                    except converter.ConvertError as exc:
                        log(f"[본편] 다시 풀지 못했습니다: {exc}")
                elif bad:
                    log(f"[본편] {', '.join(bad)} 내용이 평문으로 확인되지 않지만 "
                        "키가 없어서 다시 풀지 않습니다")
                size = path.stat().st_size
                if 0 < size < role.source_size:
                    status("본편 CCI를 원본 크기에 맞추는 중...")
                    padded = _pad_to_size(path, role.source_size,
                                          work_dir / "base_padded.cci", log)
                    return finish(PreparedSource(
                        padded, True, allow_header=True, padded_from=size))
                return finish(PreparedSource(path, True, allow_header=True))
        elif info.kind == "cia":
            if info.encrypted:
                status("업데이트 암호를 푸는 중...")
                log("[업데이트] 암호화된 CIA를 복호화합니다")
                result = converter.decrypt_cia(
                    path, work_dir / "update_decrypted.cia", keys, progress)
                return finish(PreparedSource(result, True))
            return finish(PreparedSource(path, False))
    except converter.ConvertError as exc:
        raise PatchError(str(exc)) from exc
    return PreparedSource(path, False)


def _explain_failure(role: Role, returncode: int, raw: bytes) -> str:
    text = raw.decode("utf-8", "replace").strip()
    lowered = text.lower()
    if "source" in lowered and ("mismatch" in lowered or "checksum" in lowered or "too short" in lowered):
        return (
            f"{role.label} 원본이 패치 대상 버전과 다릅니다.\n\n"
            "xdelta3 메시지:\n"
            f"{text}\n\n"
            "일본판 요괴워치3 스키야키 v0인지 확인해 주세요. "
            "본편은 복호화 CCI나 CIA(hshop 본편 포함), 업데이트는 Update 4.0 CIA여야 합니다. "
            "다른 지역판이나 다른 버전이면 크기·내용이 달라서 거부됩니다.\n"
            "다른 도구로 CCI를 만들었다면, 변환 전 원본(CIA)을 그대로 넣어 보세요."
        )
    return f"xdelta3 실행에 실패했습니다 (종료 코드 {returncode}).\n\n{text}"


class PatcherApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("800x600")
        self.minsize(720, 520)
        self._queue: queue.Queue = queue.Queue()
        self._busy = False
        self._last_out_dir: Path | None = None
        self._entries: list[ttk.Entry] = []
        self._buttons: list[ttk.Button] = []

        self.option_add("*Font", ("Malgun Gothic", 10))
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Title.TLabel", font=("Malgun Gothic", 15, "bold"))
        style.configure("Hint.TLabel", foreground="#555555")
        style.configure("Warn.TLabel", foreground="#a15c00")
        style.configure("Ok.TLabel", foreground="#1b6e33")
        style.configure("Go.TButton", font=("Malgun Gothic", 11, "bold"))

        self._build_widgets()
        self._refresh()
        self._center_window()
        self.after(80, self._drain_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------------------------------------------------------------- UI
    def _build_widgets(self) -> None:
        outer = ttk.Frame(self, padding=16)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)
        self._outer = outer

        ttk.Label(outer, text="요괴워치3 스키야키 한국어 패치", style="Title.TLabel").grid(
            row=0, column=0, sticky="w")
        ttk.Label(
            outer,
            text="본편 롬과 업데이트 파일, 두 개만 고르고 시작을 누르면 한글 롬이 만들어집니다.",
            style="Hint.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(2, 12))

        files = ttk.Frame(outer)
        files.grid(row=2, column=0, sticky="ew")
        files.columnconfigure(1, weight=1)
        self.base_var = tk.StringVar()
        self.update_var = tk.StringVar()
        self.out_var = tk.StringVar()
        self.keys_var = tk.StringVar()
        self.ready_var = tk.StringVar(value="본편 롬과 업데이트 파일을 골라 주세요.")
        self._add_file_row(files, 0, "① 본편 롬", self.base_var, self._pick_base)
        self._add_file_row(files, 1, "② 업데이트 파일", self.update_var, self._pick_update)
        self._add_file_row(files, 2, "③ 저장 위치", self.out_var, self._pick_out, folder=True)
        self._add_file_row(files, 3, "키 파일 (선택)", self.keys_var, self._pick_keys)
        self.patch_version_var = tk.StringVar(value="한글 패치: 시작 시 공식 최신 버전 확인")
        ttk.Label(files, textvariable=self.patch_version_var, style="Hint.TLabel",
                  wraplength=700).grid(row=4, column=0, columnspan=3, sticky="w", pady=(6, 0))
        self.ready_label = ttk.Label(outer, textvariable=self.ready_var, style="Hint.TLabel",
                                     wraplength=760, justify="left")
        self.ready_label.grid(row=3, column=0, sticky="w", pady=(12, 0))
        self.base_var.trace_add("write", lambda *_: self._refresh())
        self.update_var.trace_add("write", lambda *_: self._refresh())
        self.keys_var.trace_add("write", lambda *_: self._refresh())

        self.start_button = ttk.Button(
            outer, text="한글 패치 시작", style="Go.TButton", command=self._start, state="disabled")
        self.start_button.grid(row=4, column=0, sticky="ew", pady=(14, 10), ipady=8)

        self.progress = ttk.Progressbar(outer, mode="determinate", maximum=100)
        self.progress.grid(row=5, column=0, sticky="ew")
        self.status_var = tk.StringVar(value="")
        ttk.Label(outer, textvariable=self.status_var).grid(row=6, column=0, sticky="w", pady=(6, 0))

        actions = ttk.Frame(outer)
        actions.grid(row=7, column=0, sticky="w", pady=(10, 0))
        self.open_button = ttk.Button(actions, text="저장 폴더 열기", command=self._open_folder)
        self.log_button = ttk.Button(actions, text="진행 기록 보기", command=self._toggle_log)
        self.log_button.pack(side="left")
        ttk.Button(actions, text="키 파일 안내", command=self._show_key_help).pack(
            side="left", padx=(8, 0))

        self.log_frame = ttk.LabelFrame(outer, text=" 진행 기록 ", padding=(6, 4))
        self.log_frame.columnconfigure(0, weight=1)
        self.log_frame.rowconfigure(0, weight=1)
        self.log_text = tk.Text(self.log_frame, height=10, wrap="word", state="disabled",
                                relief="flat", background="#fafafa", borderwidth=1)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(self.log_frame, orient="vertical", command=self.log_text.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=scroll.set)
        ttk.Button(self.log_frame, text="패치 데이터 새로 받기", command=self._reset_cache).grid(
            row=1, column=0, sticky="w", pady=(4, 0))

        ttk.Label(
            outer,
            text="원본 파일은 그대로 두고 새 파일로 만들어요. 패치 파일은 제작팀 공식 배포처에서만 받습니다.",
            style="Hint.TLabel",
            wraplength=780,
        ).grid(row=10, column=0, sticky="w", pady=(10, 0))

    def _add_file_row(self, parent, row: int, label: str, var: tk.StringVar, command, folder=False) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=(0, 10), pady=4)
        entry = ttk.Entry(parent, textvariable=var)
        entry.grid(row=row, column=1, sticky="ew", pady=4)
        self._entries.append(entry)
        text = "변경" if folder else "찾아보기"
        button = ttk.Button(parent, text=text, command=command, width=10)
        button.grid(row=row, column=2, sticky="w", padx=(6, 0), pady=4)
        self._buttons.append(button)

    def _pick_base(self) -> None:
        path = self._ask_file("본편 롬 선택")
        if path:
            self.base_var.set(path)

    def _pick_update(self) -> None:
        path = self._ask_file("업데이트 파일 선택")
        if path:
            self.update_var.set(path)

    def _ask_file(self, title: str) -> str:
        path = filedialog.askopenfilename(
            title=title,
            filetypes=[
                ("3DS 롬/업데이트 파일", "*.cci *.cia *.3ds *.3dz *.app *.cxi"),
                ("모든 파일", "*.*"),
            ],
        )
        return path or ""

    def _refresh(self) -> None:
        """선택한 두 파일을 살펴보고 준비 상태를 한 줄로 보여준다."""
        if self._busy:
            return
        base_text = self.base_var.get().strip().strip('"')
        update_text = self.update_var.get().strip().strip('"')
        if base_text and not self.out_var.get().strip():
            self.out_var.set(str(Path(base_text).parent / "YW3_KO"))

        if not base_text and not update_text:
            self._set_ready("본편 롬과 업데이트 파일을 골라 주세요.", "Hint.TLabel", False)
            return
        if not base_text or not update_text:
            missing = "본편 롬" if not base_text else "업데이트 파일"
            self._set_ready(f"{missing}을(를) 아직 고르지 않았어요.", "Hint.TLabel", False)
            return

        base_path, update_path = Path(base_text), Path(update_text)
        missing = [name for name, path in (("본편 롬", base_path), ("업데이트 파일", update_path))
                   if not path.is_file()]
        if missing:
            self._set_ready(f"{' · '.join(missing)}을(를) 찾을 수 없어요. 다시 골라 주세요.",
                            "Warn.TLabel", False)
            return

        lines: list[str] = []
        has_warning = False
        infos: list[RomInfo] = []
        for role_key, path in (("base", base_path), ("update", update_path)):
            info = inspect_rom(path)
            infos.append(info)
            message, level = describe_rom(role_key, info)
            has_warning = has_warning or level == "warn"
            lines.append(("✓ " if level == "ok" else "") + message)

        keys = self._load_keys(base_path, update_path)
        hints: list[str] = []
        chosen = self.keys_var.get().strip().strip('"')
        if chosen and not Path(chosen).is_file():
            hints.append("· 고른 키 파일을 찾을 수 없어요. 경로를 확인해 주세요.")
        if any(info.kind == "cia" and info.encrypted for info in infos) and not keys.has_common():
            hints.append("· 암호화된 CIA를 풀려면 keys.txt의 common 키가 필요해요.")
        if keys.common_y and not (keys.keyx.get(converter.COMMON_KEYX_SLOT)
                                  or keys.keyx.get(converter.COMMON_KEYX_SLOT - 1)):
            hints.append("· keys.txt의 common0~common5는 KeyY예요. "
                         "slot0x3DKeyX도 같이 있어야 풀 수 있어요.")
        missing = sorted({slot for info in infos if info.encrypted
                          for slot in info.key_slots if slot not in keys.keyx})
        if missing:
            names = ", ".join(f"slot0x{slot:02X}KeyX" for slot in missing)
            hints.append(f"· 암호화된 CCI를 풀려면 keys.txt에 {names}가 필요해요.")
        for info in infos:
            if (info.encrypted and info.seed and info.title_id is not None
                    and info.title_id not in keys.seeds):
                hints.append(f"· 시드 암호가 걸린 CCI예요. seeddb.bin이나 "
                             f"seed_{info.title_id:016X} 줄이 필요해요.")
        if hints:
            has_warning = True
            lines.extend(hints)
            lines.append("· 키 파일은 롬과 같은 폴더에 두거나 '키 파일 (선택)' 칸에서 고르세요.")
            lines.append("· 만드는 법은 '키 파일 안내' 버튼에 있어요.")
        if has_warning:
            self._set_ready("\n".join(lines), "Warn.TLabel", True)
        else:
            self._set_ready("준비 완료. 시작을 누르면 한글 패치가 시작됩니다.\n" + "\n".join(lines),
                            "Ok.TLabel", True)

    def _set_ready(self, text: str, style: str, ready: bool) -> None:
        self.ready_var.set(text)
        self.ready_label.configure(style=style)
        if not self._busy:
            self.start_button.configure(state="normal" if ready else "disabled")

    def _toggle_log(self) -> None:
        if self.log_frame.winfo_manager():
            self.log_frame.grid_remove()
            self.log_button.configure(text="진행 기록 보기")
            self._outer.rowconfigure(9, weight=0)
            self.geometry("800x600")
        else:
            self._outer.rowconfigure(9, weight=1)
            self.log_frame.grid(row=9, column=0, sticky="nsew", pady=(12, 0))
            self.log_button.configure(text="진행 기록 숨기기")
            self.geometry("800x820")

    def _center_window(self) -> None:
        width, height = 800, 600
        x = max(0, (self.winfo_screenwidth() - width) // 2)
        y = max(0, (self.winfo_screenheight() - height) // 3)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def _pick_out(self) -> None:
        initial = self.out_var.get() or str(self._last_out_dir or Path.home())
        path = filedialog.askdirectory(title="결과를 저장할 폴더 선택", initialdir=initial)
        if path:
            self.out_var.set(path)

    def _pick_keys(self) -> None:
        path = filedialog.askopenfilename(
            title="키 파일 선택 (keys.txt / aes_keys.txt)",
            filetypes=[("키 파일", "*.txt *.bin"), ("모든 파일", "*.*")],
        )
        if path:
            self.keys_var.set(path)

    def _load_keys(self, base: Path, update: Path) -> converter.Keys:
        """화면에서 고른 키 파일을 먼저 읽고, 없으면 롬 옆에서 찾는다."""
        extra: list[Path] = []
        text = self.keys_var.get().strip().strip('"')
        if text and Path(text).is_file():
            extra.append(Path(text))
        return converter.load_keys([base.parent, update.parent], extra)

    def _show_key_help(self) -> None:
        window = tk.Toplevel(self)
        window.title("키 파일(keys.txt) 만드는 법")
        window.geometry("740x600")
        window.transient(self)
        frame = ttk.Frame(window, padding=14)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        text = tk.Text(frame, wrap="word", relief="flat", background="#fafafa",
                       borderwidth=1, padx=10, pady=8)
        text.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        text.configure(yscrollcommand=scroll.set)
        text.insert("1.0", KEY_HELP_TEXT)
        text.configure(state="disabled")
        buttons = ttk.Frame(frame)
        buttons.grid(row=1, column=0, columnspan=2, sticky="w", pady=(10, 0))
        ttk.Button(buttons, text="키 덤프 스크립트 안내",
                   command=lambda: webbrowser.open(KEY_DUMP_URL)).pack(side="left")
        ttk.Button(buttons, text="GodMode9 설치 안내",
                   command=lambda: webbrowser.open(GODMODE9_URL)).pack(side="left", padx=(8, 0))
        ttk.Button(buttons, text="닫기", command=window.destroy).pack(side="left", padx=(8, 0))

    # ------------------------------------------------------------ control
    def _start(self) -> None:
        if self._busy:
            return
        base = Path(self.base_var.get().strip().strip('"'))
        update = Path(self.update_var.get().strip().strip('"'))

        for path, what in ((base, "본편 롬"), (update, "업데이트 파일")):
            if not path.is_file():
                self._set_ready(f"{what}을(를) 찾을 수 없어요. 다시 골라 주세요.", "Warn.TLabel", False)
                return
        if base.resolve() == update.resolve():
            self._set_ready("본편과 업데이트에 같은 파일이 들어 있어요. 서로 다른 두 파일을 골라 주세요.",
                            "Warn.TLabel", False)
            return

        out_text = self.out_var.get().strip().strip('"') or str(base.parent / "YW3_KO")
        out_dir = Path(out_text)
        self.out_var.set(out_text)
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self._set_ready(f"저장 위치를 만들 수 없어요: {exc}", "Warn.TLabel", False)
            return

        needed = sum(role.result_size for role in ROLES) + 256 * 1024 * 1024
        for path in (base, update):
            info = inspect_rom(path)
            if info.kind == "cia" or (path == base and info.kind == "ncch"):
                needed += path.stat().st_size  # 변환/복호화 임시 파일
            elif path == base and info.kind == "cci" and (
                    info.encrypted or path.stat().st_size < BASE.source_size):
                needed += BASE.source_size  # 복호화하거나 크기를 채운 CCI 임시 파일
        free = shutil.disk_usage(out_dir).free
        if free < needed:
            self._log(f"저장 공간이 부족할 수 있습니다. 필요 약 {human_size(needed)}, 남은 공간 {human_size(free)}")

        keys = self._load_keys(base, update)
        self._last_out_dir = out_dir
        self._set_busy(True)
        self.progress["value"] = 0
        self.status_var.set("시작하는 중...")
        self.open_button.pack_forget()
        self._clear_log()
        self._log(f"본편: {base}")
        self._log(f"업데이트: {update}")
        self._log(f"저장 위치: {out_dir}")
        for line in keys.summary():
            self._log(line)
        for role_key, path in (("base", base), ("update", update)):
            self._log(describe_rom(role_key, inspect_rom(path))[0])
        threading.Thread(target=self._worker, args=(base, update, out_dir, keys), daemon=True).start()

    def _worker(self, base: Path, update: Path, out_dir: Path, keys: converter.Keys) -> None:
        work_dir = out_dir / "_YW3_KO_work"
        try:
            self._emit("patch_version", "한글 패치: 공식 최신 버전 확인 중...")
            self._status("공식 최신 한글 패치 확인 중...")
            prep_value = 0.0

            def on_prep(done: int, total: int) -> None:
                nonlocal prep_value
                if total > 0:
                    prep_value = max(prep_value, 9.0 * min(1.0, done / total))
                    self._progress(prep_value)

            roles, version_label = resolve_patch_roles(self._log, on_prep)
            self._emit("patch_version", version_label)
            exe = ensure_xdelta(self._log, on_prep)
            patches = {role.key: ensure_patch(role, self._log, on_prep) for role in roles}
            work_dir.mkdir(parents=True, exist_ok=True)

            plans = (
                (roles[0], base, 9.0, 28.0, 28.0, 60.0),
                (roles[1], update, 60.0, 70.0, 70.0, 96.0),
            )
            results: list[Path] = []
            notes: list[str] = []
            for role, source, prep_low, prep_high, low, high in plans:
                prepared = prepare_source(
                    role, source, work_dir, keys, self._log, self._status,
                    lambda percent, a=prep_low, b=prep_high: self._progress(a + (b - a) * percent / 100.0),
                )
                report: dict = {}
                results.append(apply_patch(
                    role, prepared.path, out_dir, exe, patches[role.key], True, True,
                    self._log,
                    lambda percent, a=low, b=high: self._progress(a + (b - a) * percent / 100.0),
                    self._status,
                    strict=not (prepared.converted or prepared.compatibility),
                    source_verified=prepared.profile_verified,
                    report=report,
                    allow_header=prepared.allow_header,
                    padded_from=prepared.padded_from,
                ))
                if prepared.converted:
                    prepared.path.unlink(missing_ok=True)
                if report.get("payload_verified"):
                    notes.append(f"{role.label}: 공식 완성본의 게임 영역과 내부 해시를 확인했습니다.")
                elif report.get("verified") is False:
                    notes.append(
                        f"{role.label}: 원본이 공식 CCI가 아니라 헤더가 조금 달라요. "
                        "게임 내용은 확인했으니 그대로 쓰면 됩니다.")
            self._status("마무리 확인 중...")
            self._emit("done", True, results, out_dir, notes)
        except PatchError as exc:
            self._emit("patch_version", "한글 패치 준비 실패 · 진행 기록을 확인해 주세요")
            self._log(f"오류: {exc}")
            self._emit("done", False, str(exc))
        except Exception as exc:  # noqa: BLE001 - UI로 넘길 마지막 안전망
            self._log(f"예기치 않은 오류: {exc!r}")
            self._emit("done", False, f"예기치 않은 오류가 났습니다.\n{exc}")
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)
            self._emit("busy", False)

    def _reset_cache(self) -> None:
        if self._busy:
            return
        if not messagebox.askyesno(
            "패치 데이터 새로 받기",
            "저장된 패치 파일과 xdelta3를 지우고 다음 실행 때 다시 받습니다.\n계속할까요?",
        ):
            return
        folder = cache_dir()
        shutil.rmtree(folder, ignore_errors=True)
        self._log(f"캐시를 비웠습니다: {folder}")

    # -------------------------------------------------------------- utils
    def _emit(self, *event) -> None:
        self._queue.put(event)

    def _drain_queue(self) -> None:
        try:
            while True:
                event = self._queue.get_nowait()
                kind = event[0]
                if kind == "log":
                    self._append_log(event[1])
                elif kind == "status":
                    self.status_var.set(event[1])
                elif kind == "patch_version":
                    self.patch_version_var.set(event[1])
                elif kind == "progress" and event[1] is not None:
                    self.progress["value"] = max(0.0, min(100.0, event[1]))
                elif kind == "done":
                    ok = event[1]
                    if ok:
                        results, out_dir = event[2], event[3]
                        notes = event[4] if len(event) > 4 else []
                        self.progress["value"] = 100
                        self.status_var.set(f"저장 위치: {out_dir}")
                        text = (
                            "완료! 한글 패치된 롬이 만들어졌어요.\n"
                            + "\n".join(f"· {path.name} ({human_size(path.stat().st_size)})"
                                        for path in results)
                        )
                        self._set_ready(text + ("\n" + "\n".join(notes) if notes else ""),
                                        "Warn.TLabel" if notes else "Ok.TLabel", True)
                        self.open_button.pack(side="left", padx=(0, 8), before=self.log_button)
                        self._open_folder()
                    else:
                        self.status_var.set("실패했어요. 진행 기록을 확인해 주세요.")
                        self._show_log()
                        messagebox.showerror("한글 패치 실패", event[2])
                elif kind == "busy":
                    self._set_busy(event[1])
        except queue.Empty:
            pass
        self.after(80, self._drain_queue)

    def _log(self, message: str) -> None:
        self._emit("log", message)

    def _status(self, message: str) -> None:
        self._emit("status", message)

    def _progress(self, value: float) -> None:
        self._emit("progress", value)

    def _append_log(self, message: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _open_folder(self) -> None:
        folder = self.out_var.get().strip()
        if folder and Path(folder).is_dir():
            os.startfile(folder)  # type: ignore[attr-defined]

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        state = "disabled" if busy else "normal"
        for widget in (*self._entries, *self._buttons, self.log_button):
            widget.configure(state=state)
        if busy:
            self.start_button.configure(state="disabled", text="한글 패치하는 중...")
        else:
            self.start_button.configure(state="normal", text="한글 패치 시작")

    def _show_log(self) -> None:
        if not self.log_frame.winfo_manager():
            self._toggle_log()

    def _on_close(self) -> None:
        if self._busy and not messagebox.askyesno("종료", "작업이 진행 중입니다. 정말 종료할까요?"):
            return
        self.destroy()


def enable_dpi_awareness() -> None:
    if sys.platform != "win32":
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:  # noqa: BLE001 - 구형 윈도우
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:  # noqa: BLE001
            pass


def run_selftest(log_path: Path) -> int:
    """배포용 exe에서도 다운로드·압축 해제·지문 확인이 되는지 점검한다."""
    lines: list[str] = []

    def log(message: str) -> None:
        lines.append(str(message))

    ok = True
    try:
        if not converter.roundtrip_check(Path(".")):
            ok = False
            log("AES-CBC 자체 점검 실패")
        else:
            log("AES-CBC 자체 점검 통과 (변환/복호화 사용 가능)")
        exe = ensure_xdelta(log)
        if sha256_file(exe) != XDETTA_EXE_SHA256:
            ok = False
            log("xdelta3 지문 불일치")
        roles, label = resolve_patch_roles(log)
        log(label)
        for role in roles:
            patch = ensure_patch(role, log)
            matched = sha256_file(patch) == role.patch_sha256
            ok = ok and matched
            log(f"{role.key} 패치: {'일치' if matched else '불일치'} ({human_size(patch.stat().st_size)})")
    except Exception as exc:  # noqa: BLE001
        ok = False
        log(f"오류: {exc!r}")
    lines.append("결과: " + ("통과" if ok else "실패"))
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError:
        pass
    return 0 if ok else 1


def main() -> int:
    if "--selftest" in sys.argv:
        index = sys.argv.index("--selftest")
        target = (
            Path(sys.argv[index + 1])
            if len(sys.argv) > index + 1
            else cache_dir() / "selftest.log"
        )
        return run_selftest(target)
    enable_dpi_awareness()
    try:
        app = PatcherApp()
        app.mainloop()
        return 0
    except Exception as exc:  # noqa: BLE001 - 창 없는 exe에서 조용히 죽지 않게
        import traceback

        try:
            log_path = cache_dir() / "crash.log"
            log_path.write_text(traceback.format_exc(), encoding="utf-8")
        except Exception:  # noqa: BLE001
            log_path = None
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror(
                "프로그램 오류",
                f"프로그램을 시작하지 못했습니다.\n{exc}\n\n"
                + (f"자세한 내용: {log_path}" if log_path else ""),
            )
            root.destroy()
        except Exception:  # noqa: BLE001
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
