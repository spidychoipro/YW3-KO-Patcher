"""3DS 컨테이너 변환/복호화.

이 모듈은 세 가지 일을 한다.

- 암호화된 CIA의 내용을 복호화한다 (티켓의 타이틀 키 사용).
- CIA(또는 NCCH)를 CCI로 다시 묶는다.
- 파일 헤더를 읽어 컨테이너 구조를 파악한다.

AES-CBC는 Windows CNG(bcrypt.dll)를 그대로 쓴다. 외부 패키지가 없어도 되고
exe에 같이 들어간다. 키는 앱에 넣지 않고 사용자가 둔 keys.txt에서만 읽는다.

참고한 문서: 3dbrew.org (CIA, Ticket, TMD, NCCH, NCSD)
"""

from __future__ import annotations

import ctypes
import os
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from ctypes import wintypes

MEDIA_UNIT = 0x200
CCI_HEADER_SIZE = 0x4000  # NCSD 헤더 + 카드 정보 헤더 영역
CHUNK = 8 * 1024 * 1024

SIG_SIZES = {
    0x00010000: 0x200,
    0x00010001: 0x100,
    0x00010002: 0x3C,
    0x00010003: 0x200,
    0x00010004: 0x100,
    0x00010005: 0x3C,
}

KEYS_ENV = "YW3KO_KEYS"
KEYS_NAMES = ("keys.txt", "aes_keys.txt")


class ConvertError(Exception):
    """사용자에게 그대로 보여줄 변환 오류."""


# --------------------------------------------------------------------- AES


_bcrypt = ctypes.WinDLL("bcrypt.dll", use_last_error=True)
_bcrypt.BCryptOpenAlgorithmProvider.argtypes = [
    ctypes.POINTER(wintypes.HANDLE), ctypes.c_wchar_p, ctypes.c_wchar_p, wintypes.ULONG]
_bcrypt.BCryptOpenAlgorithmProvider.restype = ctypes.c_long
_bcrypt.BCryptCloseAlgorithmProvider.argtypes = [wintypes.HANDLE, wintypes.ULONG]
_bcrypt.BCryptCloseAlgorithmProvider.restype = ctypes.c_long
_bcrypt.BCryptSetProperty.argtypes = [
    wintypes.HANDLE, ctypes.c_wchar_p, ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG]
_bcrypt.BCryptSetProperty.restype = ctypes.c_long
_bcrypt.BCryptGenerateSymmetricKey.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(wintypes.HANDLE), ctypes.c_void_p, wintypes.ULONG,
    ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG]
_bcrypt.BCryptGenerateSymmetricKey.restype = ctypes.c_long
_bcrypt.BCryptDestroyKey.argtypes = [wintypes.HANDLE]
_bcrypt.BCryptDestroyKey.restype = ctypes.c_long
_bcrypt.BCryptDecrypt.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, wintypes.ULONG, ctypes.c_void_p, ctypes.c_void_p,
    wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG), wintypes.ULONG]
_bcrypt.BCryptDecrypt.restype = ctypes.c_long
_bcrypt.BCryptEncrypt.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, wintypes.ULONG, ctypes.c_void_p, ctypes.c_void_p,
    wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG), wintypes.ULONG]
_bcrypt.BCryptEncrypt.restype = ctypes.c_long


def _ntstatus(status: int) -> None:
    if status != 0:
        raise ConvertError(f"Windows 암호화 기능을 쓰지 못했습니다 (0x{status & 0xFFFFFFFF:08X}).")


class AesCbc:
    """AES-CBC 한 벌. with 문으로 열고 닫는다."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 16:
            raise ConvertError("AES 키 길이가 16바이트가 아닙니다.")
        self._alg = wintypes.HANDLE()
        self._key = wintypes.HANDLE()
        _ntstatus(_bcrypt.BCryptOpenAlgorithmProvider(
            ctypes.byref(self._alg), "AES", None, 0))
        try:
            mode = "ChainingModeCBC".encode("utf-16-le") + b"\x00\x00"
            _ntstatus(_bcrypt.BCryptSetProperty(
                self._alg, "ChainingMode", mode, len(mode), 0))
            key_buf = ctypes.create_string_buffer(key, len(key))
            _ntstatus(_bcrypt.BCryptGenerateSymmetricKey(
                self._alg, ctypes.byref(self._key), None, 0, key_buf, len(key), 0))
        except Exception:
            _bcrypt.BCryptCloseAlgorithmProvider(self._alg, 0)
            raise

    def close(self) -> None:
        if self._key:
            _bcrypt.BCryptDestroyKey(self._key)
            self._key = wintypes.HANDLE()
        if self._alg:
            _bcrypt.BCryptCloseAlgorithmProvider(self._alg, 0)
            self._alg = wintypes.HANDLE()

    def __enter__(self) -> "AesCbc":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def _run(self, data: bytes, iv: bytes, encrypt: bool) -> bytes:
        if len(data) % 16:
            raise ConvertError("암호화 데이터 길이가 16의 배수가 아닙니다.")
        if not data:
            return b""
        out = ctypes.create_string_buffer(len(data))
        written = wintypes.ULONG(0)
        iv_buf = ctypes.create_string_buffer(iv, 16)
        func = _bcrypt.BCryptEncrypt if encrypt else _bcrypt.BCryptDecrypt
        _ntstatus(func(self._key, data, len(data), None, iv_buf, 16,
                       out, len(data), ctypes.byref(written), 0))
        return out.raw[:written.value]

    def decrypt(self, data: bytes, iv: bytes) -> bytes:
        return self._run(data, iv, encrypt=False)

    def encrypt(self, data: bytes, iv: bytes) -> bytes:
        return self._run(data, iv, encrypt=True)


def cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    with AesCbc(key) as cipher:
        return cipher.decrypt(data, iv)


def cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    with AesCbc(key) as cipher:
        return cipher.encrypt(data, iv)


# -------------------------------------------------------------------- keys


@dataclass(frozen=True)
class Keys:
    common: bytes | None = None
    path: Path | None = None


def load_keys_file(path: Path) -> Keys:
    """keys.txt에서 common 키를 찾는다. 'common: <32 hex>' 형식을 권장한다."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return Keys()
    bare: bytes | None = None
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        name, value = "", line
        match = re.match(r"^([^=:]+)[=:](.+)$", line)
        if match:
            name, value = match.group(1).strip().lower(), match.group(2).strip()
        value = value.replace(" ", "").replace("-", "")
        if len(value) != 32 or any(c not in "0123456789abcdefABCDEF" for c in value):
            continue
        if "common" in name:
            return Keys(bytes.fromhex(value), path)
        if not name and bare is None:
            bare = bytes.fromhex(value)
    if bare is not None:
        return Keys(bare, path)
    return Keys(None, path)


def find_keys(search_dirs: list[Path]) -> Keys:
    """키 파일을 찾아 common 키를 읽는다. 없으면 빈 Keys."""
    candidates: list[Path] = []
    override = os.environ.get(KEYS_ENV)
    if override:
        candidates.append(Path(override))
    for folder in search_dirs:
        for name in KEYS_NAMES:
            candidates.append(folder / name)
    for path in candidates:
        if path.is_file():
            keys = load_keys_file(path)
            if keys.common:
                return keys
    return Keys()


# ------------------------------------------------------------- CIA parsing


@dataclass
class CiaContent:
    index: int
    content_id: int
    size: int
    offset: int
    encrypted: bool


@dataclass
class CiaInfo:
    header_size: int
    title_id: int
    title_version: int
    ticket: bytes
    tmd: bytes
    contents: list[CiaContent] = field(default_factory=list)
    content_area: int = 0
    title_key: bytes | None = None
    needs_key: bool = False

    @property
    def program(self) -> CiaContent | None:
        for content in self.contents:
            if content.index == 0:
                return content
        return self.contents[0] if self.contents else None


def _sig_data_size(sig_type: int) -> int:
    size = 4 + SIG_SIZES.get(sig_type, 0x100)
    return (size + 0x3F) & ~0x3F


def _align(value: int, align: int) -> int:
    return (value + align - 1) // align * align


def decrypt_title_key(encrypted: bytes, title_id: int, common_key: bytes) -> bytes:
    iv = title_id.to_bytes(8, "big") + b"\x00" * 8
    return cbc_decrypt(common_key, iv, encrypted[:16])[:16]


def read_cia(path: Path, keys: Keys | None = None) -> CiaInfo:
    """CIA 헤더/티켓/TMD를 읽는다. 암호화 여부와 타이틀 키까지 계산한다."""
    with path.open("rb") as handle:
        head = handle.read(0x2020)
        if len(head) < 0x2020 or head[:4] != b"\x20\x20\x00\x00":
            raise ConvertError("CIA 헤더가 아닙니다.")
        header_size = int.from_bytes(head[0x00:0x04], "little")
        cert_size = int.from_bytes(head[0x08:0x0C], "little")
        ticket_size = int.from_bytes(head[0x0C:0x10], "little")
        tmd_size = int.from_bytes(head[0x10:0x14], "little")

        ticket_offset = header_size + cert_size
        tmd_offset = ticket_offset + ticket_size
        handle.seek(ticket_offset)
        ticket = handle.read(ticket_size)
        handle.seek(tmd_offset)
        tmd = handle.read(tmd_size)

    if len(ticket) < 0x250 or len(tmd) < 0xC4:
        raise ConvertError("CIA 안의 티켓이나 TMD가 잘렸습니다.")

    tmd_sig = _sig_data_size(int.from_bytes(tmd[0:4], "big"))
    tmd_header = tmd[tmd_sig:]
    title_id = int.from_bytes(tmd_header[0x4C:0x54], "big")
    title_version = int.from_bytes(tmd_header[0x9C:0x9E], "big")
    content_count = int.from_bytes(tmd_header[0x9E:0xA0], "big")

    records = tmd[tmd_sig + 0xC4 + 0x24 * 64:]
    content_area = _align(tmd_offset + tmd_size, 0x40)
    contents: list[CiaContent] = []
    offset = content_area
    for index in range(content_count):
        record = records[index * 0x30:(index + 1) * 0x30]
        if len(record) != 0x30:
            raise ConvertError("TMD 내용 목록이 잘렸습니다.")
        content_id = int.from_bytes(record[0x00:0x04], "big")
        content_index = int.from_bytes(record[0x04:0x06], "big")
        content_type = int.from_bytes(record[0x06:0x08], "big")
        size = int.from_bytes(record[0x08:0x10], "big")
        contents.append(CiaContent(content_index, content_id, size, offset, bool(content_type & 1)))
        offset = _align(offset + size, 0x40)
    contents.sort(key=lambda item: item.offset)

    ticket_sig = _sig_data_size(int.from_bytes(ticket[0:4], "big"))
    ticket_data = ticket[ticket_sig:]
    encrypted_key = ticket_data[0x7F:0x8F]
    ticket_title = int.from_bytes(ticket_data[0x9C:0xA4], "big")

    title_key: bytes | None = None
    needs_key = any(item.encrypted for item in contents)
    if needs_key and keys is not None and keys.common:
        try:
            title_key = decrypt_title_key(encrypted_key, ticket_title, keys.common)
        except ConvertError:
            title_key = None
    return CiaInfo(
        header_size=header_size,
        title_id=title_id,
        title_version=title_version,
        ticket=ticket,
        tmd=tmd,
        contents=contents,
        content_area=content_area,
        title_key=title_key,
        needs_key=needs_key,
    )


def _content_iv(index: int) -> bytes:
    return index.to_bytes(2, "big") + b"\x00" * 14


# ------------------------------------------------------------ stream utils


def _decrypt_copy(src, dst, size: int, cipher: AesCbc, iv: bytes, progress=None,
                  report_from: float = 0.0, report_to: float = 100.0,
                  done_base: int = 0, total: int | None = None) -> None:
    """src에서 size만큼 읽어 CBC 복호화하며 dst에 쓴다. IV는 알아서 이어진다."""
    done = 0
    total = total or size
    while done < size:
        block = src.read(min(CHUNK, size - done))
        if not block:
            raise ConvertError("파일을 읽는 도중에 끝났습니다. 파일이 손상됐을 수 있어요.")
        if len(block) % 16:
            raise ConvertError("암호화 구간 길이가 16의 배수가 아닙니다.")
        dst.write(cipher.decrypt(block, iv))
        iv = block[-16:]
        done += len(block)
        if progress:
            progress(report_from + (report_to - report_from) * (done_base + done) / max(total, 1))


def _decrypt_in_place(handle, offset: int, size: int, cipher: AesCbc, iv: bytes,
                      progress=None, report_from: float = 0.0, report_to: float = 100.0) -> None:
    """열린 파일의 한 구간을 제자리에서 복호화한다."""
    done = 0
    while done < size:
        block_size = min(CHUNK, size - done)
        handle.seek(offset + done)
        block = handle.read(block_size)
        if len(block) != block_size:
            raise ConvertError("파일을 읽는 도중에 끝났습니다. 파일이 손상됐을 수 있어요.")
        if block_size % 16:
            raise ConvertError("암호화 구간 길이가 16의 배수가 아닙니다.")
        handle.seek(offset + done)
        handle.write(cipher.decrypt(block, iv))
        iv = block[-16:]
        done += block_size
        if progress:
            progress(report_from + (report_to - report_from) * done / max(size, 1))


# ------------------------------------------------------- CIA -> decrypted


def decrypt_cia(src: Path, dst: Path, keys: Keys, progress=None) -> Path:
    """CIA를 내용만 복호화한 CIA로 다시 저장한다. 구조(티켓/TMD)는 그대로 둔다."""
    info = read_cia(src, keys)
    if not info.needs_key:
        raise ConvertError("이 CIA는 이미 복호화되어 있습니다.")
    if not info.title_key:
        raise ConvertError(_need_key_message())

    dst.parent.mkdir(parents=True, exist_ok=True)
    part = dst.with_name(dst.name + ".part")
    part.unlink(missing_ok=True)
    with src.open("rb") as source, part.open("w+b") as target:
        while True:
            block = source.read(CHUNK)
            if not block:
                break
            target.write(block)
        target.flush()
        with AesCbc(info.title_key) as cipher:
            for done, content in enumerate(info.contents):
                if not content.encrypted:
                    continue
                _decrypt_in_place(target, content.offset, content.size, cipher,
                                  _content_iv(content.index), progress,
                                  done * 100.0 / len(info.contents),
                                  (done + 1) * 100.0 / len(info.contents))
    os.replace(part, dst)
    return dst


# --------------------------------------------------------- CIA/NCCH -> CCI


def _build_ncsd_header(ncch_head: bytes, ncch_size: int, total_size: int) -> bytes:
    """NCCH 헤더를 보고 NCSD(CCI) 헤더 0x4000바이트를 만든다."""
    header = bytearray(CCI_HEADER_SIZE)
    header[0x100:0x104] = b"NCSD"
    header[0x104:0x108] = (total_size // MEDIA_UNIT).to_bytes(4, "little")
    header[0x108:0x110] = ncch_head[0x108:0x110]  # 미디어 ID 자리에 파티션 ID(타이틀 ID)
    header[0x110:0x118] = (0).to_bytes(8, "big")  # 파티션 FS 종류: 일반
    header[0x118:0x120] = b"\x00" * 8  # 파티션별 암호화 종류: 전부 없음
    start_unit = CCI_HEADER_SIZE // MEDIA_UNIT
    size_unit = _align(ncch_size, MEDIA_UNIT) // MEDIA_UNIT
    header[0x120:0x124] = start_unit.to_bytes(4, "little")
    header[0x124:0x128] = size_unit.to_bytes(4, "little")
    header[0x160:0x180] = ncch_head[0x160:0x180]  # 확장 헤더 해시
    header[0x180:0x184] = (0).to_bytes(4, "little")  # 추가 헤더 없음
    header[0x184:0x188] = (0).to_bytes(4, "little")  # 섹터 0 오프셋
    header[0x18C] = 1  # 미디어 플랫폼: CTR
    header[0x18D] = 1  # 미디어 종류: 카드1
    header[0x190:0x198] = ncch_head[0x118:0x120]  # 파티션 0 타이틀 ID
    header[0x310:0x312] = ncch_head[0x112:0x114]  # 카드 정보 헤더의 타이틀 버전
    return bytes(header)


def _patch_nocrypto(ncch_head: bytes) -> bytes:
    """복호화한 내용이니 NCCH 헤더의 NoCrypto 플래그를 켠다."""
    fixed = bytearray(ncch_head)
    fixed[0x18F] |= 0x04
    return bytes(fixed)


def cia_to_cci(src: Path, dst: Path, keys: Keys, log, progress=None) -> Path:
    """CIA의 본편 내용을 꺼내 CCI로 다시 묶는다. 암호화되어 있으면 풀면서 쓴다."""
    info = read_cia(src, keys)
    program = info.program
    if program is None:
        raise ConvertError("CIA 안에 본편 내용이 없습니다.")
    if program.encrypted and not info.title_key:
        raise ConvertError(_need_key_message())

    with src.open("rb") as source:
        source.seek(program.offset)
        raw_head = source.read(0x400)
        if len(raw_head) < 0x400:
            raise ConvertError("CIA 내용이 잘렸습니다.")
        iv = _content_iv(program.index)
        plain_head = (cbc_decrypt(info.title_key, iv, raw_head)
                      if program.encrypted else raw_head)
        if plain_head[0x100:0x104] != b"NCCH":
            raise ConvertError("CIA 안에서 NCCH 헤더를 찾지 못했습니다.")

        declared = int.from_bytes(plain_head[0x104:0x108], "little") * MEDIA_UNIT
        ncch_size = max(declared, _align(program.size, MEDIA_UNIT))
        total = CCI_HEADER_SIZE + ncch_size
        header = _build_ncsd_header(_patch_nocrypto(plain_head), ncch_size, total)

        dst.parent.mkdir(parents=True, exist_ok=True)
        part = dst.with_name(dst.name + ".part")
        part.unlink(missing_ok=True)
        with part.open("wb") as target:
            target.write(header)
            target.write(_patch_nocrypto(plain_head))
            copied = len(raw_head)
            remaining = max(program.size - copied, 0)
            if program.encrypted:
                with AesCbc(info.title_key) as cipher:
                    _decrypt_copy(source, target, remaining, cipher, raw_head[-16:],
                                  progress, 0.0, 100.0, copied, ncch_size)
            else:
                while remaining > 0:
                    block = source.read(min(CHUNK, remaining))
                    if not block:
                        break
                    target.write(block)
                    remaining -= len(block)
                    copied += len(block)
                    if progress:
                        progress(100.0 * copied / ncch_size)
            written = target.tell() - CCI_HEADER_SIZE
            missing = ncch_size - written
            while missing > 0:
                step = min(CHUNK, missing)
                target.write(b"\x00" * step)
                missing -= step
        os.replace(part, dst)
    log(f"CCI 변환 완료: {dst.name} ({_size_text(dst.stat().st_size)})")
    return dst


def ncch_to_cci(src: Path, dst: Path, log, progress=None) -> Path:
    """떠 있는 NCCH(.app/.cxi) 하나를 CCI로 감싼다."""
    with src.open("rb") as source:
        head = source.read(0x400)
        if len(head) < 0x400 or head[0x100:0x104] != b"NCCH":
            raise ConvertError("NCCH 헤더가 아닙니다.")
        ncch_size = max(int.from_bytes(head[0x104:0x108], "little") * MEDIA_UNIT,
                        _align(src.stat().st_size, MEDIA_UNIT))
        total = CCI_HEADER_SIZE + ncch_size
        header = _build_ncsd_header(_patch_nocrypto(head), ncch_size, total)
        dst.parent.mkdir(parents=True, exist_ok=True)
        part = dst.with_name(dst.name + ".part")
        part.unlink(missing_ok=True)
        with part.open("wb") as target:
            target.write(header)
            target.write(_patch_nocrypto(head))
            remaining = src.stat().st_size - len(head)
            done = len(head)
            while remaining > 0:
                block = source.read(min(CHUNK, remaining))
                if not block:
                    break
                target.write(block)
                remaining -= len(block)
                done += len(block)
                if progress:
                    progress(min(99.0, 100.0 * done / max(src.stat().st_size, 1)))
            missing = total - target.tell()
            written = 0
            while written < missing:
                step = min(CHUNK, missing - written)
                target.write(b"\x00" * step)
                written += step
    os.replace(part, dst)
    log(f"CCI 변환 완료: {dst.name} ({_size_text(dst.stat().st_size)})")
    return dst


def _need_key_message() -> str:
    return (
        "이 파일은 암호화되어 있어서 3DS 공통 키가 필요합니다.\n\n"
        "keys.txt 파일을 만들고 아래처럼 한 줄만 넣은 뒤, 롬 파일과 같은 폴더에 두세요.\n\n"
        "common: <32자리 16진수>\n\n"
        "키는 앱에 들어 있지 않습니다. 본인 콘솔에서 추출한 키를 쓰면 됩니다."
    )


def _size_text(value: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024:
            return f"{value:.0f}{unit}"
        value /= 1024
    return f"{value:.1f}TB"


def describe_cia(path: Path, keys: Keys | None = None) -> tuple[int, int, int, bool]:
    """(타이틀 ID, 타이틀 버전, 내용 수, 키 필요 여부). 헤더 확인용."""
    info = read_cia(path, keys)
    return info.title_id, info.title_version, len(info.contents), info.needs_key


def roundtrip_check(path: Path) -> bool:
    """AES 구현이 제대로 도는지 확인하는 자체 점검."""
    key = bytes(range(16))
    iv = bytes(range(16, 32))
    data = bytes(range(64))
    return cbc_decrypt(key, iv, cbc_encrypt(key, iv, data)) == data
