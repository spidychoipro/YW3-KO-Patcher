"""3DS 컨테이너 변환/복호화.

이 모듈은 네 가지 일을 한다.

- 암호화된 CIA의 내용을 복호화한다 (티켓의 타이틀 키 사용).
- 암호화된 CCI(NCSD)의 NCCH 구간을 복호화한다 (NCCH 표준 암호).
- CIA(또는 NCCH)를 CCI로 다시 묶는다.
- 복호화된 CCI를 실기에서 설치할 수 있는 CIA로 바꾼다.
- 파일 헤더를 읽어 컨테이너 구조를 파악한다.

AES는 Windows CNG(bcrypt.dll)를 그대로 쓴다. 외부 패키지가 없어도 되고
exe에 같이 들어간다. 키는 앱에 넣지 않고 사용자가 둔 keys.txt에서만 읽는다.

참고한 문서: 3dbrew.org (CIA, Ticket, TMD, NCCH, NCSD), GodMode9/Decrypt9 소스
"""

from __future__ import annotations

import array
import ctypes
import hashlib
import os
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from ctypes import wintypes

import yw3ciatemplate as ciatemplate

MEDIA_UNIT = 0x200
CCI_HEADER_SIZE = 0x4000  # NCSD 헤더 + 카드 정보 헤더 영역
CIA_HEADER_SIZE = 0x2020  # CIA 헤더(뒤 예약 영역 포함)
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
    """AES 한 벌(CBC/ECB). with 문으로 열고 닫는다."""

    def __init__(self, key: bytes, chaining: str = "CBC") -> None:
        if len(key) != 16:
            raise ConvertError("AES 키 길이가 16바이트가 아닙니다.")
        self._alg = wintypes.HANDLE()
        self._key = wintypes.HANDLE()
        _ntstatus(_bcrypt.BCryptOpenAlgorithmProvider(
            ctypes.byref(self._alg), "AES", None, 0))
        try:
            mode = f"ChainingMode{chaining}".encode("utf-16-le") + b"\x00\x00"
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

    def _run(self, data: bytes, iv: bytes | None, encrypt: bool) -> bytes:
        if len(data) % 16:
            raise ConvertError("암호화 데이터 길이가 16의 배수가 아닙니다.")
        if not data:
            return b""
        out = ctypes.create_string_buffer(len(data))
        written = wintypes.ULONG(0)
        iv_buf = ctypes.create_string_buffer(iv, 16) if iv is not None else None
        func = _bcrypt.BCryptEncrypt if encrypt else _bcrypt.BCryptDecrypt
        _ntstatus(func(self._key, data, len(data), None, iv_buf, 16 if iv_buf else 0,
                       out, len(data), ctypes.byref(written), 0))
        return out.raw[:written.value]

    def decrypt(self, data: bytes, iv: bytes) -> bytes:
        return self._run(data, iv, encrypt=False)

    def encrypt(self, data: bytes, iv: bytes) -> bytes:
        return self._run(data, iv, encrypt=True)


class AesEcb(AesCbc):
    """AES-ECB 한 벌. CTR 카운터 블록을 암호화할 때 쓴다."""

    def __init__(self, key: bytes) -> None:
        super().__init__(key, chaining="ECB")

    def encrypt_blocks(self, data: bytes) -> bytes:
        return self._run(data, None, encrypt=True)


def cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    with AesCbc(key) as cipher:
        return cipher.decrypt(data, iv)


def cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    with AesCbc(key) as cipher:
        return cipher.encrypt(data, iv)


# --------------------------------------------------------------------- CTR
#
# 3DS NCCH는 AES-CTR을 쓴다. 카운터는 빅엔디언 128비트이고 16바이트마다 1씩 는다.
# Windows CNG에는 CTR 모드가 없어서(이 PC에서 확인) 카운터 블록을 ECB로 한꺼번에
# 암호화한 뒤 데이터와 XOR한다. 카운터 블록은 1MiB 단위로 모아서 만든다.

CTR_BATCH_BLOCKS = 1 << 16  # 1MiB
_MASK64 = (1 << 64) - 1
# j = 0..65535일 때 BE32(j)의 3번째/4번째 바이트 모양
_CTR_BYTE14 = b"".join(bytes([value]) * 256 for value in range(256))
_CTR_BYTE15 = bytes(range(256)) * 256


def _xor_bytes(data: bytes, stream: bytes) -> bytes:
    size = len(data)
    if not size:
        return b""
    return (int.from_bytes(data, "little") ^ int.from_bytes(stream, "little")).to_bytes(
        size, "little")


def _counters_general(ctr: int, blocks: int) -> bytes:
    """ctr부터 blocks개의 빅엔디언 128비트 카운터를 만든다."""
    low = ctr & _MASK64
    high = (ctr >> 64) & _MASK64
    if low + blocks > _MASK64:
        first = _MASK64 + 1 - low
        return _counters_general(ctr, first) + _counters_general(ctr + first, blocks - first)
    values = array.array("Q", range(low, low + blocks))
    if sys.byteorder == "little":
        values.byteswap()
    lows = values.tobytes()
    out = bytearray(16 * blocks)
    high_bytes = high.to_bytes(8, "big")
    for index in range(8):
        out[index::16] = bytes([high_bytes[index]]) * blocks
        out[8 + index::16] = lows[index::8]
    return bytes(out)


class _CtrSection:
    """구간 시작(카운터 하위 56비트가 0) 카운터를 빠르게 만드는 틀."""

    def __init__(self, base: int) -> None:
        self.base = base
        self.template = bytearray(16 * CTR_BATCH_BLOCKS)
        high_bytes = ((base >> 64) & _MASK64).to_bytes(8, "big")
        for index in range(8):
            self.template[index::16] = bytes([high_bytes[index]]) * CTR_BATCH_BLOCKS
        self.template[8::16] = bytes([(base >> 56) & 0xFF]) * CTR_BATCH_BLOCKS
        self.template[14::16] = _CTR_BYTE14
        self.template[15::16] = _CTR_BYTE15

    def counters(self, block: int, count: int) -> bytes:
        chunk, rest = divmod(block, CTR_BATCH_BLOCKS)
        if rest == 0 and 0 <= chunk < 0x10000 and count <= CTR_BATCH_BLOCKS:
            if count == CTR_BATCH_BLOCKS:
                out = bytearray(self.template)
            else:
                out = bytearray(self.template[:16 * count])
            out[12::16] = bytes([(chunk >> 8) & 0xFF]) * count
            out[13::16] = bytes([chunk & 0xFF]) * count
            return bytes(out)
        return _counters_general(self.base + block, count)


class CtrCipher:
    """NCCH 한 구간용 AES-CTR. offset은 구간 시작부터의 바이트 위치."""

    def __init__(self, key: bytes, ctr_base: int) -> None:
        self._aes = AesEcb(key)
        self._base = ctr_base
        self._section: _CtrSection | None = None
        self._fast = (ctr_base & ((1 << 56) - 1)) == 0

    def close(self) -> None:
        self._aes.close()

    def __enter__(self) -> "CtrCipher":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def _keystream(self, block: int, blocks: int) -> bytes:
        if self._fast:
            if self._section is None:
                self._section = _CtrSection(self._base)
            counters = self._section.counters(block, blocks)
        else:
            counters = _counters_general(self._base + block, blocks)
        return self._aes.encrypt_blocks(counters)

    def decrypt(self, offset: int, data: bytes) -> bytes:
        total = len(data)
        out = bytearray(total)
        pos = 0
        while pos < total:
            absolute = offset + pos
            skip = absolute % 16
            block = absolute // 16
            take = min(total - pos, CTR_BATCH_BLOCKS * 16 - skip)
            blocks = (skip + take + 15) // 16
            piece = self._keystream(block, blocks)[skip:skip + take]
            out[pos:pos + take] = _xor_bytes(data[pos:pos + take], piece)
            pos += take
        return bytes(out)


def ctr_decrypt(key: bytes, ctr_base: int, offset: int, data: bytes) -> bytes:
    with CtrCipher(key, ctr_base) as cipher:
        return cipher.decrypt(offset, data)


# ------------------------------------------------------------- NCCH keys


def _rol128(value: int, bits: int) -> int:
    bits %= 128
    mask = (1 << 128) - 1
    return ((value << bits) | (value >> (128 - bits))) & mask


def normal_key(key_x: bytes, key_y: bytes) -> bytes:
    """keyX/keyY로 NCCH 표준 암호에 쓰는 normal key를 만든다(키 스크램블러)."""
    scrambled = _rol128(
        (_rol128(int.from_bytes(key_x, "big"), 2) ^ int.from_bytes(key_y, "big"))
        + 0x1FF9E9AAC5FE0408024591DC5D52768A,
        87,
    )
    return scrambled.to_bytes(16, "big")


# -------------------------------------------------------------------- keys


COMMON_KEYX_SLOT = 0x3D
COMMON_KEY_COUNT = 6


@dataclass(frozen=True)
class Keys:
    """keys.txt에서 읽은 키 묶음.

    common은 예전 형식(이름 없는 한 줄 또는 `common:`)으로 들어온 값이다.
    요즘 덤프 도구의 `common0`~`common5`는 공통 키의 KeyY라서 그대로는 쓸 수
    없고, `slot0x3DKeyX`와 키 스크램블러로 normal key를 만들어야 한다.
    """

    common: bytes | None = None
    keyx: dict[int, bytes] = field(default_factory=dict)
    seeds: dict[int, bytes] = field(default_factory=dict)
    path: Path | None = None
    common_keys: dict[int, bytes] = field(default_factory=dict)  # 인덱스별 normal key
    common_y: dict[int, bytes] = field(default_factory=dict)  # 인덱스별 KeyY

    def _derive_common(self, index: int) -> bytes | None:
        key_y = self.common_y.get(index)
        key_x = self.keyx.get(COMMON_KEYX_SLOT) or self.keyx.get(COMMON_KEYX_SLOT - 1)
        if key_y is None or key_x is None:
            return None
        return normal_key(key_x, key_y)

    def common_candidates(self, ticket_index: int | None = None) -> list[tuple[int | None, bytes]]:
        """타이틀 키를 풀어 볼 common 키 후보를 우선순위대로 돌려준다.

        티켓이 가리키는 인덱스를 먼저 보고, 그다음 나머지 후보를 본다.
        어느 쪽이 맞는지는 실제 내용이 NCCH로 풀리는지로 확인한다.
        """
        ordered: list[tuple[int | None, bytes]] = []
        seen: set[bytes] = set()

        def add(index: int | None, key: bytes | None) -> None:
            if key is None or len(key) != 16 or key in seen:
                return
            seen.add(key)
            ordered.append((index, key))

        def add_index(index: int) -> None:
            add(index, self.common_keys.get(index))
            add(index, self._derive_common(index))
            # commonN을 normal key로 적어 둔 파일도 있어서 한 번 더 본다.
            add(index, self.common_y.get(index))

        if ticket_index is not None:
            add_index(ticket_index)
        add(None, self.common)
        if self.common is not None:
            key_x = self.keyx.get(COMMON_KEYX_SLOT) or self.keyx.get(COMMON_KEYX_SLOT - 1)
            if key_x is not None:
                add(None, normal_key(key_x, self.common))
        for index in sorted(self.common_keys):
            add_index(index)
        for index in sorted(self.common_y):
            add_index(index)
        return ordered

    def has_common(self) -> bool:
        return bool(self.common or self.common_keys or self.common_y)

    def summary(self) -> list[str]:
        """키 파일에 뭐가 들어 있는지 사람이 읽을 수 있게 정리한다."""
        if self.path is None and not (self.common or self.common_keys
                                      or self.common_y or self.keyx or self.seeds):
            return ["키 파일: 없음 (암호화된 파일이면 필요해요)"]
        lines = [f"키 파일: {self.path}" if self.path else "키 파일: (경로 없음)"]
        common: list[str] = []
        if self.common:
            common.append("기본 common")
        if self.common_keys:
            common.append("normal " + ", ".join(
                f"{index}" for index in sorted(self.common_keys)))
        if self.common_y:
            common.append("KeyY " + ", ".join(
                f"{index}" for index in sorted(self.common_y)))
        lines.append("  공통 키: " + (", ".join(common) if common else "없음"))
        keyx = ", ".join(f"0x{slot:02X}" for slot in sorted(self.keyx))
        lines.append("  keyX 슬롯: " + (keyx if keyx else "없음"))
        if self.seeds:
            lines.append(f"  시드: {len(self.seeds)}개")
        return lines


def _parse_keyx_slot(name: str) -> int | None:
    """'slot0x2CKeyX', 'keyX2C', '2c' 같은 이름에서 keyX 슬롯 번호를 뽑는다."""
    lowered = name.lower()
    if "keyx" not in lowered and not lowered.startswith("slot"):
        return None
    cleaned = lowered.replace("keyx", "").replace("slot", "").replace("0x", "")
    cleaned = cleaned.replace("_", "").replace("-", "").replace(" ", "")
    if not cleaned or len(cleaned) > 2:
        return None
    if any(char not in "0123456789abcdef" for char in cleaned):
        return None
    return int(cleaned, 16)


def _parse_seed_title(name: str) -> int | None:
    """'seed_00040000001AF400' 같은 이름에서 타이틀 ID를 뽑는다."""
    lowered = name.lower()
    if "seed" not in lowered:
        return None
    match = re.search(r"[0-9a-f]{16}", lowered)
    if not match:
        return None
    return int(match.group(0), 16)


def _parse_common_slot(name: str) -> tuple[str, int | None] | None:
    """'common0'/'common00'/'slot0x3DKey0'에서 (종류, 인덱스)를 뽑는다.

    관행상 `common0`~`common5`는 KeyY, `common00`~`common05`와
    `slot0x3DKey0`~`slot0x3DKey5`는 normal key다.
    """
    lowered = name.replace("_", "").replace("-", "").replace(" ", "")
    match = re.match(r"^slot0x3dkey([0-9a-f])$", lowered)
    if match:
        return "normal", int(match.group(1), 16)
    if not lowered.startswith("common"):
        return None
    suffix = lowered[len("common"):]
    if not suffix:
        return "legacy", None
    if len(suffix) > 2 or any(char not in "0123456789abcdef" for char in suffix):
        return "legacy", None
    if len(suffix) == 1:
        return "keyy", int(suffix, 16)
    if suffix[0] == "0":
        return "normal", int(suffix[1], 16)
    return "normal", int(suffix, 16)


def load_keys_file(path: Path) -> Keys:
    """keys.txt에서 common/keyX/seed를 읽는다.

    권장 형식:
        common: <32 hex>              (예전 형식, normal key로 취급)
        slot0x3DKeyX: <32 hex>        (공통 키 KeyX)
        common0: <32 hex>             (공통 키 0번 KeyY)
        slot0x2CKeyX: <32 hex>
        seed_00040000001AF400: <32 hex>
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return Keys()
    common: bytes | None = None
    bare: bytes | None = None
    keyx: dict[int, bytes] = {}
    seeds: dict[int, bytes] = {}
    common_keys: dict[int, bytes] = {}
    common_y: dict[int, bytes] = {}
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
        data = bytes.fromhex(value)
        common_slot = _parse_common_slot(name)
        if common_slot is not None:
            kind, index = common_slot
            if kind == "keyy" and index is not None:
                common_y.setdefault(index, data)
            elif kind == "normal" and index is not None:
                common_keys.setdefault(index, data)
            else:
                common = common or data
            continue
        slot = _parse_keyx_slot(name)
        if slot is not None:
            keyx.setdefault(slot, data)
            continue
        title_id = _parse_seed_title(name)
        if title_id is not None:
            seeds.setdefault(title_id, data)
            continue
        if not name and bare is None:
            bare = data
    return Keys(common or bare, keyx, seeds, path, common_keys, common_y)


def find_keys(search_dirs: list[Path]) -> Keys:
    """키 파일을 찾아 common/keyX/seed를 읽는다. 없으면 빈 Keys."""
    candidates: list[Path] = []
    override = os.environ.get(KEYS_ENV)
    if override:
        candidates.append(Path(override))
    for folder in search_dirs:
        if folder.is_file():
            candidates.append(folder)
            continue
        for name in KEYS_NAMES:
            candidates.append(folder / name)
    common: bytes | None = None
    keyx: dict[int, bytes] = {}
    seeds: dict[int, bytes] = {}
    common_keys: dict[int, bytes] = {}
    common_y: dict[int, bytes] = {}
    found_path: Path | None = None
    for path in candidates:
        if not path.is_file():
            continue
        keys = load_keys_file(path)
        if keys.common or keys.common_keys or keys.common_y or keys.keyx or keys.seeds:
            found_path = found_path or path
        common = common or keys.common
        for slot, key in keys.keyx.items():
            keyx.setdefault(slot, key)
        for title_id, seed in keys.seeds.items():
            seeds.setdefault(title_id, seed)
        for index, key in keys.common_keys.items():
            common_keys.setdefault(index, key)
        for index, key in keys.common_y.items():
            common_y.setdefault(index, key)
    return Keys(common, keyx, seeds, found_path, common_keys, common_y)


# ----------------------------------------------------------- seeddb.bin


SEEDDB_NAMES = ("seeddb.bin",)


def load_seeddb(path: Path) -> dict[int, bytes]:
    """seeddb.bin(GodMode9 덤프)에서 타이틀별 시드를 읽는다."""
    try:
        data = path.read_bytes()
    except OSError:
        return {}
    if len(data) < 16:
        return {}
    count = int.from_bytes(data[0:4], "little")
    available = max((len(data) - 16) // 0x20, 0)
    if count > available:
        count = available
    seeds: dict[int, bytes] = {}
    for index in range(count):
        entry = 16 + index * 0x20
        title_id = int.from_bytes(data[entry:entry + 8], "little")
        seed = data[entry + 8:entry + 24]
        if title_id and len(seed) == 16:
            seeds[title_id] = seed
    return seeds


def find_seeds(search_dirs: list[Path]) -> dict[int, bytes]:
    """seeddb.bin을 찾아 시드 목록을 읽는다. 없으면 빈 dict."""
    for folder in search_dirs:
        for name in SEEDDB_NAMES:
            path = folder / name
            if path.is_file():
                seeds = load_seeddb(path)
                if seeds:
                    return seeds
    return {}


def load_keys(search_dirs: list[Path], extra_files: list[Path] | None = None) -> Keys:
    """keys.txt와 seeddb.bin을 함께 읽는다. keys.txt의 시드가 우선한다.

    extra_files는 사용자가 화면에서 직접 고른 키 파일이다. 폴더에서 찾은 것보다
    먼저 읽어서 값이 겹치면 고른 파일 쪽을 쓴다.
    """
    keys = find_keys(list(extra_files or ()) + list(search_dirs))
    seeds = find_seeds(search_dirs)
    if not seeds:
        return keys
    merged = dict(seeds)
    merged.update(keys.seeds)
    return Keys(keys.common, keys.keyx, merged, keys.path, keys.common_keys, keys.common_y)


# --------------------------------------------------- CCI (NCSD) decryption
#
# CCI/3DS 안에는 NCCH가 파티션으로 들어 있다. NCCH 헤더 자체는 평문이고,
# 확장 헤더/ExeFS/RomFS만 AES-CTR로 암호화되어 있다. 복호화에 필요한 keyX는
# 앱에 넣지 않고 keys.txt에서만 읽는다. 시드 암호면 seeddb.bin도 쓴다.
#
# 카드리더 하드웨어 단계(SNOW 2.0 + RC4)는 여기서 다루지 않는다. 그건 콘솔에서
# 카드를 읽을 때 풀리는 암호라서, 이미 .3ds로 덤프된 파일에는 해당되지 않는다.

NCCH_MAGIC = b"NCCH"
NCSD_PARTITIONS = 8


@dataclass(frozen=True)
class NcchCryptoInfo:
    """NCCH 헤더에서 뽑은 암호 관련 정보."""

    program_id: int
    version: int
    flags3: int
    flags7: int
    seed_crypto: bool
    fixed_key: bool
    key_slots: tuple[int, int]  # (메뉴 정보용 keyid 0, 본문용 keyid 1)


def ncch_crypto_info(header: bytes) -> NcchCryptoInfo:
    if len(header) < 0x200 or header[0x100:0x104] != NCCH_MAGIC:
        raise ConvertError("NCCH 헤더가 아닙니다.")
    flags3 = header[0x18B]
    flags7 = header[0x18F]
    if not flags3:
        content_slot = 0x2C
    elif flags3 == 0x0A:
        content_slot = 0x18
    elif flags3 == 0x0B:
        content_slot = 0x1B
    else:
        content_slot = 0x25
    return NcchCryptoInfo(
        program_id=int.from_bytes(header[0x118:0x120], "little"),
        version=int.from_bytes(header[0x112:0x114], "little"),
        flags3=flags3,
        flags7=flags7,
        seed_crypto=bool(flags7 & 0x20),
        fixed_key=bool(flags7 & 0x01),
        key_slots=(0x2C, content_slot),
    )


@dataclass
class NcchPartition:
    """NCSD 파티션 하나. offset/size는 파일 안에서의 바이트 위치."""

    index: int
    offset: int
    size: int
    header: bytes


@dataclass(frozen=True)
class NcchRegion:
    """NCCH 안의 게임 영역 하나. offset/size는 NCCH 시작부터의 바이트."""

    name: str
    offset: int
    size: int


def ncch_unit(header: bytes) -> int:
    """NCCH 미디어 유닛 크기. 보통 0x200이고, 큰 게임은 더 클 수 있다."""
    return MEDIA_UNIT << header[0x18E]


def ncch_regions(header: bytes) -> list[NcchRegion]:
    """NCCH 헤더가 가리키는 확장 헤더/평문/로고/ExeFS/RomFS 영역을 읽는다.

    공식 패치의 manifest.json과 같은 방식으로 위치를 계산한다.
    크기가 0인 영역은 목록에서 뺀다.
    """
    unit = ncch_unit(header)

    def u32(at: int) -> int:
        return int.from_bytes(header[at:at + 4], "little")

    regions: list[NcchRegion] = []
    exthdr_size = u32(0x180)
    if exthdr_size:
        regions.append(NcchRegion("exheader", 0x200, exthdr_size))
    for name, field in (("plain", 0x190), ("logo", 0x198),
                        ("exefs", 0x1A0), ("romfs", 0x1B0)):
        offset = u32(field) * unit
        size = u32(field + 4) * unit
        if size:
            regions.append(NcchRegion(name, offset, size))
    return regions


@dataclass
class _DecryptRange:
    """복호화할 구간. offset은 기준(NCCH 또는 파일) 시작부터의 바이트."""

    offset: int
    size: int
    key: bytes
    ctr_base: int
    ctr_offset: int


@dataclass
class _PartitionPlan:
    partition: NcchPartition
    ranges: list[_DecryptRange]  # NCCH 안에서의 위치
    header_patch: bytes
    seed_crypto: bool


def read_ncsd(path: Path) -> list[NcchPartition]:
    """NCSD(CCI) 헤더와 파티션별 NCCH 헤더를 읽는다."""
    total = path.stat().st_size
    with path.open("rb") as handle:
        head = handle.read(CCI_HEADER_SIZE)
        if len(head) < CCI_HEADER_SIZE or head[0x100:0x104] != b"NCSD":
            raise ConvertError("CCI(NCSD) 헤더가 아닙니다.")
        partitions: list[NcchPartition] = []
        for index in range(NCSD_PARTITIONS):
            entry = 0x120 + index * 8
            units = int.from_bytes(head[entry:entry + 4], "little")
            count = int.from_bytes(head[entry + 4:entry + 8], "little")
            if not units or not count:
                continue
            offset = units * MEDIA_UNIT
            declared = count * MEDIA_UNIT
            if offset + 0x200 > total:
                raise ConvertError("CCI 파티션 위치가 파일 크기를 넘어갑니다. 파일이 잘렸을 수 있어요.")
            handle.seek(offset)
            header = handle.read(0x200)
            if len(header) < 0x200 or header[0x100:0x104] != NCCH_MAGIC:
                raise ConvertError(f"CCI 파티션 {index}에서 NCCH 헤더를 찾지 못했습니다.")
            content_units = int.from_bytes(header[0x104:0x108], "little")
            size = (content_units * MEDIA_UNIT) or declared
            size = min(max(size, 0x200), declared or size)
            if offset + size > total:
                raise ConvertError(f"CCI 파티션 {index}가 파일 끝을 넘어갑니다. 파일이 잘렸을 수 있어요.")
            partitions.append(NcchPartition(index, offset, size, header))
    return partitions


@dataclass(frozen=True)
class NcsdContainer:
    """GodMode9이 보는 NCSD 헤더 값. 게임 내용은 읽지 않는다."""

    file_size: int
    size_units: int
    card_size_bytes: int
    media_id: bytes
    fs_type_zero: bool
    partitions: tuple[tuple[int, int], ...]  # (시작 유닛, 크기 유닛)

    @property
    def size_bytes(self) -> int:
        return self.size_units * MEDIA_UNIT

    @property
    def partition_end_units(self) -> int:
        return max((offset + size for offset, size in self.partitions if size), default=0)

    @property
    def partition_end_bytes(self) -> int:
        return self.partition_end_units * MEDIA_UNIT

    def structural_issues(self) -> list[str]:
        """ValidateNcsdHeader + IdentifyFileType에서 파일을 GC 제외하는 조건."""
        issues: list[str] = []
        if not self.fs_type_zero:
            issues.append("NCSD 파티션 FS 종류가 0이 아닙니다")
        if not any(self.media_id):
            issues.append("NCSD 미디어 ID가 0입니다")
        if not self.partitions or not self.partitions[0][1]:
            issues.append("NCSD 첫 파티션이 없습니다")
        cursor = 0
        for offset, size in self.partitions:
            if not size:
                continue
            if offset < cursor:
                issues.append("NCSD 파티션이 겹치거나 순서가 바뀌었습니다")
                break
            if (offset + size) * MEDIA_UNIT > self.file_size:
                issues.append("NCSD 파티션이 파일 끝을 넘어갑니다")
                break
            cursor = offset + size
        return issues


def read_ncsd_container(path: Path) -> NcsdContainer:
    """파티션 크기를 보정하지 않고 NCSD 헤더에 적힌 값을 그대로 읽는다."""
    total = path.stat().st_size
    with path.open("rb") as handle:
        head = handle.read(CCI_HEADER_SIZE)
    if len(head) < CCI_HEADER_SIZE:
        raise ConvertError("CCI 헤더가 잘렸습니다.")
    if head[0x100:0x104] != b"NCSD":
        raise ConvertError("NCSD(CCI) 헤더가 아닙니다.")
    partitions = tuple(
        (int.from_bytes(head[0x120 + index * 8:0x124 + index * 8], "little"),
         int.from_bytes(head[0x124 + index * 8:0x128 + index * 8], "little"))
        for index in range(NCSD_PARTITIONS)
    )
    return NcsdContainer(
        file_size=total,
        size_units=int.from_bytes(head[0x104:0x108], "little"),
        card_size_bytes=int.from_bytes(head[0x300:0x304], "little"),
        media_id=head[0x108:0x110],
        fs_type_zero=head[0x110:0x118] == bytes(8),
        partitions=partitions)


def validate_ncsd_container(path: Path) -> NcsdContainer:
    """구조가 잘못된 CCI를 결과로 저장하지 않게 막는다."""
    info = read_ncsd_container(path)
    issues = info.structural_issues()
    if issues:
        raise ConvertError("사용할 수 없는 CCI 컨테이너입니다: " + ", ".join(issues))
    return info


def repair_ncsd_size(path: Path, log=None) -> tuple[int, int]:
    """NCSD 선언 크기가 파티션 끝보다 작으면 헤더 두 칸만 고친다.

    xdelta 결과가 공식 완성본과 같아도 원본 CIA로 만든 CCI는 선언 크기가
    작을 수 있다. GodMode9는 선언 크기가 파티션 끝보다 작으면 NCSD로
    인식하지 않으므로 0x104와 카드 정보의 0x300만 맞춘다.
    게임 영역·NCCH 헤더·서명은 건드리지 않는다.
    """
    info = validate_ncsd_container(path)
    old = info.size_units
    new = max(old, info.partition_end_units)
    card = max(info.card_size_bytes, new * MEDIA_UNIT)
    if card > 0xFFFFFFFF:
        card = info.card_size_bytes
    if new == old and card == info.card_size_bytes:
        return old, old
    with path.open("r+b") as handle:
        handle.seek(0x104)
        handle.write(new.to_bytes(4, "little"))
        handle.seek(0x300)
        handle.write(card.to_bytes(4, "little"))
    if log is not None:
        log(f"NCSD 선언 크기 보정: {old:,} → {new:,} 유닛 "
            f"({info.size_bytes:,} → {new * MEDIA_UNIT:,}바이트, GodMode9 인식용)")
    return old, new


def _ncch_ctr_base(header: bytes, section: int, section_start: int) -> int:
    """GetNcchCtr와 같은 초기 카운터를 만든다.

    version 1은 파티션 시작부터의 실제 오프셋을 카운터에 넣고,
    그 밖(0/2)은 파티션 ID + 구간 번호 조합을 쓴다.
    """
    partition_id = header[0x108:0x110]
    version = int.from_bytes(header[0x112:0x114], "little")
    if version == 1:
        return (int.from_bytes(partition_id, "big") << 64) | section_start
    return (int.from_bytes(partition_id, "little") << 64) | (section << 56)


def _seed_hash(seed: bytes, program_id: int) -> bytes:
    return hashlib.sha256(seed + program_id.to_bytes(8, "little")).digest()[:4]


def _pick_seed(header: bytes, keys: Keys) -> bytes | None:
    """이 NCCH에 맞는 시드를 찾는다. 헤더의 hash_seed로 검증한다."""
    program_id = int.from_bytes(header[0x118:0x120], "little")
    seed = keys.seeds.get(program_id)
    wanted = header[0x114:0x118]
    if seed is not None and (not any(wanted) or _seed_hash(seed, program_id) == wanted):
        return seed
    if any(wanted):  # 제목이 달라도 해시가 맞는 시드가 있으면 쓴다
        for candidate in keys.seeds.values():
            if _seed_hash(candidate, program_id) == wanted:
                return candidate
    if seed is not None and not any(wanted):
        return seed
    if seed is not None:
        raise ConvertError(
            "keys.txt(또는 seeddb.bin)의 시드가 이 CCI와 맞지 않습니다.\n\n"
            f"타이틀 0x{program_id:016X}의 시드를 다시 확인해 주세요."
        )
    return None


def _read_decrypt(handle, partition: NcchPartition, part_range: _DecryptRange) -> bytes:
    """파일에서 구간을 읽어 복호화한다(검증용)."""
    handle.seek(partition.offset + part_range.offset)
    data = handle.read(part_range.size)
    if len(data) != part_range.size:
        raise ConvertError("CCI를 읽는 도중에 끝났습니다. 파일이 잘렸을 수 있어요.")
    return ctr_decrypt(part_range.key, part_range.ctr_base, part_range.ctr_offset, data)


def _read_plain(handle, partition: NcchPartition, offset: int, size: int) -> bytes:
    handle.seek(partition.offset + offset)
    return handle.read(size)


def _exefs_names_ok(header: bytes) -> bool | None:
    """복호화된 ExeFS 첫 블록이 그럴듯한지 본다. 해시가 없을 때 쓰는 보조 확인."""
    if len(header) < 0x10:
        return None
    known = {b".code", b"code", b"banner", b"icon", b"logo", b".fst", b"fst"}
    names = [header[index * 0x10:index * 0x10 + 8].rstrip(b"\x00")
             for index in range(10)]
    found = sum(1 for name in names if name in known)
    if found:
        return True
    return False


def _probe_regions(handle, partition: NcchPartition,
                   key_menu: bytes | None, key_content: bytes | None
                   ) -> tuple[bool | None, list[str]]:
    """확장 헤더/ExeFS/RomFS를 풀어(또는 그대로 읽어) 실제 내용인지 확인한다.

    key_menu/key_content가 None이면 이미 복호화된 파일로 보고 그대로 읽는다.
    확인할 수 있는 영역이 없으면 None을 돌려준다.
    """
    header = partition.header
    info = ncch_crypto_info(header)
    checks: list[bool] = []
    issues: list[str] = []
    exthdr_size = int.from_bytes(header[0x180:0x184], "little")
    exefs_offset = int.from_bytes(header[0x1A0:0x1A4], "little") * ncch_unit(header)
    exefs_size = int.from_bytes(header[0x1A4:0x1A8], "little") * ncch_unit(header)
    romfs_offset = int.from_bytes(header[0x1B0:0x1B4], "little") * ncch_unit(header)
    romfs_size = int.from_bytes(header[0x1B4:0x1B8], "little") * ncch_unit(header)

    def read(offset: int, size: int, key: bytes | None, section: int,
             ctr_offset: int = 0) -> bytes:
        data = _read_plain(handle, partition, offset, size)
        if key is None:
            return data
        base = _ncch_ctr_base(header, section, offset)
        return ctr_decrypt(key, base, ctr_offset, data)

    if exthdr_size:
        plain = read(0x200, min(0x400, exthdr_size), key_menu, 1)
        expected = header[0x160:0x180]
        if any(expected) and len(plain) == 0x400:
            checks.append(hashlib.sha256(plain).digest() == expected)
        else:
            program_id = plain[0x200:0x208] if len(plain) >= 0x208 else b""
            if program_id and any(program_id):
                checks.append(program_id == header[0x118:0x120])
        if checks and not checks[-1]:
            issues.append("확장 헤더")

    if exefs_size:
        head = read(exefs_offset, 0x200, key_menu, 2)
        expected = header[0x1C0:0x1E0]
        hash_units = int.from_bytes(header[0x1A8:0x1AC], "little")
        result: bool | None
        if any(expected) and hash_units == 1:
            result = hashlib.sha256(head).digest() == expected
        else:
            result = _exefs_names_ok(head)
        if result is not None:
            checks.append(result)
            if not result:
                issues.append("ExeFS")

    if romfs_size:
        head = read(romfs_offset, min(0x200, romfs_size), key_content, 3)
        result = head[:4] == b"IVFC"
        expected = header[0x1E0:0x200]
        hash_units = int.from_bytes(header[0x1B8:0x1BC], "little")
        if result and any(expected) and hash_units == 1 and len(head) >= 0x200:
            result = hashlib.sha256(head).digest() == expected
        checks.append(result)
        if not result:
            issues.append("RomFS")

    if not checks:
        return None, []
    return all(checks), issues


def _partition_key_pairs(info: NcchCryptoInfo, header: bytes,
                         keys: Keys) -> list[tuple[bytes, bytes, int | None, int | None]]:
    """이 파티션을 풀어 볼 (메뉴 키, 본문 키, 슬롯, 슬롯) 후보를 만든다.

    외부 도구가 헤더의 암호 플래그만 바꿔 놓은 파일은 flags3도 지워져 있어서
    본문 슬롯을 믿을 수 없다. 그래서 keys.txt에 있는 다른 슬롯도 차례로 본다.
    """
    if info.fixed_key:
        if info.program_id & (0x10 << 32):
            raise ConvertError(
                "시스템 고정 키로 암호화된 타이틀이라 이 앱에서는 풀 수 없습니다."
            )
        zero = bytes(16)
        return [(zero, zero, None, None)]

    if info.seed_crypto:
        seed = _pick_seed(header, keys)
        if seed is None:
            raise ConvertError(_need_seed_message(info.program_id))
        key_y_content = hashlib.sha256(header[0:16] + seed).digest()[:16]
    else:
        key_y_content = header[0:16]

    usable = {slot: key for slot, key in keys.keyx.items() if slot != COMMON_KEYX_SLOT}
    if not usable:
        missing = list(dict.fromkeys([0x2C, info.key_slots[1]]))
        raise ConvertError(_need_keyx_message(missing))

    menu_slots = list(dict.fromkeys([0x2C, info.key_slots[0], *sorted(usable)]))
    content_slots = list(dict.fromkeys(
        [info.key_slots[1], 0x2C, 0x18, 0x1B, 0x25, *sorted(usable)]))
    pairs: list[tuple[bytes, bytes, int | None, int | None]] = []
    seen: set[tuple[bytes, bytes]] = set()
    for menu_slot in menu_slots:
        key_x_menu = usable.get(menu_slot)
        if key_x_menu is None:
            continue
        key_menu = normal_key(key_x_menu, header[0:16])
        for content_slot in content_slots:
            key_x_content = usable.get(content_slot)
            if key_x_content is None:
                continue
            key_content = normal_key(key_x_content, key_y_content)
            pair = (key_menu, key_content)
            if pair in seen:
                continue
            seen.add(pair)
            pairs.append((key_menu, key_content, menu_slot, content_slot))
    if not pairs:
        missing = [slot for slot in dict.fromkeys([0x2C, info.key_slots[1]])
                   if slot not in keys.keyx]
        raise ConvertError(_need_keyx_message(missing))
    return pairs


def _plan_partition(handle, partition: NcchPartition, keys: Keys,
                    log=None) -> _PartitionPlan | None:
    """한 파티션의 복호화 구간을 만들고 키가 맞는지 검증한다."""
    header = partition.header
    info = ncch_crypto_info(header)

    if info.flags7 & 0x04:
        # 외부 변환 도구가 헤더만 "복호화됨"으로 바꿔 두는 경우가 있다.
        # 플래그를 믿지 말고 실제 영역을 확인하고, 아니면 키로 다시 푼다.
        ok, issues = _probe_regions(handle, partition, None, None)
        if ok is not False:
            return None
        if log:
            log(f"NCSD 파티션 {partition.index}: 헤더는 복호화됐다고 되어 있지만 "
                f"{', '.join(issues)} 내용이 암호화되어 있음. 키로 다시 풀어 봅니다")
    else:
        ok, _issues = _probe_regions(handle, partition, None, None)
        if ok is not False and ok is not None:
            if log:
                log(f"NCSD 파티션 {partition.index}: 헤더는 암호화라고 되어 있지만 "
                    "내용은 이미 복호화되어 있음")
            return None

    pairs = _partition_key_pairs(info, header, keys)
    chosen: tuple[bytes, bytes, int | None, int | None] | None = None
    all_issues: list[str] = []
    for key_menu, key_content, menu_slot, content_slot in pairs:
        ok, issues = _probe_regions(handle, partition, key_menu, key_content)
        if ok is not False:
            chosen = (key_menu, key_content, menu_slot, content_slot)
            break
        all_issues.extend(issue for issue in issues if issue not in all_issues)

    if chosen is None:
        section = all_issues[0] if all_issues else "확장 헤더"
        raise ConvertError(_wrong_key_message(
            info.program_id, section,
            tried=len(pairs), content_slot=info.key_slots[1]))
    key_menu, key_content, menu_slot, content_slot = chosen
    if log and (menu_slot != info.key_slots[0] or content_slot != info.key_slots[1]):
        log(f"NCSD 파티션 {partition.index}: 실제 키 슬롯은 "
            f"menu 0x{menu_slot:02X}, 본문 0x{content_slot:02X}")

    unit = ncch_unit(header)
    exefs_offset = int.from_bytes(header[0x1A0:0x1A4], "little") * unit
    exefs_size = int.from_bytes(header[0x1A4:0x1A8], "little") * unit
    romfs_offset = int.from_bytes(header[0x1B0:0x1B4], "little") * unit
    romfs_size = int.from_bytes(header[0x1B4:0x1B8], "little") * unit
    exthdr_size = int.from_bytes(header[0x180:0x184], "little")

    ranges: list[_DecryptRange] = []
    if exthdr_size:
        exthdr = _DecryptRange(
            0x200, 0x800, key_menu, _ncch_ctr_base(header, 1, 0x200), 0)
        ranges.append(exthdr)

    if exefs_size:
        base = _ncch_ctr_base(header, 2, exefs_offset)
        exefs_head = _DecryptRange(exefs_offset, 0x200, key_menu, base, 0)
        plain_head = _read_decrypt(handle, partition, exefs_head)
        ranges.append(exefs_head)
        for index in range(10):
            entry = plain_head[index * 0x10:(index + 1) * 0x10]
            name = entry[:8].rstrip(b"\x00")
            file_offset = int.from_bytes(entry[8:12], "little")
            file_size = int.from_bytes(entry[12:16], "little")
            if not file_size:
                continue
            start = exefs_offset + 0x200 + file_offset
            if start >= exefs_offset + exefs_size:
                continue
            file_size = min(file_size, exefs_offset + exefs_size - start)
            key = key_menu if name.startswith((b"banner", b"icon")) else key_content
            ranges.append(_DecryptRange(start, file_size, key, base, 0x200 + file_offset))
            padding = _align(file_size, MEDIA_UNIT) - file_size
            if padding > 0:
                ranges.append(_DecryptRange(
                    start + file_size, padding, key_menu, base,
                    0x200 + file_offset + file_size))

    if romfs_size:
        base = _ncch_ctr_base(header, 3, romfs_offset)
        ranges.append(_DecryptRange(romfs_offset, romfs_size, key_content, base, 0))

    patched = bytearray(header)
    patched[0x18B] = 0  # ncchflag[3]
    patched[0x18F] = (patched[0x18F] & ~0x21) | 0x04
    return _PartitionPlan(partition, ranges, bytes(patched), info.seed_crypto)


def _merge_ranges(ranges: list[_DecryptRange]) -> list[_DecryptRange]:
    """겹치는 구간을 정리한다. 앞 구간을 자르고 빈 구간은 버린다."""
    result: list[_DecryptRange] = []
    for item in sorted(ranges, key=lambda rng: rng.offset):
        if item.size <= 0:
            continue
        if result:
            previous = result[-1]
            end = previous.offset + previous.size
            if item.offset < end:
                previous.size = item.offset - previous.offset
                if previous.size <= 0:
                    result.pop()
        result.append(item)
    return result


def check_plaintext_cci(path: Path) -> list[str]:
    """복호화됐다고 표시된 CCI의 실제 내용이 정말 평문인지 확인한다.

    외부 변환 도구가 NCCH 헤더의 플래그만 바꿔 놓는 경우가 있어서, 플래그를
    믿지 않고 확장 헤더/ExeFS/RomFS를 읽어 본다. 문제가 된 영역 이름을 돌려주고,
    목록이 비어 있으면 그대로 써도 된다.
    """
    try:
        partitions = read_ncsd(path)
    except ConvertError:
        return []  # 헤더가 잘린 파일은 크기를 맞춘 뒤에 다시 본다
    issues: list[str] = []
    with path.open("rb") as handle:
        for partition in partitions:
            info = ncch_crypto_info(partition.header)
            if not (info.flags7 & 0x04):
                continue
            ok, bad = _probe_regions(handle, partition, None, None)
            if ok is False:
                issues.extend(issue for issue in bad if issue not in issues)
    return issues


def decrypt_cci(src: Path, dst: Path, keys: Keys, log, progress=None) -> Path:
    """암호화된 CCI를 복호화한 CCI로 새로 쓴다. NCSD 헤더는 그대로 둔다."""
    partitions = read_ncsd(src)
    total = src.stat().st_size
    plans: list[_PartitionPlan] = []
    with src.open("rb") as handle:
        for partition in partitions:
            plan = _plan_partition(handle, partition, keys, log)
            if plan is None:
                log(f"NCSD 파티션 {partition.index}: 이미 복호화되어 있음")
                continue
            plans.append(plan)
            log(f"NCSD 파티션 {partition.index}: NCCH 암호 해제 준비"
                + (" (시드 암호)" if plan.seed_crypto else ""))
    if not plans:
        raise ConvertError("이 CCI는 이미 복호화되어 있습니다.")

    ranges: list[_DecryptRange] = []
    patches: dict[int, bytes] = {}
    for plan in plans:
        base = plan.partition.offset
        for part_range in plan.ranges:
            size = min(part_range.size, plan.partition.size - part_range.offset)
            if size <= 0:
                continue
            ranges.append(_DecryptRange(
                base + part_range.offset, size, part_range.key,
                part_range.ctr_base, part_range.ctr_offset))
        patches[base] = plan.header_patch
    ranges = _merge_ranges(ranges)

    dst.parent.mkdir(parents=True, exist_ok=True)
    part = dst.with_name(dst.name + ".part")
    part.unlink(missing_ok=True)
    ciphers: list[tuple[int, CtrCipher]] = []
    try:
        with src.open("rb") as source, part.open("wb") as target:
            position = 0
            index = 0
            while position < total:
                chunk = source.read(min(CHUNK, total - position))
                if not chunk:
                    raise ConvertError("CCI를 읽는 도중에 끝났습니다. 파일이 잘렸을 수 있어요.")
                buffer = bytearray(chunk)
                end = position + len(chunk)

                for patch_offset, patch in patches.items():
                    patch_end = patch_offset + len(patch)
                    if patch_end <= position or patch_offset >= end:
                        continue
                    left = max(position, patch_offset)
                    right = min(end, patch_end)
                    buffer[left - position:right - position] = \
                        patch[left - patch_offset:right - patch_offset]

                while index < len(ranges) and ranges[index].offset + ranges[index].size <= position:
                    index += 1
                cursor = index
                while cursor < len(ranges) and ranges[cursor].offset < end:
                    item = ranges[cursor]
                    left = max(position, item.offset)
                    right = min(end, item.offset + item.size)
                    if right > left:
                        cipher = _cipher_for(ciphers, cursor, item)
                        offset = item.ctr_offset + (left - item.offset)
                        buffer[left - position:right - position] = cipher.decrypt(
                            offset, bytes(buffer[left - position:right - position]))
                    cursor += 1

                target.write(buffer)
                position = end
                if progress:
                    progress(100.0 * position / max(total, 1))
            if target.tell() != total:
                raise ConvertError("CCI 복호화 결과 크기가 원본과 다릅니다.")
        os.replace(part, dst)
    except Exception:
        part.unlink(missing_ok=True)
        raise
    finally:
        for _index, cipher in ciphers:
            cipher.close()
    log(f"CCI 암호 해제 완료: {dst.name} ({_size_text(dst.stat().st_size)})")
    return dst


def _cipher_for(ciphers: list[tuple[int, CtrCipher]], index: int,
                item: _DecryptRange) -> CtrCipher:
    for saved_index, cipher in ciphers:
        if saved_index == index:
            return cipher
    cipher = CtrCipher(item.key, item.ctr_base)
    ciphers.append((index, cipher))
    return cipher


# ------------------------------------------------------------- CIA parsing


@dataclass
class CiaContent:
    index: int
    content_id: int
    size: int
    offset: int
    encrypted: bool
    plaintext: bool = False  # TMD는 암호화라고 하는데 내용은 이미 평문인 경우


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
    common_index: int | None = None
    title_key_index: int | None = None
    key_verified: bool = False
    title_key_origin: str = ""
    key_candidates: int = 0
    bad_contents: tuple[int, ...] = ()
    tmd_offset: int = 0

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


def _is_sig_type(value: int) -> bool:
    return 0x00010000 <= value <= 0x00010005


def _ticket_common_index(ticket_data: bytes) -> int | None:
    """티켓이 가리키는 common 키 인덱스(0~5). 없으면 None."""
    if len(ticket_data) <= 0xB1:
        return None
    index = ticket_data[0xB1]
    return index if index < COMMON_KEY_COUNT else None


def _content_is_plaintext(raw: bytes) -> bool:
    return len(raw) >= 0x104 and raw[0x100:0x104] == NCCH_MAGIC


def _title_key_unlocks(raw: bytes, index: int, title_key: bytes) -> bool:
    """이 타이틀 키로 내용 머리를 풀었을 때 NCCH가 나오는지 본다."""
    if len(raw) < 0x200:
        return False
    plain = cbc_decrypt(title_key, _content_iv(index), raw[:0x200])
    return plain[0x100:0x104] == NCCH_MAGIC


def _find_title_key(encrypted_key: bytes, ticket_title: int, tmd_title: int,
                    ticket_data: bytes, probes: list[tuple[int, bytes]] | None,
                    keys: Keys) -> tuple[bytes | None, int | None, bool, int, str]:
    """타이틀 키 후보를 차례로 대 보고 실제로 풀리는 것을 고른다.

    - 티켓의 타이틀 키가 이미 평문인 CIA도 있어서 그것부터 본다.
    - common0~common5는 KeyY인 경우가 많아 slot0x3DKeyX와 짝을 맞춘다.
    - 티켓 타이틀 ID와 TMD 타이틀 ID가 다른 CIA도 있어서 둘 다 시도한다.
    - 암호화된 내용이 여러 개면 하나라도 풀리는 키를 찾는다. 첫 내용이
      깨져 있어도 다른 내용으로 키를 확인할 수 있다.
    - 0으로 채워진 키는 후보에서 뺀다.
    """
    candidates: list[tuple[bytes, int | None, str]] = []
    seen: set[bytes] = set()

    def add(key: bytes | None, index: int | None, origin: str) -> None:
        if key is None or len(key) != 16 or key == bytes(16) or key in seen:
            return
        seen.add(key)
        candidates.append((key, index, origin))

    add(encrypted_key, None, "평문 타이틀 키")
    common_index = _ticket_common_index(ticket_data)
    for index, common in keys.common_candidates(common_index):
        for title in dict.fromkeys((ticket_title, tmd_title)):
            if not title:
                continue
            try:
                title_key = decrypt_title_key(encrypted_key, title, common)
            except ConvertError:
                continue
            origin = f"common {index}" if index is not None else "common"
            if title != ticket_title:
                origin += f" / 타이틀 0x{title:016X}"
            add(title_key, index, origin)

    if not candidates:
        return None, None, False, 0, ""
    if not probes:
        # 내용이 너무 짧아 확인할 수 없으면 첫 후보를 그대로 쓴다.
        key, index, origin = candidates[0]
        return key, index, False, len(candidates), origin
    for key, index, origin in candidates:
        for content_index, raw in probes:
            if _title_key_unlocks(raw, content_index, key):
                return key, index, True, len(candidates), origin
    return None, None, False, len(candidates), ""


def read_cia(path: Path, keys: Keys | None = None) -> CiaInfo:
    """CIA 헤더/티켓/TMD를 읽는다. 암호화 여부와 타이틀 키까지 계산한다.

    CIA는 각 구간(인증서, 티켓, TMD, 메타, 내용)이 0x40 경계에서 시작한다.
    헤더 크기가 보통 0x2020이라 그냥 더하면 0x20씩 밀리므로 반드시 맞춰 준다.
    """
    with path.open("rb") as handle:
        head = handle.read(0x2040)
        if len(head) < 0x2020 or head[:4] != b"\x20\x20\x00\x00":
            raise ConvertError("CIA 헤더가 아닙니다.")
        header_size = int.from_bytes(head[0x00:0x04], "little")
        cert_size = int.from_bytes(head[0x08:0x0C], "little")
        ticket_size = int.from_bytes(head[0x0C:0x10], "little")
        tmd_size = int.from_bytes(head[0x10:0x14], "little")

        def probe(offset: int) -> int:
            handle.seek(offset)
            found = handle.read(4)
            return int.from_bytes(found, "big") if len(found) == 4 else -1

        def place(offset: int) -> int:
            """기본은 0x40 정렬. 정렬 안 한 예전 CIA면 그냥 붙여 쓴 위치가 맞다."""
            aligned = _align(offset, 0x40)
            if aligned != offset and not _is_sig_type(probe(aligned)) and _is_sig_type(probe(offset)):
                return offset
            return aligned

        cert_offset = place(header_size)
        ticket_offset = place(cert_offset + cert_size)
        tmd_offset = place(ticket_offset + ticket_size)
        # CIA content follows the TMD; optional metadata follows content.
        content_area = _align(tmd_offset + tmd_size, 0x40)
        handle.seek(ticket_offset)
        ticket = handle.read(ticket_size)
        handle.seek(tmd_offset)
        tmd = handle.read(tmd_size)

    if len(ticket) < 0x250 or len(tmd) < 0xC4:
        raise ConvertError("CIA 안의 티켓이나 TMD가 잘렸습니다.")

    tmd_sig = _sig_data_size(int.from_bytes(tmd[0:4], "big"))
    tmd_header = tmd[tmd_sig:]
    title_id = int.from_bytes(tmd_header[0x4C:0x54], "big")
    if title_id >> 48 != 0x0004:  # CTR 타이틀 ID는 항상 0x0004로 시작한다
        raise ConvertError("CIA 안의 TMD에서 타이틀 ID를 읽지 못했습니다. 파일이 손상됐을 수 있어요.")
    title_version = int.from_bytes(tmd_header[0x9C:0x9E], "big")
    content_count = int.from_bytes(tmd_header[0x9E:0xA0], "big")

    records = tmd[tmd_sig + 0xC4 + 0x24 * 64:]
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

    # TMD는 암호화라고 적혀 있어도 실제 내용이 평문인 CIA가 있다(hshop 등).
    # 먼저 내용 머리를 보고, 진짜 암호화된 구간만 키 확인에 쓴다.
    probes: list[tuple[int, bytes]] = []
    encrypt_required = False
    with path.open("rb") as handle:
        for content in contents:
            if not content.encrypted:
                continue
            handle.seek(content.offset)
            raw = handle.read(min(0x400, content.size))
            if _content_is_plaintext(raw):
                content.plaintext = True
                continue
            encrypt_required = True
            if len(raw) >= 0x200:
                probes.append((content.index, raw))

    needs_key = encrypt_required
    title_key: bytes | None = None
    title_key_index: int | None = None
    key_verified = False
    title_key_origin = ""
    key_candidates = 0
    if needs_key and keys is not None:
        title_key, title_key_index, key_verified, key_candidates, title_key_origin = \
            _find_title_key(
                encrypted_key, ticket_title, title_id, ticket_data, probes, keys)

    bad_contents: list[int] = []
    if title_key is not None:
        # 첫 내용만 맞고 다른 내용이 안 풀리는 경우를 따로 알려준다.
        with path.open("rb") as handle:
            for content in contents:
                if not content.encrypted or content.plaintext or content.size < 0x200:
                    continue
                handle.seek(content.offset)
                raw = handle.read(0x200)
                if len(raw) == 0x200 and not _title_key_unlocks(raw, content.index, title_key):
                    bad_contents.append(content.index)

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
        common_index=_ticket_common_index(ticket_data),
        title_key_index=title_key_index,
        key_verified=key_verified,
        title_key_origin=title_key_origin,
        key_candidates=key_candidates,
        bad_contents=tuple(bad_contents),
        tmd_offset=tmd_offset,
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
        raise ConvertError(_title_key_error(info, keys))
    if info.bad_contents:
        raise ConvertError(_bad_content_message(info))

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
                if not content.encrypted or content.plaintext:
                    continue
                _decrypt_in_place(target, content.offset, content.size, cipher,
                                  _content_iv(content.index), progress,
                                  done * 100.0 / len(info.contents),
                                  (done + 1) * 100.0 / len(info.contents))
    os.replace(part, dst)
    return dst


# --------------------------------------------------------- CIA/NCCH -> CCI


def _build_ncsd_header(parts: list[tuple[bytes, int]], total_size: int | None = None) -> bytes:
    """NCCH 헤더 목록(헤더, 파티션 크기)으로 카트리지 같은 NCSD(CCI) 헤더를 만든다.

    파티션 0은 본편, 1은 설명서, 2는 다운로드 플레이 자식이다. 카트리지 덤프와
    같은 모양으로 맞춰 두면 에뮬레이터와 3DS 쪽에서 그냥 CCI로 인식한다.
    """
    if not parts:
        raise ConvertError("CCI로 묶을 NCCH가 없습니다.")
    packed = sum(size for _head, size in parts)
    total = total_size or (CCI_HEADER_SIZE + packed)

    header = bytearray(CCI_HEADER_SIZE)
    first = parts[0][0]
    header[0x100:0x104] = b"NCSD"
    header[0x104:0x108] = (total // MEDIA_UNIT).to_bytes(4, "little")
    header[0x108:0x110] = first[0x108:0x110]  # 미디어 ID = 본편 파티션 ID
    header[0x110:0x118] = (0).to_bytes(8, "big")  # 파티션 FS 종류: 일반
    header[0x118:0x120] = b"\x00" * 8  # 파티션별 암호화 종류: 전부 없음

    offset = CCI_HEADER_SIZE
    for index, (head, size) in enumerate(parts[:NCSD_PARTITIONS]):
        header[0x120 + index * 8:0x124 + index * 8] = \
            (offset // MEDIA_UNIT).to_bytes(4, "little")
        header[0x124 + index * 8:0x128 + index * 8] = \
            (size // MEDIA_UNIT).to_bytes(4, "little")
        header[0x190 + index * 8:0x198 + index * 8] = head[0x108:0x110]
        offset += size

    header[0x160:0x180] = first[0x160:0x180]  # 확장 헤더 해시
    header[0x180:0x184] = (0).to_bytes(4, "little")  # 추가 헤더 없음
    header[0x184:0x188] = (0).to_bytes(4, "little")  # 섹터 0 오프셋
    header[0x18C] = 1  # 미디어 플랫폼: CTR
    header[0x18D] = 1  # 미디어 종류: 카드1
    header[0x200:0x204] = b"\xff\xff\xff\xff"  # 카드1은 항상 0xFFFFFFFF
    header[0x204:0x208] = (1).to_bytes(4, "little")  # 카드 정보 있음
    header[0x300:0x304] = total.to_bytes(4, "little")  # 카트리지 채운 크기
    header[0x310:0x312] = first[0x112:0x114]  # 타이틀 버전

    title_id = int.from_bytes(first[0x118:0x120], "little")
    header[0x1000:0x1008] = title_id.to_bytes(8, "little")  # 시드 자리
    header[0x1100:0x1200] = first[0x100:0x200]  # NCCH 헤더 사본(서명 제외)
    return bytes(header)


def _patch_nocrypto(ncch_head: bytes) -> bytes:
    """복호화한 내용이니 NCCH 헤더의 암호 플래그를 정리한다."""
    fixed = bytearray(ncch_head)
    fixed[0x18B] = 0  # ncchflag[3]
    fixed[0x18F] = (fixed[0x18F] & ~0x21) | 0x04
    return bytes(fixed)


def _cia_ncch_size(plain_head: bytes, content_size: int) -> int:
    """CIA 내용 하나가 CCI에서 차지할 크기를 정한다."""
    declared = int.from_bytes(plain_head[0x104:0x108], "little") * MEDIA_UNIT
    return max(declared, _align(content_size, MEDIA_UNIT), 0x400)


def cia_to_cci(src: Path, dst: Path, keys: Keys, log, progress=None,
               min_size: int = 0) -> Path:
    """CIA의 모든 내용(본편·설명서·DLP)을 꺼내 카트리지처럼 CCI로 묶는다.

    min_size는 카트리지 원본 크기다. 설명서나 DLP 내용이 빠진 CIA라도
    xdelta 패치가 원본 크기를 요구하므로 뒤를 0으로 채워 크기를 맞춘다.
    """
    info = read_cia(src, keys)
    if not info.contents:
        raise ConvertError("CIA 안에 내용이 없습니다.")
    if info.needs_key and not info.title_key:
        raise ConvertError(_title_key_error(info, keys))
    if info.bad_contents:
        raise ConvertError(_bad_content_message(info))

    entries: list[tuple[CiaContent, bytes, bytes, int]] = []
    with src.open("rb") as source:
        for content in sorted(info.contents, key=lambda item: item.index)[:NCSD_PARTITIONS]:
            source.seek(content.offset)
            raw_head = source.read(0x400)
            if len(raw_head) < 0x400:
                raise ConvertError("CIA 내용이 잘렸습니다.")
            if content.encrypted and not content.plaintext:
                plain_head = cbc_decrypt(info.title_key, _content_iv(content.index), raw_head)
            else:
                plain_head = raw_head
            if plain_head[0x100:0x104] != b"NCCH":
                if content.encrypted:
                    if info.key_verified:
                        raise ConvertError(_content_broken_message(info, content.index))
                    raise ConvertError(_title_key_error(info, keys))
                raise ConvertError(
                    f"CIA 내용 {content.index}에서 NCCH 헤더를 찾지 못했습니다. "
                    "파일이 손상됐는지 확인해 주세요.")
            entries.append((content, _patch_nocrypto(plain_head), raw_head,
                            _cia_ncch_size(plain_head, content.size)))

        packed = sum(size for _content, _head, _raw, size in entries)
        total = CCI_HEADER_SIZE + packed
        wanted = _align(min_size, MEDIA_UNIT) if min_size else 0
        # 설명서/DLP가 빠진 CIA면 카트리지 원본 크기까지 0으로 채운다.
        # 차이가 너무 크면 애초에 다른 게임이라 채워도 패치가 안 되니 그냥 둔다.
        if wanted and 0 < wanted - total <= 0x10000000:
            total = wanted
        header = _build_ncsd_header(
            [(head, size) for _content, head, _raw, size in entries], total)
        log(f"CIA 내용 {len(entries)}개를 CCI로 묶습니다 "
            f"(본편 {_size_text(entries[0][3])}"
            + (f", 추가 {_size_text(packed - entries[0][3])}" if len(entries) > 1 else "")
            + ")")

        dst.parent.mkdir(parents=True, exist_ok=True)
        part = dst.with_name(dst.name + ".part")
        part.unlink(missing_ok=True)
        done = 0
        try:
            with part.open("wb") as target:
                target.write(header)

                def report(extra: int = 0) -> None:
                    if progress:
                        progress(min(99.0, 100.0 * (done + extra) / max(total, 1)))

                for content, plain_head, raw_head, size in entries:
                    target.write(plain_head)
                    body = max(content.size - len(raw_head), 0)
                    if content.encrypted and not content.plaintext:
                        start_pct = 100.0 * (done + len(raw_head)) / max(total, 1)
                        end_pct = 100.0 * (done + len(raw_head) + body) / max(total, 1)
                        source.seek(content.offset + len(raw_head))
                        with AesCbc(info.title_key) as cipher:
                            _decrypt_copy(source, target, body, cipher, raw_head[-16:],
                                          progress, start_pct, end_pct, 0, max(body, 1))
                    else:
                        source.seek(content.offset + len(raw_head))
                        sent = 0
                        while sent < body:
                            block = source.read(min(CHUNK, body - sent))
                            if not block:
                                raise ConvertError(
                                    "CIA를 읽는 도중에 끝났습니다. 파일이 손상됐을 수 있어요.")
                            target.write(block)
                            sent += len(block)
                            report(len(raw_head) + sent)
                    padding = size - len(plain_head) - body
                    while padding > 0:
                        step = min(CHUNK, padding)
                        target.write(b"\x00" * step)
                        padding -= step
                    done += size
                    report()

                padding = total - CCI_HEADER_SIZE - packed
                while padding > 0:
                    step = min(CHUNK, padding)
                    target.write(b"\x00" * step)
                    padding -= step
        except Exception:
            part.unlink(missing_ok=True)
            raise
        os.replace(part, dst)
    log(f"CCI 변환 완료: {dst.name} ({_size_text(dst.stat().st_size)})")
    return dst


def cci_to_cia(src: Path, dst: Path, log, progress=None) -> Path:
    """복호화된 CCI를 실기에서 설치할 수 있는 CIA로 바꾼다.

    makerom은 CCI 전체를 메모리에 올려서 3GB가 넘는 본편을 처리하지 못한다.
    여기서는 CIA의 머리 부분(인증서·티켓·TMD)만 고정 서식으로 만들어 쓰고
    NCCH 파티션은 스트리밍으로 복사한다. 내용은 이미 평문이므로 암호화하지
    않고, TMD에 각 파티션의 크기와 SHA-256만 남긴다.
    """
    parts = read_ncsd(src)
    if not parts:
        raise ConvertError("CCI 안에 NCCH 파티션이 없습니다.")
    title_id = int.from_bytes(parts[0].header[0x118:0x120], "little")
    if title_id != 0x00040000001AF400:
        raise ConvertError("본편 CCI가 아닙니다. 요괴워치3 스키야키 본편 CCI를 골라 주세요.")
    for part in parts:
        if not part.header[0x18F] & 0x04:
            raise ConvertError("암호화된 CCI는 CIA로 바로 바꿀 수 없습니다. "
                               "먼저 복호화된 CCI를 만들어 주세요.")

    count = len(parts)
    tmd_sig = _sig_data_size(int.from_bytes(ciatemplate.TMD[0:4], "big"))
    tmd_fixed = tmd_sig + 0xC4
    info_records = 64 * 0x24
    tmd_size = tmd_fixed + info_records + count * 0x30
    ticket_sig = _sig_data_size(int.from_bytes(ciatemplate.TICKET[0:4], "big"))

    cert = bytearray(ciatemplate.CERT_CHAIN)
    ticket = bytearray(ciatemplate.TICKET)
    tmd = bytearray(ciatemplate.TMD)
    if len(tmd) < tmd_size:
        tmd.extend(b"\x00" * (tmd_size - len(tmd)))
    else:
        del tmd[tmd_size:]

    ticket[ticket_sig + 0x7F:ticket_sig + 0x8F] = b"\x00" * 16
    ticket[ticket_sig + 0x9C:ticket_sig + 0xA4] = title_id.to_bytes(8, "big")
    ticket[ticket_sig + 0xA6:ticket_sig + 0xA8] = (0).to_bytes(2, "big")
    tmd[tmd_sig + 0x4C:tmd_sig + 0x54] = title_id.to_bytes(8, "big")
    tmd[tmd_sig + 0x9C:tmd_sig + 0x9E] = (0).to_bytes(2, "big")
    tmd[tmd_sig + 0x9E:tmd_sig + 0xA0] = count.to_bytes(2, "big")

    sizes = [_align(part.size, 0x40) for part in parts]
    content_size = sum(sizes)
    header = bytearray(CIA_HEADER_SIZE)
    header[0:4] = (CIA_HEADER_SIZE).to_bytes(4, "little")
    header[8:12] = len(cert).to_bytes(4, "little")
    header[12:16] = len(ticket).to_bytes(4, "little")
    header[16:20] = len(tmd).to_bytes(4, "little")
    header[24:32] = content_size.to_bytes(8, "little")
    cert_offset = _align(CIA_HEADER_SIZE, 0x40)
    ticket_offset = _align(cert_offset + len(cert), 0x40)
    tmd_offset = _align(ticket_offset + len(ticket), 0x40)
    content_offset = _align(tmd_offset + len(tmd), 0x40)

    log(f"CCI 파티션 {count}개를 실기용 CIA로 묶습니다.")
    dst.parent.mkdir(parents=True, exist_ok=True)
    part_path = dst.with_name(dst.name + ".part")
    part_path.unlink(missing_ok=True)
    hashes: list[bytes] = []
    try:
        with src.open("rb") as source, part_path.open("wb") as target:
            target.write(header)
            target.write(b"\x00" * (cert_offset - target.tell()))
            target.write(cert)
            target.write(b"\x00" * (ticket_offset - target.tell()))
            target.write(ticket)
            target.write(b"\x00" * (tmd_offset - target.tell()))
            tmd_position = target.tell()
            target.write(tmd)
            target.write(b"\x00" * (content_offset - target.tell()))

            done = 0
            for ncch, size in zip(parts, sizes):
                source.seek(ncch.offset)
                digest = hashlib.sha256()
                left = ncch.size
                while left:
                    block = source.read(min(CHUNK, left))
                    if not block:
                        raise ConvertError("CCI를 읽는 도중에 끝났습니다. 파일이 손상됐을 수 있어요.")
                    digest.update(block)
                    target.write(block)
                    left -= len(block)
                if size > ncch.size:
                    target.write(b"\x00" * (size - ncch.size))
                hashes.append(digest.digest())
                done += size
                if progress:
                    progress(min(99.0, 100.0 * done / max(content_size, 1)))

            records = bytearray()
            for index, (ncch, digest) in enumerate(zip(parts, hashes)):
                record = bytearray(0x30)
                record[0:4] = index.to_bytes(4, "big")
                record[4:6] = ncch.index.to_bytes(2, "big")
                record[6:8] = (0).to_bytes(2, "big")
                record[8:16] = ncch.size.to_bytes(8, "big")
                record[16:48] = digest
                records.extend(record)
            info_record = bytearray(0x24)
            info_record[2:4] = count.to_bytes(2, "big")
            info_record[4:36] = hashlib.sha256(records).digest()
            tmd[tmd_fixed:tmd_fixed + 0x24] = info_record
            records_offset = tmd_fixed + info_records
            tmd[records_offset:records_offset + len(records)] = records
            target.seek(tmd_position)
            target.write(tmd)
    except Exception:
        part_path.unlink(missing_ok=True)
        raise
    os.replace(part_path, dst)

    info = read_cia(dst)
    if (info.title_id != title_id or len(info.contents) != count or info.needs_key
            or info.content_area != content_offset):
        raise ConvertError("만든 CIA를 다시 읽어 확인하지 못했습니다. 파일을 지우고 다시 시도해 주세요.")
    log(f"CIA 변환 완료: {dst.name} ({_size_text(dst.stat().st_size)})")
    return dst


def ncch_to_cci(src: Path, dst: Path, log, progress=None) -> Path:
    """떠 있는 NCCH(.app/.cxi) 하나를 CCI로 감싼다."""
    with src.open("rb") as source:
        head = source.read(0x400)
        if len(head) < 0x400 or head[0x100:0x104] != b"NCCH":
            raise ConvertError("NCCH 헤더가 아닙니다.")
        ncch_size = _cia_ncch_size(head, src.stat().st_size)
        plain_head = _patch_nocrypto(head)
        header = _build_ncsd_header([(plain_head, ncch_size)])
        total = CCI_HEADER_SIZE + ncch_size
        dst.parent.mkdir(parents=True, exist_ok=True)
        part = dst.with_name(dst.name + ".part")
        part.unlink(missing_ok=True)
        with part.open("wb") as target:
            target.write(header)
            target.write(plain_head)
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
        "keys.txt 파일을 만들고 아래처럼 넣은 뒤, 롬 파일과 같은 폴더에 두세요.\n\n"
        "common: <32자리 16진수>\n"
        "slot0x3DKeyX: <32자리 16진수>\n"
        "common0: <32자리 16진수>\n\n"
        "덤프 도구가 만든 keys.txt에 common0~common5만 있고 slot0x3DKeyX가 없다면,\n"
        "공통 키의 KeyY만 있는 상태라 normal key를 만들 수 없습니다.\n"
        "slot0x3DKeyX도 같이 넣어 주세요.\n\n"
        "키는 앱에 들어 있지 않습니다. 본인 콘솔에서 추출한 키를 쓰면 됩니다."
    )


def _bad_content_message(info: CiaInfo) -> str:
    indices = ", ".join(str(index) for index in info.bad_contents)
    return (
        "CIA의 타이틀 키는 다른 내용에서 확인됐는데, 일부 내용이 NCCH로 나오지 않습니다.\n"
        f"문제가 된 내용 번호: {indices}\n\n"
        "키가 틀린 게 아니라 이 내용이 손상됐거나 중간에 바뀐 것 같습니다. "
        "콘솔에서 덤프한 원본 CIA인지 확인하고, 가능하면 다시 덤프해 보세요."
    )


def _content_broken_message(info: CiaInfo, content_index: int) -> str:
    return (
        "CIA의 타이틀 키는 다른 내용에서 확인됐는데, "
        f"내용 {content_index}만 NCCH로 나오지 않습니다.\n\n"
        "keys.txt의 common 키 문제가 아니라 이 내용이 손상됐거나 중간에 바뀐 것 같습니다. "
        f"타이틀 0x{info.title_id:016X}의 원본 CIA인지 확인하고, "
        "가능하면 콘솔에서 다시 덤프해 보세요."
    )


def _title_key_error(info: CiaInfo, keys: Keys) -> str:
    """타이틀 키를 못 풀었을 때: 키가 아예 없는지, 있는데 안 맞는지 구분한다."""
    if not keys.has_common():
        if not keys.path and not keys.keyx:
            return _need_key_message()
        return (
            "keys.txt는 읽었는데 CIA를 풀 공통 키(common0~common5)가 없습니다.\n\n"
            + "\n".join(keys.summary())
            + "\n\nDumpKeys로 만든 aes_keys.txt를 쓰거나, common0~common5와 "
            "slot0x3DKeyX를 같이 넣어 주세요."
        )
    key_x = keys.keyx.get(COMMON_KEYX_SLOT) or keys.keyx.get(COMMON_KEYX_SLOT - 1)
    if keys.common_y and key_x is None:
        return (
            "keys.txt에 common0~common5(KeyY)는 있는데 slot0x3DKeyX가 없습니다.\n"
            "KeyY만으로는 normal key를 만들 수 없어서 타이틀 키를 풀지 못합니다.\n\n"
            + "\n".join(keys.summary())
            + "\n\nGodMode9에서 DumpKeys를 다시 실행해 slot0x3DKeyX 줄을 "
            "같이 받아 주세요."
        )
    lines = [
        "CIA의 타이틀 키를 풀지 못했습니다.",
        "",
        f"  티켓 common 인덱스: {info.common_index if info.common_index is not None else '알 수 없음'}",
        f"  시도한 키 후보: {info.key_candidates}개",
    ]
    lines += keys.summary()
    lines += [
        "",
        "common0~common5는 보통 KeyY입니다. slot0x3DKeyX와 짝을 맞춰 normal key를 "
        "만들어야 하고, 두 줄이 다 있어야 합니다.",
        "타이틀 키가 평문으로 들어 있는 CIA도 있어서 그 경로도 시도했지만 풀리지 않았습니다.",
        f"타이틀 0x{info.title_id:016X}의 원본 CIA가 맞는지, 콘솔에서 덤프한 그대로인지도 "
        "확인해 주세요. 중간에 손댄 파일이면 키가 맞아도 이렇게 나옵니다.",
    ]
    return "\n".join(lines)


def _need_keyx_message(slots: list[int]) -> str:
    lines = [
        "이 CCI는 암호화되어 있어서 NCCH 키(keyX)가 필요합니다.",
        "",
        "keys.txt에 아래 줄을 넣고 롬 파일과 같은 폴더에 두세요.",
        "",
    ]
    for slot in slots:
        lines.append(f"slot0x{slot:02X}KeyX: <32자리 16진수>")
    lines += [
        "",
        "키는 앱에 들어 있지 않습니다. 본인 콘솔에서 추출한 키를 쓰면 됩니다.",
    ]
    return "\n".join(lines)


def _need_seed_message(title_id: int) -> str:
    return (
        "이 CCI에는 시드 암호(seed crypto)가 걸려 있어서 시드가 필요합니다.\n\n"
        "seeddb.bin을 롬 파일과 같은 폴더에 두거나, keys.txt에 아래 줄을 넣으세요.\n\n"
        f"seed_{title_id:016X}: <32자리 16진수>\n\n"
        "시드는 앱에 들어 있지 않습니다. 본인 콘솔에서 추출한 것을 쓰면 됩니다."
    )


def _wrong_key_message(title_id: int, section: str, tried: int = 0,
                       content_slot: int | None = None) -> str:
    detail = ""
    if content_slot is not None:
        detail += f"\n헤더가 가리키는 본문 키 슬롯: 0x{content_slot:02X}"
    if tried:
        detail += f"\n시도한 키 조합: {tried}개"
    return (
        f"{section}를 풀었는데 내용이 맞지 않습니다.\n\n"
        f"타이틀 0x{title_id:016X}에 맞는 키(keyX/시드)인지 확인해 주세요. "
        "콘솔에서 덤프한 원본 그대로인지도 같이 봐야 합니다."
        f"{detail}\n\n"
        "헤더의 암호 플래그만 바꾼 파일이라면 내용은 아직 암호화되어 있습니다. "
        "keys.txt에 slot0x2CKeyX와 본문 슬롯 keyX를 넣으면 다시 풀어 봅니다."
    )


def _size_text(value: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024:
            return f"{value:.0f}{unit}"
        value /= 1024
    return f"{value:.1f}TB"


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    while True:
        if pos >= len(data):
            raise ConvertError("xdelta 패치 구조가 잘렸습니다.")
        byte = data[pos]
        pos += 1
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            return value, pos


def read_vcdiff_windows(path: Path) -> list[tuple[int, int, int | None]]:
    """xdelta3(VCDIFF) 패치의 창 목록을 (대상 오프셋, 길이, adler32)로 읽는다.

    패치를 적용한 결과가 공식 결과와 같은지 창 단위로 확인할 때 쓴다.
    adler32가 없는 패치(-n으로 만들었거나 예전 형식)는 None으로 돌려준다.
    """
    data = path.read_bytes()
    if len(data) < 5 or data[:4] != b"\xd6\xc3\xc4\x00":
        raise ConvertError("xdelta3(VCDIFF) 패치 파일이 아닙니다.")

    pos = 4
    header = data[pos]
    pos += 1
    if header & 0x01:  # 보조 압축기 ID
        pos += 1
    if header & 0x02:  # 사용자 코드 테이블
        length, pos = _read_varint(data, pos)
        pos += length
    if header & 0x04:  # 응용 헤더
        length, pos = _read_varint(data, pos)
        pos += length

    windows: list[tuple[int, int, int | None]] = []
    offset = 0
    while pos < len(data):
        indicator = data[pos]
        pos += 1
        if indicator & 0x03:  # VCD_SOURCE 또는 VCD_TARGET
            _source_size, pos = _read_varint(data, pos)
            _source_pos, pos = _read_varint(data, pos)
        _delta_len, pos = _read_varint(data, pos)
        target_len, pos = _read_varint(data, pos)
        pos += 1  # delta indicator
        lengths = []
        for _ in range(3):
            length, pos = _read_varint(data, pos)
            lengths.append(length)
        checksum: int | None = None
        if indicator & 0x04:  # VCD_ADLER32
            if pos + 4 > len(data):
                raise ConvertError("xdelta 패치 구조가 잘렸습니다.")
            checksum = int.from_bytes(data[pos:pos + 4], "big")
            pos += 4
        pos += sum(lengths)
        if pos > len(data):
            raise ConvertError("xdelta 패치 구조가 잘렸습니다.")
        windows.append((offset, target_len, checksum))
        offset += target_len

    if not windows:
        raise ConvertError("xdelta 패치에 창이 없습니다.")
    return windows


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
