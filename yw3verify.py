"""Container hash links used after payload-verified compatibility patching."""
from pathlib import Path
import hashlib

import yw3convert as converter


def _hash(handle, offset: int, size: int) -> bytes:
    handle.seek(offset)
    digest = hashlib.sha256()
    while size:
        block = handle.read(min(size, converter.CHUNK))
        if not block:
            raise converter.ConvertError("해시 검증 구간이 파일 끝을 넘습니다.")
        digest.update(block)
        size -= len(block)
    return digest.digest()


def check_ncch_links(path: Path, parts) -> None:
    with path.open('rb') as handle:
        for part in parts:
            head = part.header
            if not head[0x18f] & 4 or head[0x18e] > 8:
                raise converter.ConvertError("결과의 NCCH 복호화 플래그/미디어 단위가 잘못됐습니다.")
            regions = {r.name: r for r in converter.ncch_regions(head)}
            for name, field, count_at in (('exheader', 0x160, None),
                    ('exefs', 0x1c0, 0x1a8), ('romfs', 0x1e0, 0x1b8)):
                region = regions.get(name)
                if region is None:
                    continue
                length = (region.size if count_at is None else
                          int.from_bytes(head[count_at:count_at + 4], 'little') * converter.ncch_unit(head))
                if not 0 < length <= region.size:
                    raise converter.ConvertError(f"{name} 내부 해시 범위가 잘못됐습니다.")
                if _hash(handle, part.offset + region.offset, length) != head[field:field + 32]:
                    raise converter.ConvertError(f"파티션 {part.index} {name}의 NCCH 내부 해시가 다릅니다.")


def update_cia_tmd(path: Path, repair: bool = False) -> None:
    with path.open('rb') as handle:
        if handle.read(4) != b'\x20\x20\x00\x00':
            return
    info = converter.read_cia(path)
    if info.needs_key or not info.contents:
        raise converter.ConvertError("결과 CIA에 암호화되었거나 누락된 콘텐츠가 있습니다.")
    tmd = bytearray(info.tmd)
    body = converter._sig_data_size(int.from_bytes(tmd[:4], 'big'))
    count = len(info.contents)
    records = body + 0x9c4
    if records + count * 48 > len(tmd):
        raise converter.ConvertError("결과 CIA의 TMD 목록이 잘렸습니다.")

    def compare_or_write(at: int, digest: bytes):
        if repair:
            tmd[at:at + 32] = digest
        elif tmd[at:at + 32] != digest:
            raise converter.ConvertError("결과 CIA의 TMD 해시가 일치하지 않습니다.")

    with path.open('rb') as handle:
        for ordinal, content in enumerate(info.contents):
            at = records + ordinal * 48
            handle.seek(content.offset)
            head = handle.read(0x200)
            if head[0x100:0x104] != b'NCCH' or content.offset + content.size > path.stat().st_size:
                raise converter.ConvertError("결과 CIA의 콘텐츠 위치/크기가 잘못됐습니다.")
            if int.from_bytes(head[0x118:0x120], 'little') != info.title_id:
                raise converter.ConvertError("결과 CIA의 TMD 타이틀 ID와 NCCH 프로그램 ID가 다릅니다.")
            if repair:
                flags = int.from_bytes(tmd[at + 6:at + 8], 'big') & ~1
                tmd[at + 6:at + 8] = flags.to_bytes(2, 'big')
            elif int.from_bytes(tmd[at + 6:at + 8], 'big') & 1:
                raise converter.ConvertError("결과 CIA의 TMD에 암호화 플래그가 남아 있습니다.")
            compare_or_write(at + 16, _hash(handle, content.offset, content.size))
    covered = set()
    for ordinal in range(64):
        at = body + 0xc4 + ordinal * 36
        first = int.from_bytes(tmd[at:at + 2], 'big')
        length = int.from_bytes(tmd[at + 2:at + 4], 'big')
        if not length:
            continue
        indices = set(range(first, first + length))
        if first + length > count or covered & indices:
            raise converter.ConvertError("결과 CIA의 TMD 콘텐츠 정보 범위가 잘못됐습니다.")
        covered |= indices
        compare_or_write(at + 4, hashlib.sha256(tmd[records + first * 48:records + (first + length) * 48]).digest())
    if covered != set(range(count)):
        raise converter.ConvertError("결과 CIA의 TMD 콘텐츠 정보가 누락됐습니다.")
    compare_or_write(body + 0xa4, hashlib.sha256(tmd[body + 0xc4:body + 0x9c4]).digest())
    if repair:
        with path.open('r+b') as handle:
            handle.seek(info.tmd_offset)
            handle.write(tmd)
