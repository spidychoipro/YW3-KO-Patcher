"""Pinned upstream CIA helper, isolated per run; no batch script or bundled binaries."""
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

import yw3convert as converter

UPSTREAM = "xxmichibxx/Batch-CIA-3DS-Decryptor-Redux"
REVISION = "2fb1ac549a4006dd5261b8545e943527960ceeff"
FILES = {
    "decrypt.exe": "35506bc9c5610cd41c7a6e6c377b01bca30217e61d5b5e4842156120fa9e59a0",
    "makerom.exe": "db810fb9c3d41ecaefa8fcbd13140ecafe9b95e6303cd9244c12a2bca70fa938",
    "seeddb.bin": "ccdcea5e4465194158737462436ec10ae48669dd961902282ac2861e260d03c9",
}


class ExternalError(Exception):
    pass


def _sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(converter.CHUNK), b''):
            digest.update(block)
    return digest.hexdigest()


def ensure_tools(cache: Path, download, log) -> dict[str, Path]:
    folder = cache / 'cia-helper' / REVISION
    folder.mkdir(parents=True, exist_ok=True)
    result = {}
    for name, digest in FILES.items():
        path = folder / name
        if not path.is_file() or _sha256(path) != digest:
            log(f'CIA 자동 복호화 도구 준비: {name}')
            download(f'https://raw.githubusercontent.com/{UPSTREAM}/{REVISION}/bin/{name}', path)
        if _sha256(path) != digest:
            path.unlink(missing_ok=True)
            raise ExternalError(f'자동 복호화 도구 {name}의 SHA-256이 다릅니다. 실행하지 않았습니다.')
        result[name] = path
    return result


@contextmanager
def protect_source(path: Path):
    """A Windows handle allowing other readers, but denying writes and deletion."""
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    api.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                               ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    api.CreateFileW.restype = wintypes.HANDLE
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.CloseHandle.restype = wintypes.BOOL
    handle = api.CreateFileW(str(path.resolve()), 0x80000000, 1, None, 3, 0x80, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ExternalError('원본 보호 잠금을 열지 못했습니다. 파일을 사용하는 프로그램을 닫아 주세요.')
    try:
        yield
    finally:
        api.CloseHandle(handle)


def _run(command, folder, phase, log):
    output = folder / (phase + '.log')
    with output.open('wb') as handle:
        process = subprocess.run(command, cwd=folder, input=b'\n', stdout=handle,
                                 stderr=subprocess.STDOUT, creationflags=0x08000000)
    if process.returncode:
        raise ExternalError(f'CIA 자동 {phase}에 실패했습니다 (종료 코드 {process.returncode}).')
    log(f'CIA 자동 {phase} 완료')


def _wrap_in_place(main: Path, parts: list[Path], output: Path, min_size: int):
    """Prepend NCSD by shifting backwards: no second multi-GB NCCH copy."""
    headers = []
    for path in parts:
        with path.open('rb') as handle:
            headers.append((handle.read(512), path.stat().st_size))
    packed = converter.CCI_HEADER_SIZE + sum(size for _, size in headers)
    wanted = converter._align(min_size, converter.MEDIA_UNIT)
    total = wanted if 0 < wanted - packed <= 0x10000000 else packed
    header = converter._build_ncsd_header(headers, total)
    original_size = main.stat().st_size
    with main.open('r+b') as handle:
        handle.truncate(total)
        end = original_size
        while end:
            start = max(0, end - converter.CHUNK)
            handle.seek(start)
            block = handle.read(end - start)
            if len(block) != end - start:
                raise ExternalError('복호화된 본편을 CCI로 옮기는 도중 파일이 잘렸습니다.')
            handle.seek(start + len(header))
            handle.write(block)
            end = start
        handle.seek(0)
        handle.write(header)
        handle.seek(len(header) + original_size)
        for path in parts[1:]:
            with path.open('rb') as source:
                shutil.copyfileobj(source, handle, converter.CHUNK)
    main.replace(output)


def prepare(source: Path, key: str, work: Path, cache: Path, download, log,
            min_size: int = 0) -> Path:
    tools = ensure_tools(cache, download, log)
    source = source.resolve()
    folder = (work / ('external_' + key)).resolve()
    folder.mkdir(exist_ok=False)
    alias = folder / 'input.cia'
    try:
        try:
            os.link(source, alias)
        except OSError:
            # Cross-volume inputs cannot use hardlinks.
            if shutil.disk_usage(folder).free < 2 * source.stat().st_size + 256 * 1024 * 1024:
                raise ExternalError('CIA 자동 복호화 임시 공간이 부족합니다. 여유 공간이 있는 저장 위치를 골라 주세요.')
            shutil.copyfile(source, alias)
        for name, path in tools.items():
            shutil.copyfile(path, folder / name)
        info = converter.read_cia(source)
        if key not in ('base', 'update') or not info.contents:
            raise ExternalError('본편 또는 업데이트 CIA 콘텐츠가 없습니다.')
        expected = 0x00040000001AF400 if key == 'base' else 0x0004000E001AF400
        if info.title_id != expected:
            raise ExternalError('선택한 역할과 CIA 타이틀 ID가 다릅니다.')
        log('키 파일 없이 CIA 자동 복호화를 시작합니다. 원본은 쓰기/삭제 잠금으로 보호합니다.')
        with protect_source(source):
            _run([str(folder / 'decrypt.exe'), str(alias)], folder, '복호화', log)
        parts = []
        for content in info.contents:
            path = folder / f'input.{content.index}.ncch'
            if not path.is_file() or path.stat().st_size != content.size:
                raise ExternalError(f'콘텐츠 {content.index} 복호화 결과가 없거나 크기가 다릅니다.')
            with path.open('rb') as handle:
                head = handle.read(512)
            if (head[0x100:0x104] != b'NCCH' or not head[0x18f] & 4
                    or int.from_bytes(head[0x118:0x120], 'little') != expected):
                raise ExternalError(f'콘텐츠 {content.index}가 정상 복호화된 NCCH가 아닙니다.')
            parts.append(path)
        if key == 'base':
            if [c.index for c in info.contents] != list(range(len(parts))):
                raise ExternalError('본편 CIA 파티션 번호 배치를 지원하지 못합니다.')
            output = folder / 'base.cci'
            _wrap_in_place(parts[0], parts, output, min_size)
        else:
            output = folder / 'update.cia'
            command = [str(folder / 'makerom.exe'), '-f', 'cia', '-ignoresign', '-target', 'p',
                       '-o', str(output), '-ver', str(info.title_version)]
            for content, path in zip(info.contents, parts):
                command += ['-i', f'{path}:{content.index}:{content.content_id}']
            _run(command, folder, 'CIA 재구성', log)
            if not output.is_file() or converter.read_cia(output).needs_key:
                raise ExternalError('업데이트 CIA 재구성 결과가 정상 복호화되지 않았습니다.')
        # Only files created in this isolated folder; keep the prepared output until patching.
        for path in folder.glob('*.ncch'):
            path.unlink()
        return output
    except (OSError, converter.ConvertError) as exc:
        raise ExternalError(f'CIA 자동 복호화 도중 오류가 발생했습니다: {exc}') from exc
    finally:
        # Release the input hardlink/copy after the read-only guard has closed.
        alias.unlink(missing_ok=True)
