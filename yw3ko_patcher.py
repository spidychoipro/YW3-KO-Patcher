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
import zipfile
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import yw3convert as converter

APP_NAME = "요괴워치3 스키야키 한국어 패치 적용기"
APP_VERSION = "1.3.0"
CACHE_ENV = "YW3KO_CACHE"

REPO = "TeamLimRyan/YW3_SUKIYAKI_KOREAN_LOCALIZATION_RELEASE"
RELEASE_TAG = "v1.0"
PATCH_ZIP_NAME = "YW3S_Korean_Patch_v1.0.zip"
PATCH_ZIP_URL = f"https://github.com/{REPO}/releases/download/{RELEASE_TAG}/{PATCH_ZIP_NAME}"

XDETTA_ZIP_URL = "https://github.com/jmacd/xdelta/releases/download/v3.2.2/xdelta3-3.2.2-windows-x86_64.zip"
XDETTA_ZIP_SHA256 = "d48f7651d86b78fdca397057b46601f89131f37219675df736db70af44ec3379"
XDETTA_EXE_MEMBER = "xdelta3-3.2.2-windows-x86_64/xdelta3.exe"
XDETTA_EXE_SHA256 = "732980d52f9220dc81817ccdd0c295eadce8a0048a24c2a771a73f791ac824e9"

CREATE_NO_WINDOW = 0x08000000
HASH_BLOCK = 8 * 1024 * 1024


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


BASE = Role(
    key="base",
    label="본편",
    patch_name="YW3_Sukiyaki_KO_base_v1.0.xdelta",
    patch_size=76459565,
    patch_sha256="b1cdc077367c198f13b34fd60330fc7f8972f8f175f3a53159093cb6807623c4",
    result_name="YW3_Sukiyaki_KO_base.cci",
    result_size=3278712832,
    result_sha256="905b326fd6949054ac64dc5db9bbb6ef90510c5da824fc197dc8a8a69f0cdb34",
)
UPDATE = Role(
    key="update",
    label="업데이트",
    patch_name="YW3_Sukiyaki_KO_update_v1.0.xdelta",
    patch_size=12287076,
    patch_sha256="e25a443c6b98f9558429299588ee35ef88158a81b3739a8431e0ffbcbdb98847",
    result_name="YW3_Sukiyaki_KO_update4.cia",
    result_size=196301824,
    result_sha256="73adda215b3c929cca7cb0d544b686957ca7c4e2d354a77d9f342924d7a35453",
)
ROLES = (BASE, UPDATE)

YW3_BASE_TITLE = 0x00040000001AF400
YW3_UPDATE_TITLE = 0x0004000E001AF400


@dataclass(frozen=True)
class RomInfo:
    """파일 헤더만 보고 판별한 컨테이너 종류/암호화 여부/타이틀."""

    kind: str  # "cci", "cia", "ncch", "unknown"
    encrypted: bool | None
    title_id: int | None
    note: str = ""


def _ncch_header(data: bytes, offset: int) -> tuple[bool, int] | None:
    """NCCH 헤더 위치에서 (암호화 여부, 프로그램 ID)를 읽는다."""
    if offset < 0 or offset + 0x200 > len(data):
        return None
    if data[offset + 0x100: offset + 0x104] != b"NCCH":
        return None
    no_crypto = bool(data[offset + 0x18F] & 0x04)
    title_id = int.from_bytes(data[offset + 0x118: offset + 0x120], "big")
    return (not no_crypto), title_id


def inspect_rom(path: Path) -> RomInfo:
    """3DS 컨테이너 헤더를 읽어 종류·암호화 여부를 판별한다. 키는 쓰지 않는다."""
    try:
        with path.open("rb") as handle:
            head = handle.read(0x2020 + 0x200000)
    except OSError as exc:
        return RomInfo("unknown", None, None, f"파일을 읽지 못했습니다: {exc}")
    if len(head) < 0x200:
        return RomInfo("unknown", None, None, "파일이 너무 작습니다.")

    found: tuple[bool, int] | None = None
    if head[0x100:0x104] == b"NCSD":
        kind = "cci"
        media_units = int.from_bytes(head[0x120:0x124], "little")
        found = _ncch_header(head, media_units * 0x200)
    elif head[:4] == b"\x20\x20\x00\x00":
        kind = "cia"
        offset = (
            int.from_bytes(head[0x00:0x04], "little")
            + int.from_bytes(head[0x08:0x0C], "little")
            + int.from_bytes(head[0x0C:0x10], "little")
            + int.from_bytes(head[0x10:0x14], "little")
            + int.from_bytes(head[0x14:0x18], "little")
        )
        offset = (offset + 0x3F) & ~0x3F
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
    encrypted, title_id = found
    return RomInfo(kind, encrypted, title_id)


def describe_rom(role_key: str, info: RomInfo) -> tuple[str, str]:
    """판별 결과를 (짧은 설명, 수준)으로 바꾼다. 수준: ok/info/warn."""
    label = "본편" if role_key == "base" else "업데이트"
    kind_name = {"cci": "CCI", "cia": "CIA", "ncch": "NCCH"}.get(info.kind, info.kind.upper())

    if info.kind == "unknown":
        return f"{label}: 3DS 파일 형식을 알아보지 못했어요. 그대로 진행할 수 있어요.", "info"
    if info.title_id is not None and info.title_id not in (YW3_BASE_TITLE, YW3_UPDATE_TITLE):
        return f"{label}: 요괴워치3 스키야키 일본판이 아니에요 (타이틀 0x{info.title_id:016X}).", "warn"
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
            return (f"{label}: 암호화된 CCI예요. 카드 이미지 암호는 콘솔 키가 필요해서 "
                    "이 앱에서는 못 풀어요."), "warn"
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
    if target.is_file() and target.stat().st_size == role.patch_size:
        if sha256_file(target) == role.patch_sha256:
            return target
        target.unlink(missing_ok=True)

    archive = cache_dir() / PATCH_ZIP_NAME
    for attempt in (1, 2):
        if not archive.is_file():
            log(f"한글 패치 v1.0 내려받는 중... ({human_size(82950210)} 내외, 처음 한 번만)")
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
            if attempt == 2:
                raise PatchError(f"{role.label} 패치를 준비하지 못했습니다.\n{exc}") from exc
    raise PatchError("패치 준비 실패")


def apply_patch(role: Role, source: Path, out_dir: Path, exe: Path, patch: Path, overwrite: bool,
                verify: bool, log, progress, status, strict: bool | None = None,
                report: dict | None = None) -> Path:
    """xdelta3로 패치 하나를 적용하고 결과 경로를 돌려준다.

    strict=False면 결과 지문이 공식 값과 달라도 파일을 남긴다(변환본으로 패치한 경우).
    """
    if strict is None:
        strict = verify
    final = out_dir / role.result_name
    if final.exists() and not overwrite:
        raise PatchError(f"결과 파일이 이미 있습니다: {final}")

    part = final.with_name(final.name + ".part")
    part.unlink(missing_ok=True)

    status(f"{role.label}에 한글을 입히는 중...")
    log(f"[{role.label}] {source.name} → {role.result_name}")
    command = [str(exe), "-d", "-f", "-s", str(source), str(patch), str(part)]
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
                log(f"[{role.label}] 변환본으로 패치해서 헤더가 달라진 경우예요. 파일은 저장합니다.")
        progress(100)
        os.replace(part, final)
    except Exception:
        part.unlink(missing_ok=True)
        raise
    log(f"[{role.label}] 완료: {final} ({human_size(final.stat().st_size)}, "
        f"{time.monotonic() - started:.0f}초)")
    return final


def prepare_source(role: Role, path: Path, work_dir: Path, keys: converter.Keys, log, status,
                   progress) -> tuple[Path, bool]:
    """패치에 쓸 파일을 준비한다. 필요하면 복호화·CCI 변환까지 한다.

    돌려주는 값은 (준비된 파일, 변환했는지 여부).
    """
    info = inspect_rom(path)
    try:
        if role.key == "base":
            if info.kind == "cia":
                status("본편 CIA를 CCI로 바꾸는 중...")
                log(f"[본편] CIA를 CCI로 변환합니다 ({human_size(path.stat().st_size)})")
                target = work_dir / "base_from_cia.cci"
                return converter.cia_to_cci(path, target, keys, log, progress), True
            if info.kind == "ncch":
                status("본편 NCCH를 CCI로 감싸는 중...")
                log("[본편] NCCH를 CCI로 감쌉니다")
                return converter.ncch_to_cci(path, work_dir / "base_from_ncch.cci", log, progress), True
            if info.encrypted:
                raise PatchError(
                    "본편 CCI가 암호화되어 있어요.\n\n"
                    "카드 이미지 암호는 그 3DS의 콘솔 키가 있어야 풀립니다. "
                    "이 앱은 그 키를 다루지 않아요.\n"
                    "복호화된 본편 CCI를 준비해 주세요."
                )
        elif info.kind == "cia" and info.encrypted:
            status("업데이트 암호를 푸는 중...")
            log("[업데이트] 암호화된 CIA를 복호화합니다")
            return converter.decrypt_cia(path, work_dir / "update_decrypted.cia", keys, progress), True
    except converter.ConvertError as exc:
        raise PatchError(str(exc)) from exc
    return path, False


def _explain_failure(role: Role, returncode: int, raw: bytes) -> str:
    text = raw.decode("utf-8", "replace").strip()
    lowered = text.lower()
    if "source" in lowered and ("mismatch" in lowered or "checksum" in lowered or "too short" in lowered):
        return (
            f"{role.label} 원본이 패치 대상 버전과 다릅니다.\n\n"
            "xdelta3 메시지:\n"
            f"{text}\n\n"
            "일본판 요괴워치3 스키야키의 복호화된 원본인지 확인해 주세요.\n"
            "본편은 복호화 CCI(v0), 업데이트는 복호화 CIA(Update 4.0)여야 합니다."
        )
    return f"xdelta3 실행에 실패했습니다 (종료 코드 {returncode}).\n\n{text}"


class PatcherApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("800x560")
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
        self.ready_var = tk.StringVar(value="본편 롬과 업데이트 파일을 골라 주세요.")
        self._add_file_row(files, 0, "① 본편 롬", self.base_var, self._pick_base)
        self._add_file_row(files, 1, "② 업데이트 파일", self.update_var, self._pick_update)
        self._add_file_row(files, 2, "③ 저장 위치", self.out_var, self._pick_out, folder=True)
        self.ready_label = ttk.Label(outer, textvariable=self.ready_var, style="Hint.TLabel",
                                     wraplength=760, justify="left")
        self.ready_label.grid(row=3, column=0, sticky="w", pady=(12, 0))
        self.base_var.trace_add("write", lambda *_: self._refresh())
        self.update_var.trace_add("write", lambda *_: self._refresh())

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
        ).grid(row=9, column=0, sticky="w", pady=(10, 0))

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
        needs_keys = False
        for role_key, path in (("base", base_path), ("update", update_path)):
            info = inspect_rom(path)
            message, level = describe_rom(role_key, info)
            has_warning = has_warning or level == "warn"
            needs_keys = needs_keys or bool(info.encrypted)
            lines.append(("✓ " if level == "ok" else "") + message)
        if needs_keys and not converter.find_keys([base_path.parent, update_path.parent]).common:
            lines.append("· 암호를 풀려면 keys.txt가 필요해요 (롬과 같은 폴더에 두면 자동으로 읽어요).")
            has_warning = True
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
            self._outer.rowconfigure(8, weight=0)
            self.geometry("800x560")
        else:
            self._outer.rowconfigure(8, weight=1)
            self.log_frame.grid(row=8, column=0, sticky="nsew", pady=(12, 0))
            self.log_button.configure(text="진행 기록 숨기기")
            self.geometry("800x780")

    def _center_window(self) -> None:
        width, height = 800, 560
        x = max(0, (self.winfo_screenwidth() - width) // 2)
        y = max(0, (self.winfo_screenheight() - height) // 3)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def _pick_out(self) -> None:
        initial = self.out_var.get() or str(self._last_out_dir or Path.home())
        path = filedialog.askdirectory(title="결과를 저장할 폴더 선택", initialdir=initial)
        if path:
            self.out_var.set(path)

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
            if info.kind == "cia" or (info.kind == "ncch" and path == base):
                needed += path.stat().st_size  # 변환/복호화 임시 파일
        free = shutil.disk_usage(out_dir).free
        if free < needed:
            self._log(f"저장 공간이 부족할 수 있습니다. 필요 약 {human_size(needed)}, 남은 공간 {human_size(free)}")

        keys = converter.find_keys([base.parent, update.parent])
        self._last_out_dir = out_dir
        self._set_busy(True)
        self.progress["value"] = 0
        self.status_var.set("시작하는 중...")
        self.open_button.pack_forget()
        self._clear_log()
        self._log(f"본편: {base}")
        self._log(f"업데이트: {update}")
        self._log(f"저장 위치: {out_dir}")
        self._log(f"키 파일: {keys.path}" if keys.common else "키 파일: 없음 (암호화된 파일이면 필요해요)")
        for role_key, path in (("base", base), ("update", update)):
            self._log(describe_rom(role_key, inspect_rom(path))[0])
        threading.Thread(target=self._worker, args=(base, update, out_dir, keys), daemon=True).start()

    def _worker(self, base: Path, update: Path, out_dir: Path, keys: converter.Keys) -> None:
        work_dir = out_dir / "_YW3_KO_work"
        try:
            self._status("한글 패치 파일 준비 중...")
            prep_value = 0.0

            def on_prep(done: int, total: int) -> None:
                nonlocal prep_value
                if total > 0:
                    prep_value = max(prep_value, 9.0 * min(1.0, done / total))
                    self._progress(prep_value)

            exe = ensure_xdelta(self._log, on_prep)
            patches = {role.key: ensure_patch(role, self._log, on_prep) for role in ROLES}
            work_dir.mkdir(parents=True, exist_ok=True)

            plans = (
                (BASE, base, 9.0, 28.0, 28.0, 60.0),
                (UPDATE, update, 60.0, 70.0, 70.0, 96.0),
            )
            results: list[Path] = []
            notes: list[str] = []
            for role, source, prep_low, prep_high, low, high in plans:
                prepared, converted = prepare_source(
                    role, source, work_dir, keys, self._log, self._status,
                    lambda percent, a=prep_low, b=prep_high: self._progress(a + (b - a) * percent / 100.0),
                )
                report: dict = {}
                results.append(apply_patch(
                    role, prepared, out_dir, exe, patches[role.key], True, True,
                    self._log,
                    lambda percent, a=low, b=high: self._progress(a + (b - a) * percent / 100.0),
                    self._status,
                    strict=not converted,
                    report=report,
                ))
                if converted:
                    prepared.unlink(missing_ok=True)
                if report.get("verified") is False:
                    notes.append(f"{role.label}: 변환본으로 패치해서 {role.result_name}의 지문이 공식 값과 달라요.")
            self._status("마무리 확인 중...")
            self._emit("done", True, results, out_dir, notes)
        except PatchError as exc:
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
        for role in ROLES:
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
