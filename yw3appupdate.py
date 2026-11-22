"""앱 자체 업데이트 확인과 사용자 동의 후 설치.

패치 데이터용 저장소(yw3updates)와는 다른, 앱 본인 저장소의 릴리스를 본다.
새 버전을 찾아도 자동으로 갈아끼우지 않고 물어본 뒤에만 설치한다.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

APP_REPO = "spidychoipro/YW3-KO-Patcher"
LATEST_URL = f"https://api.github.com/repos/{APP_REPO}/releases/latest"
ASSET_NAME = "YW3-KO-Patcher.exe"
MAX_ASSET_SIZE = 200 * 1024 * 1024
CREATE_NO_WINDOW = 0x08000000
HASH_BLOCK = 8 * 1024 * 1024

# PyInstaller onefile 부트로더가 자식 프로세스에 물려주는 환경변수.
# 이게 남아 있으면 새 exe가 이미 지워진 _MEI... 임시 폴더에서 python DLL을
# 찾으려다 "Failed to load Python DLL" 창을 띄운다. updater와 그 자식에서
# 모두 지워야 한다.
PYI_ENV_VARS = (
    "_PYI_ARCHIVE_FILE",
    "_PYI_APPLICATION_HOME_DIR",
    "_PYI_PARENT_PROCESS_LEVEL",
    "_MEIPASS2",
)

VERSION_RE = re.compile(r"v?(\d+(?:\.\d+){1,3})")
HEX_RE = re.compile(r"[0-9a-f]{64}")
URL_PREFIX = f"/{APP_REPO}/releases/download/"


class AppUpdateError(Exception):
    """앱 업데이트 확인/설정 중 사용자에게 알려줄 만한 문제."""


@dataclass(frozen=True)
class AppRelease:
    version: str
    tag: str
    size: int
    digest: str
    url: str
    page: str


def parse_version(value: str) -> tuple[int, int, int]:
    match = VERSION_RE.fullmatch(str(value).strip())
    if not match:
        raise AppUpdateError(f"버전 형식을 읽지 못했습니다: {value}")
    parts = [int(part) for part in match.group(1).split(".")]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])  # type: ignore[return-value]


def is_newer(current: str, found: str) -> bool:
    return parse_version(found) > parse_version(current)


def _hash(value: object) -> str:
    if not isinstance(value, str) or not HEX_RE.fullmatch(value.lower()):
        raise AppUpdateError("공식 릴리스의 SHA-256 정보가 올바르지 않습니다")
    return value.lower()


def _size(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value > MAX_ASSET_SIZE:
        raise AppUpdateError("공식 설치 파일의 크기가 올바르지 않습니다")
    return value


def parse_release(data: object) -> AppRelease:
    """API 응답에서 정식 릴리스의 EXE 하나만 안전하게 뽑는다."""
    try:
        if not isinstance(data, dict):
            raise ValueError("릴리스 정보가 아닙니다")
        if data.get("draft") or data.get("prerelease"):
            raise ValueError("시험용 릴리스는 설치하지 않습니다")
        tag = data["tag_name"]
        if not isinstance(tag, str) or not VERSION_RE.fullmatch(tag.strip()):
            raise ValueError("정식 버전 태그가 아닙니다")
        tag = tag.strip()
        version = parse_version(tag)
        assets = data.get("assets")
        if not isinstance(assets, list):
            raise ValueError("첨부 파일 목록이 없습니다")
        matches = [a for a in assets if isinstance(a, dict) and a.get("name") == ASSET_NAME]
        if len(matches) != 1:
            raise ValueError(f"{ASSET_NAME} 첨부 파일을 하나로 찾지 못했습니다")
        asset = matches[0]
        size = _size(asset.get("size"))
        digest = _hash(str(asset.get("digest", "")).removeprefix("sha256:"))
        url = asset.get("browser_download_url")
        parsed = urllib.parse.urlsplit(url) if isinstance(url, str) else None
        if (parsed is None or parsed.scheme != "https" or parsed.netloc != "github.com"
                or not parsed.path.startswith(f"{URL_PREFIX}{tag}/")):
            raise ValueError("공식 저장소의 다운로드 주소가 아닙니다")
        version_text = ".".join(str(part) for part in version)
        return AppRelease(
            version=version_text,
            tag=tag,
            size=size,
            digest=digest,
            url=url,
            page=f"https://github.com/{APP_REPO}/releases/tag/{tag}",
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise AppUpdateError(f"공식 앱 릴리스를 지원하지 못합니다: {exc}") from exc


def fetch_latest(opener=None) -> dict:
    open_url = opener or urllib.request.urlopen
    request = urllib.request.Request(LATEST_URL, headers={
        "User-Agent": "YW3KoPatcher", "Accept": "application/vnd.github+json"})
    with open_url(request, timeout=15) as response:
        raw = response.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise AppUpdateError("공식 릴리스 응답이 너무 큽니다")
    try:
        return json.loads(raw)
    except ValueError as exc:
        raise AppUpdateError("공식 릴리스 정보를 읽지 못했습니다") from exc


def check(current: str, fetch=None) -> AppRelease | None:
    """새 정식 버전이 있으면 그 정보, 없으면 None을 돌려준다."""
    data = (fetch or fetch_latest)()
    release = parse_release(data)
    return release if is_newer(current, release.version) else None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(HASH_BLOCK)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest().lower()


def staged_path(cache: Path, release: AppRelease) -> Path:
    return cache / "app-updates" / release.version / release.digest[:16] / ASSET_NAME


def prune_stale_downloads(cache: Path, keep_version: str) -> None:
    root = cache / "app-updates"
    if not root.is_dir():
        return
    for entry in root.iterdir():
        if entry.is_dir() and entry.name != keep_version:
            shutil.rmtree(entry, ignore_errors=True)


def prepare_download(cache: Path, release: AppRelease, download, log=lambda _: None,
                     progress=None) -> Path:
    """공식 첨부 파일을 검증해서 캐시에 준비한다."""
    prune_stale_downloads(cache, release.version)
    dest = staged_path(cache, release)
    dest.parent.mkdir(parents=True, exist_ok=True)

    def valid() -> bool:
        return (dest.is_file() and dest.stat().st_size == release.size
                and sha256_file(dest) == release.digest)

    if valid():
        log(f"이미 받아 둔 앱 업데이트 {release.version}을 씁니다")
        return dest
    dest.unlink(missing_ok=True)
    log(f"앱 새 버전 {release.version}을 내려받습니다 ({release.size // (1024 * 1024)}MB)")
    download(release.url, dest, progress)
    if not valid():
        dest.unlink(missing_ok=True)
        raise AppUpdateError("내려받은 설치 파일의 크기 또는 SHA-256이 다릅니다")
    return dest


def can_self_update() -> bool:
    """배포용 Windows exe일 때만 자기 파일을 바꿀 수 있다."""
    return sys.platform == "win32" and bool(getattr(sys, "frozen", False))


UPDATER_SCRIPT = r'''param(
    [string]$Target,
    [string]$Source,
    [int]$ParentPid,
    [string]$ReleaseUrl,
    [string]$Log
)
$ErrorActionPreference = 'Stop'
foreach ($name in @('_PYI_ARCHIVE_FILE', '_PYI_APPLICATION_HOME_DIR', '_PYI_PARENT_PROCESS_LEVEL', '_MEIPASS2')) {
    Remove-Item "Env:$name" -ErrorAction SilentlyContinue
}
function Write-UpdaterLog([string]$Message) {
    if (-not $Log) { return }
    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -LiteralPath $Log -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
}
$backup = $null
try {
    Write-UpdaterLog "앱 업데이트 시작"
    if ($ParentPid -gt 0) {
        $proc = Get-Process -Id $ParentPid -ErrorAction SilentlyContinue
        while ($null -ne $proc) {
            Start-Sleep -Milliseconds 200
            $proc = Get-Process -Id $ParentPid -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Milliseconds 400
    $backup = "$Target.old"
    if (Test-Path -LiteralPath $backup) {
        Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
    }
    Move-Item -LiteralPath $Target -Destination $backup -Force
    Copy-Item -LiteralPath $Source -Destination $Target -Force
    Write-UpdaterLog "새 버전 설치 완료"
    Start-Process -FilePath $Target -WorkingDirectory (Split-Path -Parent $Target)
    Remove-Item -LiteralPath $Source -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $backup) {
        Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
    }
} catch {
    Write-UpdaterLog "실패: $($_.Exception.Message)"
    if ($backup -and (Test-Path -LiteralPath $backup) -and -not (Test-Path -LiteralPath $Target)) {
        Move-Item -LiteralPath $backup -Destination $Target -Force -ErrorAction SilentlyContinue
        Write-UpdaterLog "이전 버전 복구"
    }
    if ($ReleaseUrl) {
        Start-Process $ReleaseUrl
    }
} finally {
    Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue
}
'''


def launch_updater(cache: Path, target: Path, source: Path, release: AppRelease,
                   parent_pid: int | None = None,
                   log_path: Path | None = None) -> subprocess.Popen:
    """앱이 종료된 뒤 파일을 바꾸고 다시 여는 별도 프로세스를 띄운다."""
    if not can_self_update():
        raise AppUpdateError("배포용 exe에서만 자동 설치할 수 있습니다")
    if parent_pid is None:
        parent_pid = os.getpid()
    script = cache / "app-updates" / "updater.ps1"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text(UPDATER_SCRIPT, encoding="utf-8")
    log_path = log_path or script.parent / "updater.log"
    args = [
        "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden",
        "-File", str(script),
        "-Target", str(target),
        "-Source", str(source),
        "-ParentPid", str(parent_pid),
        "-ReleaseUrl", release.page,
        "-Log", str(log_path),
    ]
    env = os.environ.copy()
    for name in PYI_ENV_VARS:
        env.pop(name, None)
    # DETACHED_PROCESS를 같이 쓰면 PowerShell이 조용히 종료되는 경우가 있어
    # CREATE_NO_WINDOW만 쓴다. 부모가 끝나도 자식 프로세스는 그대로 남는다.
    return subprocess.Popen(args, creationflags=CREATE_NO_WINDOW, close_fds=True, env=env)
