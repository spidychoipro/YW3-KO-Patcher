"""Resolve official patch releases and their version-specific verification data."""
from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

import yw3profile as profiles

REPO = "TeamLimRyan/YW3_SUKIYAKI_KOREAN_LOCALIZATION_RELEASE"
LATEST_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
XDELTA_SHA256 = "732980d52f9220dc81817ccdd0c295eadce8a0048a24c2a771a73f791ac824e9"
FORMAT = "VCDIFF (xdelta3); no application header, secondary compression or armor"


class UpdateError(Exception):
    """Official release exists but cannot be applied by this app."""


@dataclass(frozen=True)
class PatchSpec:
    key: str
    patch_name: str
    patch_size: int
    patch_sha256: str
    result_name: str
    result_size: int
    result_sha256: str
    source_size: int
    source_profile: profiles.Profile


@dataclass(frozen=True)
class Bundle:
    version: str
    archive: Path
    patches: tuple[PatchSpec, ...]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _hash(value) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise ValueError("SHA-256 값이 없거나 잘못됐습니다")
    return value.lower()


def _size(value) -> int:
    if type(value) is not int or not 0 < value <= 64 * 1024**3:
        raise ValueError("파일 크기가 없거나 지원 범위를 벗어납니다")
    return value


def _filename(value, extension: str) -> str:
    if (not isinstance(value, str) or not value.endswith(extension)
            or any(c in value for c in '/\\:<>"|?*') or value in (".", "..")
            or value.endswith((" ", "."))):
        raise ValueError("파일명이 지원되지 않습니다")
    return value


def _profile(data: dict, key: str) -> profiles.Profile:
    if data["role"] != key:
        raise ValueError("원본 프로필 역할이 다릅니다")
    parts = []
    for part in data["parts"]:
        index = part["index"]
        if type(index) is not int or not 0 <= index < 8 or index in [p.index for p in parts]:
            raise ValueError("파티션 번호가 잘못됐습니다")
        if not re.fullmatch(r"[0-9a-fA-F]{16}", part["program_id"]):
            raise ValueError("프로그램 ID가 잘못됐습니다")
        regions = tuple(profiles.RegionSpec(r["name"], _size(r["size"]), _hash(r["sha256"]))
                        for r in part["regions"])
        names = [r.name for r in regions]
        if (not names or len(set(names)) != len(names)
                or set(names) - {"exheader", "plain", "logo", "exefs", "romfs"}):
            raise ValueError("게임 영역 목록이 지원되지 않습니다")
        parts.append(profiles.PartSpec(index, int(part["program_id"], 16),
                                      str(part["product_code"]), regions))
    main = next((p for p in parts if p.index == 0), None)
    expected_id = 0x00040000001AF400 if key == "base" else 0x0004000E001AF400
    if (main is None or main.program_id != expected_id
            or not {"exefs", "romfs"} <= {r.name for r in main.regions}):
        raise ValueError("지원하는 스키야키 원본 프로필이 아닙니다")
    return profiles.Profile(key, tuple(parts))


def read_manifest(archive: Path, version: str) -> Bundle:
    try:
        with zipfile.ZipFile(archive) as bundle:
            manifests = [i for i in bundle.infolist() if Path(i.filename).name == "manifest.json"]
            if len(manifests) != 1 or manifests[0].file_size > 1024 * 1024:
                raise ValueError("manifest.json이 없거나 중복/과대 크기입니다")
            data = json.loads(bundle.read(manifests[0]).decode("utf-8-sig"))
            if (data["package_version"] != version or data["format"] != FORMAT
                    or data["xdelta_version"] != "3.2.2"
                    or _hash(data["xdelta_sha256"]) != XDELTA_SHA256):
                raise ValueError("패키지 버전 또는 xdelta 형식이 지원되지 않습니다")
            specs = []
            for patch in data["patches"]:
                key = patch["role"]
                if key not in ("base", "update") or key in [s.key for s in specs]:
                    raise ValueError("패치 역할이 누락되거나 중복됐습니다")
                name = _filename(patch["patch_file"], ".xdelta")
                size = _size(patch["patch_size"])
                members = [i for i in bundle.infolist() if Path(i.filename).name == name]
                if len(members) != 1 or members[0].file_size != size:
                    raise ValueError("패치 파일이 없거나 크기가 다릅니다")
                specs.append(PatchSpec(key, name, size, _hash(patch["patch_sha256"]),
                    _filename(patch["target_file"], ".cci" if key == "base" else ".cia"),
                    _size(patch["target_size"]), _hash(patch["target_sha256"]),
                    _size(patch["source_size"]), _profile(patch["source_profile"], key)))
            if {s.key for s in specs} != {"base", "update"}:
                raise ValueError("본편/업데이트 패치 정보가 모두 필요합니다")
        return Bundle(version, archive, tuple(sorted(specs, key=lambda s: s.key)))
    except (KeyError, TypeError, ValueError, OSError, RuntimeError, NotImplementedError,
            zipfile.BadZipFile) as exc:
        raise UpdateError(f"한글 패치 {version}의 배포 형식을 지원하지 못합니다: {exc}\n"
                          "구버전 패치를 대신 적용하지 않았습니다. 앱 업데이트를 확인해 주세요.") from exc


def fetch_latest() -> dict:
    request = urllib.request.Request(LATEST_URL, headers={
        "User-Agent": "YW3KoPatcher", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=15) as response:
        raw = response.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise UpdateError("공식 릴리스 응답이 너무 큽니다")
    try:
        return json.loads(raw)
    except ValueError as exc:
        raise UpdateError("공식 릴리스 정보를 읽지 못했습니다") from exc


def _asset(release: dict) -> tuple[str, dict, str]:
    try:
        version = release["tag_name"]
        if (not isinstance(version, str) or not re.fullmatch(r"v?\d+(?:\.\d+){1,3}", version)
                or release.get("draft") or release.get("prerelease")):
            raise ValueError("정식 버전 태그가 아닙니다")
        assets = [a for a in release["assets"]
                  if re.fullmatch(r"YW3S_Korean_Patch_[^/\\]+\.zip", a["name"])]
        if len(assets) != 1:
            raise ValueError("공식 패치 ZIP을 하나로 식별하지 못했습니다")
        asset = assets[0]
        _size(asset["size"])
        url = urllib.parse.urlsplit(asset["browser_download_url"])
        prefix = f"/{REPO}/releases/download/{version}/"
        if url.scheme != "https" or url.netloc != "github.com" or not url.path.startswith(prefix):
            raise ValueError("공식 저장소의 다운로드 주소가 아닙니다")
        digest = asset["digest"]
        if not isinstance(digest, str) or not digest.startswith("sha256:"):
            raise ValueError("공식 ZIP의 SHA-256 정보가 없습니다")
        return version, asset, _hash(digest[7:])
    except (KeyError, TypeError, ValueError) as exc:
        raise UpdateError(f"공식 최신 릴리스를 지원하지 못합니다: {exc}\n"
                          "구버전 패치를 대신 적용하지 않았습니다.") from exc


def resolve(cache: Path, download, log, progress=None) -> tuple[Bundle | None, str]:
    """Only a network failure allows offline fallback; unsupported releases stop."""
    folder = cache / "releases"
    folder.mkdir(parents=True, exist_ok=True)
    metadata = folder / "latest.json"
    offline = False
    try:
        release = fetch_latest()
    except (OSError, urllib.error.URLError) as exc:
        offline = True
        log(f"최신 한글 패치 확인 실패: {exc}")
        if not metadata.is_file():
            return None, "최신 확인 실패 · 기본 지원 한글 패치 v1.01 사용"
        try:
            release = json.loads(metadata.read_text(encoding="utf-8"))
        except (OSError, ValueError) as err:
            raise UpdateError("저장된 패치 버전 정보를 읽지 못했습니다. 네트워크를 확인해 주세요.") from err
    # Remember a newer unsupported release as well; do not silently downgrade next time.
    if not offline:
        temp = metadata.with_suffix(".part")
        temp.write_text(json.dumps(release, ensure_ascii=False), encoding="utf-8")
        temp.replace(metadata)
    version, asset, digest = _asset(release)
    archive = folder / version / digest / "package.zip"
    if not archive.is_file() or archive.stat().st_size != _size(asset["size"]) or sha256(archive) != digest:
        if offline:
            raise UpdateError(f"최신 확인 실패 · 저장된 {version} 패키지를 검증할 수 없습니다.\n"
                              "인터넷 연결 후 다시 시도해 주세요.")
        archive.parent.mkdir(parents=True, exist_ok=True)
        log(f"한글 패치 {version} 공식 패키지를 내려받습니다")
        download(asset["browser_download_url"], archive, progress)
        if archive.stat().st_size != _size(asset["size"]) or sha256(archive) != digest:
            archive.unlink(missing_ok=True)
            raise UpdateError("내려받은 공식 패키지의 크기 또는 SHA-256이 다릅니다")
    bundle = read_manifest(archive, version)
    label = (f"최신 확인 실패 · 저장된 한글 패치 {version} 사용" if offline
             else f"공식 최신 한글 패치 {version}")
    log(label)
    return bundle, label
