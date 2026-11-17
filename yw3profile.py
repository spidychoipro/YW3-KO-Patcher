"""공식 배포본 manifest.json의 게임 영역 해시.

패치 적용 전에 사용자가 가진 원본이 제작팀이 기준으로 삼은 파일과 같은지
확인하는 데만 쓴다. 게임 데이터나 키는 들어 있지 않고, 해시와 크기만 있다.

출처: YW3S_Korean_Patch_v1.01.zip 안의 manifest.json
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RegionSpec:
    name: str
    size: int
    sha256: str


@dataclass(frozen=True)
class PartSpec:
    index: int
    program_id: int
    product_code: str
    regions: tuple[RegionSpec, ...]


@dataclass(frozen=True)
class Profile:
    role: str
    parts: tuple[PartSpec, ...]


BASE_SOURCE = Profile(
    role="base",
    parts=(
        PartSpec(
            index=0,
            program_id=0x00040000001AF400,
            product_code="CTR-P-ALZJ",
            regions=(
                RegionSpec("exheader", 1024,
                           "a12dcccc3429f6fb3831974c2404e2032856a5d9897e466b959705f05913fc9b"),
                RegionSpec("plain", 1024,
                           "d17aa4997f05df571ab57529834fa854284f2c7a58448c25fd2a1562dcc72db0"),
                RegionSpec("logo", 8192,
                           "dd8c470edf60553b03fd5a42304923b47625409ae04d61a3208122547edc5150"),
                RegionSpec("exefs", 5203968,
                           "b6038c2f99ac1711fe0a8b60f18babb047ecfe75652b553b08c00fd068bdbf0d"),
                RegionSpec("romfs", 3263385600,
                           "fab26380166713d44e56590ad0749bf420a890b20034fbc49c930a7b86a6544c"),
            ),
        ),
        PartSpec(
            index=1,
            program_id=0x00040000001AF400,
            product_code="CTR-P-CTAP",
            regions=(
                RegionSpec("romfs", 2236416,
                           "96d7e21884c8bee5093ba9b00500f434677afecf67cb51b8c51a5e0f0f6a21e8"),
            ),
        ),
    ),
)

UPDATE_SOURCE = Profile(
    role="update",
    parts=(
        PartSpec(
            index=0,
            program_id=0x0004000E001AF400,
            product_code="CTR-U-ALZJ",
            regions=(
                RegionSpec("exheader", 1024,
                           "5d0cab8f19417c39d5126269954a4b65a407ac2c295a5db5772edf15805d8e34"),
                RegionSpec("plain", 1024,
                           "d17aa4997f05df571ab57529834fa854284f2c7a58448c25fd2a1562dcc72db0"),
                RegionSpec("logo", 8192,
                           "dd8c470edf60553b03fd5a42304923b47625409ae04d61a3208122547edc5150"),
                RegionSpec("exefs", 4918784,
                           "093132501f6a04995f2374496ca69ded367c736a6f251ea1d0d49a27d3f21189"),
                RegionSpec("romfs", 189202432,
                           "93f9f6399527cb5e738781b7160dd363ce8d274f6de7f80a7ca18d2c75aacbdc"),
            ),
        ),
        PartSpec(
            index=1,
            program_id=0x0004000E001AF400,
            product_code="CTR-P-CTAP",
            regions=(
                RegionSpec("romfs", 2240512,
                           "552a8cbb6302de88f6d9299d9bb55c6063dfacd63a6d0deebc96ecb064cc6c83"),
            ),
        ),
    ),
)

PROFILES = {
    "base": BASE_SOURCE,
    "update": UPDATE_SOURCE,
}


# 같은 공식 manifest의 원본 전체 해시와 완성본 게임 영역 프로필.
SOURCE_SHA256 = {'base': 'd98a9430f3edc0b25fc1a4e0d147d0b976db1b0bdce8e042c50f0e84a738f4d8', 'update': '95d5e28eb4920a68bfc3c0ae407a308ddc06a11ab229da3d28cfa4976af58082'}

TARGET_PROFILES = {
    'base': Profile('base', (
        PartSpec(0, 0x00040000001af400, 'CTR-P-ALZJ', (
            RegionSpec('exheader', 1024,
                       'a12dcccc3429f6fb3831974c2404e2032856a5d9897e466b959705f05913fc9b'),
            RegionSpec('plain', 1024,
                       'd17aa4997f05df571ab57529834fa854284f2c7a58448c25fd2a1562dcc72db0'),
            RegionSpec('logo', 8192,
                       'dd8c470edf60553b03fd5a42304923b47625409ae04d61a3208122547edc5150'),
            RegionSpec('exefs', 5203968,
                       'b275984094a8e45428a0ffbc0ecc0bfad00c0ecb937f8a6af62345bdbf24f59b'),
            RegionSpec('romfs', 3271237632,
                       'e323da87861d558a6445644052800599fee384225416bfce45fe1006806d0f08'),
        )),
        PartSpec(1, 0x00040000001af400, 'CTR-P-CTAP', (
            RegionSpec('romfs', 2236416,
                       '96d7e21884c8bee5093ba9b00500f434677afecf67cb51b8c51a5e0f0f6a21e8'),
        )),
    )),
    'update': Profile('update', (
        PartSpec(0, 0x0004000e001af400, 'CTR-U-ALZJ', (
            RegionSpec('exheader', 1024,
                       '5d0cab8f19417c39d5126269954a4b65a407ac2c295a5db5772edf15805d8e34'),
            RegionSpec('plain', 1024,
                       'd17aa4997f05df571ab57529834fa854284f2c7a58448c25fd2a1562dcc72db0'),
            RegionSpec('logo', 8192,
                       'dd8c470edf60553b03fd5a42304923b47625409ae04d61a3208122547edc5150'),
            RegionSpec('exefs', 4918784,
                       '0c90a8a9c305938f7d4abb37f20c5a42f628c184667004d0c52b3212a0f75ace'),
            RegionSpec('romfs', 189100032,
                       '2775eda77680c6f1ee4811068e1b25134d6eb324303006f8860834dd29446e6e'),
        )),
        PartSpec(1, 0x0004000e001af400, 'CTR-P-CTAP', (
            RegionSpec('romfs', 2240512,
                       '552a8cbb6302de88f6d9299d9bb55c6063dfacd63a6d0deebc96ecb064cc6c83'),
        )),
    )),
}
