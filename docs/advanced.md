# 고급 사용 및 개발 안내

기본 사용법과 설치 순서는 [README](../README.md)를 먼저 확인하세요.

## 지원 입력 형식

| 입력 | 처리 |
| --- | --- |
| 복호화 CCI | 원본 검증 후 패치 |
| 본편 CIA | 필요하면 복호화하고 CCI로 변환한 뒤 패치 |
| 업데이트 CIA | 필요하면 복호화한 뒤 패치 |
| NCCH (`.app`, `.cxi`) | CCI로 감싸서 처리 |
| NCCH 암호화 CCI | 사용자 키 파일로 복호화. 시드 암호화는 해당 시드도 필요 |
| 일부 잘린 CCI | 지원 범위에서 크기를 보정하고 게임 영역 검증 |
| 카드 하드웨어 단계 암호화 이미지 | 지원하지 않음. 콘솔에서 지원 형식으로 덤프 필요 |

컨테이너의 헤더만 다른 호환 원본도 처리할 수 있지만, 게임 영역 검증을 통과해야 합니다. 파일 확장자만 바꾸거나 암호화 플래그만 바꾼 파일을 복호화된 원본으로 간주하지 않습니다.

## 키 파일이 필요한 경우

암호화 CIA는 일반적으로 자동 도구 경로를 사용할 수 있습니다. 암호화 CCI 등 내장 복호화 경로는 사용자가 준비한 키가 필요합니다. 앱이 표시한 필요한 키 슬롯과 시드 여부를 확인하세요.

앱의 **키 파일 (선택)**에서 `keys.txt` 또는 `aes_keys.txt`를 선택할 수 있습니다. 자동 검색 순서는 다음과 같습니다.

1. 앱에서 선택한 키 파일
2. `YW3KO_KEYS` 환경 변수가 가리키는 파일
3. 본편과 업데이트 파일의 폴더
4. 앱 캐시 폴더

지원하는 표기에는 `common`, `common0`~`common5`, `slot0x3DKeyX`, NCCH용 `slot0x2CKeyX` 등이 있습니다. `common0`~`common5`가 KeyY인 경우 `slot0x3DKeyX`와 함께 normal key를 계산합니다. 시드는 `seeddb.bin` 또는 `seed_<타이틀 ID>` 형식으로 읽습니다. 값은 실제 파일과 맞아야 합니다. 임의의 예시 값을 넣으면 복호화되지 않습니다.

키 값과 게임 파일은 공개 이슈에 첨부하지 마세요. 키 파일 없이 CIA를 처리할 수 있는지 먼저 확인하면 불필요한 수동 설정을 줄일 수 있습니다.

## 다운로드와 캐시

- 한글 패치: [제작팀 공식 배포 저장소](https://github.com/TeamLimRyan/YW3_SUKIYAKI_KOREAN_LOCALIZATION_RELEASE)의 지원 형식 릴리스에서 받습니다.
- CIA 자동 복호화: [Batch CIA 3DS Decryptor Redux](https://github.com/xxmichibxx/Batch-CIA-3DS-Decryptor-Redux)의 고정 버전 도구를 다운로드하고 SHA-256을 확인합니다. 배치 스크립트는 실행하지 않습니다.
- xdelta3: 공식 배포 파일을 다운로드하고 SHA-256을 확인합니다.
- 앱 업데이트: 이 저장소의 정식 릴리스에서 `YW3-KO-Patcher.exe`를 다운로드하고 크기·SHA-256을 확인합니다. 실행 파일 교체 전 사용자 동의를 받습니다.

기본 캐시 위치는 `%LOCALAPPDATA%\YW3KoPatcher`입니다. `YW3KO_CACHE` 환경 변수로 위치를 바꿀 수 있습니다. 앱의 **패치 데이터 새로 받기**는 캐시를 정리하고 다시 받는 기능입니다.

패치 버전은 배포 ZIP의 manifest에서 읽으며 버전·해시별로 캐시합니다. 최신 확인에 실패하면 사용할 캐시나 기본 지원 버전을 명시합니다. 지원하지 않는 새 배포 형식은 앱 업데이트를 안내하며, 구버전을 최신이라고 표시하지 않습니다.

## 검증과 파일 보존

패치 전에는 공식 원본의 게임 영역과 비교합니다. 기준 원본은 전체 결과 해시로, 호환 원본은 공식 완성본의 영역별 크기·SHA-256 및 내부 해시로 검증합니다. CIA는 TMD의 콘텐츠·목록 해시도 확인합니다.

CCI→CIA 변환에서는 게임 콘텐츠를 스트리밍으로 복사하고 TMD와 CIA 메타데이터를 구성합니다. v1.7.8은 TMD 최상위 해시·세이브 크기·메타데이터를 보완했습니다. [조사 기록 #43](https://github.com/spidychoipro/YW3-KO-Patcher/issues/43)

원본 CIA는 보호 잠금을 걸어 읽고, 변환용 임시 파일은 실행별 작업 폴더에서 처리합니다. 검증 실패 시 새 임시 결과를 정리합니다. 기존 결과 파일이 다른 프로그램에서 사용 중이면 변환 결과가 다른 이름으로 저장될 수 있으므로 완료 화면의 경로를 확인하세요.

파일 검증은 실제 게임 실행과 별개입니다. 에뮬레이터·실기에서의 확인 범위는 [README](../README.md)와 각 이슈에 기록합니다.

## 문제 신고에 필요한 정보

[이슈](https://github.com/spidychoipro/YW3-KO-Patcher/issues)에 앱 버전, 실행 환경, 오류가 발생한 단계, 오류 코드·화면, 본편과 한글 업데이트 설치 여부를 남겨 주세요. 진행 기록과 `diagnostic_*.txt`가 있으면 함께 확인할 수 있습니다. 개인 경로 등 공개를 원하지 않는 정보는 가려 주세요.

## 소스 실행과 빌드

Windows와 Python 3.10 이상을 기준으로 합니다. 내장 암호화 처리는 Windows CNG를 사용합니다.

```powershell
# 소스 실행
python .\yw3ko_patcher.py

# 관련 검사
python .\tools\test_cci_to_cia.py
python .\tools\test_format_regressions.py
python .\tools\test_updates.py
python .\tools\test_app_update.py

# 통합 점검: 네트워크 다운로드와 GUI 검사가 포함됨
python .\tools\smoke_test.py

# 실행 파일 빌드: dist\YW3-KO-Patcher.exe
pwsh -File .\build.ps1
```

| 파일 | 역할 |
| --- | --- |
| `yw3ko_patcher.py` | GUI·패치 실행 흐름 |
| `yw3convert.py` | 컨테이너 변환·복호화·CCI→CIA 생성 |
| `yw3profile.py`, `yw3verify.py` | 게임 영역과 내부 해시 검증 |
| `yw3updates.py` | 한글 패치 배포본 확인 |
| `yw3appupdate.py` | 앱 자체 업데이트 |
| `yw3external.py` | 외부 CIA 처리 도구 관리 |
| `build.ps1` | PyInstaller 빌드 |

버전별 변경 내역은 [CHANGELOG](../CHANGELOG.md)에 기록합니다.
