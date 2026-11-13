# 요괴워치3 스키야키 한국어 패치 적용기 빌드 스크립트
# 사용법:  pwsh -File .\build.ps1
param(
    [switch]$NoInstall
)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

if (-not $NoInstall) {
    python -m pip install --disable-pip-version-check --quiet pyinstaller
}

python .\tools\make_icon.py .\build\app.ico

$arguments = @(
    '--noconfirm'
    '--clean'
    '--onefile'
    '--windowed'
    '--name', 'YW3-KO-Patcher'
    '--icon', (Join-Path $PSScriptRoot 'build\app.ico')
    '--workpath', (Join-Path $PSScriptRoot 'build\pyi')
    '--specpath', (Join-Path $PSScriptRoot 'build')
    '--distpath', (Join-Path $PSScriptRoot 'dist')
    (Join-Path $PSScriptRoot 'yw3ko_patcher.py')
)

python -m PyInstaller @arguments

$exe = Join-Path $PSScriptRoot 'dist\YW3-KO-Patcher.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw "빌드 결과가 없습니다: $exe" }
$size = [math]::Round((Get-Item -LiteralPath $exe).Length / 1MB, 1)
Write-Host "빌드 완료: $exe ($size MB)"
