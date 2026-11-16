# Crea dist\Perseus-<versione>-win-x64.zip (app self-contained + installer).
#   .\scripts\package.ps1 -Version 0.1.0
param([string]$Version = "0.1.0")
$ErrorActionPreference = "Continue"   # i tool nativi scrivono su stderr: si controlla $LASTEXITCODE
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    cargo test -p perseus-core --release
    if ($LASTEXITCODE -ne 0) { throw "test Rust falliti" }
    cargo build -p perseus-core --release
    if ($LASTEXITCODE -ne 0) { throw "build Rust fallita" }

    $stage = Join-Path $root "dist\stage"
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    dotnet publish app/Perseus.App.csproj -c Release -r win-x64 --self-contained true `
        -p:Version=$Version -p:SkipCargo=true -o (Join-Path $stage "app")
    if ($LASTEXITCODE -ne 0) { throw "publish WPF fallito" }
    Copy-Item target/release/perseus_core.dll (Join-Path $stage "app") -Force
    Copy-Item installer/* $stage -Force

    $zip = Join-Path $root "dist\Perseus-$Version-win-x64.zip"
    Remove-Item $zip -Force -ErrorAction SilentlyContinue
    Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip -CompressionLevel Optimal
    Write-Host "Pacchetto: $zip"
} finally { Pop-Location }
