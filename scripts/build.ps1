# Compila core Rust + app WPF e avvia i test.
#   .\scripts\build.ps1            (Release)
#   .\scripts\build.ps1 -Run       (compila e avvia)
param([switch]$Run, [string]$Configuration = "Release")
$ErrorActionPreference = "Continue"   # i tool nativi scrivono su stderr: si controlla $LASTEXITCODE
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    cargo test -p perseus-core --release
    if ($LASTEXITCODE -ne 0) { throw "test Rust falliti" }
    dotnet build app/Perseus.App.csproj -c $Configuration
    if ($LASTEXITCODE -ne 0) { throw "build WPF fallita" }
    if ($Run) { & "app/bin/$Configuration/net10.0-windows/Perseus.exe" }
} finally { Pop-Location }
