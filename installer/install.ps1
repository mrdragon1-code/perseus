# PERSEUS — installazione per l'utente corrente (nessun privilegio amministratore).
# Uso: doppio clic su install.cmd, oppure
#   powershell -ExecutionPolicy Bypass -File install.ps1 [-NoShellMenu] [-DesktopShortcut]
param([switch]$NoShellMenu, [switch]$DesktopShortcut)
$ErrorActionPreference = "Stop"

$src  = Join-Path $PSScriptRoot "app"
$dest = Join-Path $env:LOCALAPPDATA "Programs\Perseus"
$exe  = Join-Path $dest "Perseus.exe"

if (-not (Test-Path (Join-Path $src "Perseus.exe"))) {
    throw "Cartella 'app' non trovata accanto a install.ps1: estrai tutto lo zip prima di installare."
}
if ([Environment]::OSVersion.Version.Major -lt 10 -or -not [Environment]::Is64BitOperatingSystem) {
    throw "Serve Windows 10/11 a 64 bit."
}

$running = Get-Process -Name Perseus -ErrorAction SilentlyContinue
if ($running) {
    Write-Host "Chiudo PERSEUS in esecuzione..."
    $running | Stop-Process -Force
    Start-Sleep -Milliseconds 500
}

Write-Host "Installo in $dest"
New-Item -ItemType Directory -Force $dest | Out-Null
Copy-Item -Path (Join-Path $src "*") -Destination $dest -Recurse -Force
Copy-Item -Path (Join-Path $PSScriptRoot "uninstall.ps1") -Destination $dest -Force

# Collegamenti
$shell = New-Object -ComObject WScript.Shell
function New-Link($path) {
    $l = $shell.CreateShortcut($path)
    $l.TargetPath = $exe
    $l.WorkingDirectory = $dest
    $l.Description = "PERSEUS - controllo accessi e vault"
    $l.Save()
}
New-Link (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\PERSEUS.lnk")
if ($DesktopShortcut) { New-Link (Join-Path ([Environment]::GetFolderPath("Desktop")) "PERSEUS.lnk") }

# Menu tasto destro sulle cartelle
if (-not $NoShellMenu) {
    Start-Process -FilePath $exe -ArgumentList "--register-shell" -Wait
    Write-Host "Menu tasto destro attivato (Windows 11: 'Mostra altre opzioni')."
}

# Voce in "App installate" per disinstallare
$key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Perseus"
New-Item -Path $key -Force | Out-Null
$ver = (Get-Item $exe).VersionInfo.ProductVersion
Set-ItemProperty $key DisplayName "PERSEUS"
Set-ItemProperty $key DisplayVersion "$ver"
Set-ItemProperty $key DisplayIcon "$exe,0"
Set-ItemProperty $key InstallLocation $dest
Set-ItemProperty $key NoModify 1 -Type DWord
Set-ItemProperty $key NoRepair 1 -Type DWord
Set-ItemProperty $key UninstallString "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$dest\uninstall.ps1`""

Write-Host ""
Write-Host "PERSEUS installato. Avvialo dal menu Start; al primo avvio crea la password." -ForegroundColor Cyan
Write-Host "ATTENZIONE: la password e' l'unico modo per recuperare i file cifrati." -ForegroundColor Yellow
