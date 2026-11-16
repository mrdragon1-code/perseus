# PERSEUS — disinstallazione.
# NON cancella %LOCALAPPDATA%\Perseus (chiave cifrata, config): senza quella i file .prs
# non si possono piu' decifrare. Decifra le cartelle prima di disinstallare, oppure usa -PurgeData.
param([switch]$PurgeData)
$ErrorActionPreference = "Continue"

$dest = Join-Path $env:LOCALAPPDATA "Programs\Perseus"
$exe  = Join-Path $dest "Perseus.exe"
$data = Join-Path $env:LOCALAPPDATA "Perseus"

Get-Process -Name Perseus -ErrorAction SilentlyContinue | Stop-Process -Force
if (Test-Path $exe) { Start-Process -FilePath $exe -ArgumentList "--unregister-shell" -Wait }
Remove-Item "HKCU:\Software\Classes\Directory\shell\Perseus" -Recurse -Force -ErrorAction SilentlyContinue

Remove-Item (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\PERSEUS.lnk") -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path ([Environment]::GetFolderPath("Desktop")) "PERSEUS.lnk") -Force -ErrorAction SilentlyContinue
Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Perseus" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $dest -Recurse -Force -ErrorAction SilentlyContinue

if ($PurgeData) {
    $ans = Read-Host "Cancellare DEFINITIVAMENTE $data ? I file ancora cifrati diventeranno irrecuperabili. Scrivi CANCELLA per confermare"
    if ($ans -ceq "CANCELLA") { Remove-Item $data -Recurse -Force; Write-Host "Dati rimossi." }
} else {
    Write-Host "Programma rimosso. I dati restano in $data (servono per decifrare i file .prs)."
}
