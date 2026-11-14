$ErrorActionPreference = "Stop"

$Repo = "RenegadeImmortal-777/Kovrek"
$Asset = "kovrek-native-windows-x86_64.exe"
$KovrekHome = if ($env:KOVREK_HOME) { $env:KOVREK_HOME } else { Join-Path $env:LOCALAPPDATA "Kovrek" }
$BinDir = Join-Path $KovrekHome "bin"
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

$Url = if ($env:KOVREK_VERSION) {
    "https://github.com/$Repo/releases/download/$($env:KOVREK_VERSION)/$Asset"
} else {
    "https://github.com/$Repo/releases/latest/download/$Asset"
}

$NativeExe = Join-Path $BinDir "kovrek-native.exe"
$PrimaryExe = Join-Path $KovrekHome "kovrek.exe"
$TmpExe = Join-Path $BinDir "kovrek-download.tmp.exe"

Write-Host "Downloading $Asset from $Url ..."
Invoke-WebRequest -Uri $Url -OutFile $TmpExe -UseBasicParsing
Move-Item -Force $TmpExe $NativeExe
Copy-Item -Force $NativeExe $PrimaryExe

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
$Parts = if ($UserPath) { $UserPath -split ";" | Where-Object { $_ -ne "" } } else { @() }
if ($Parts -notcontains $KovrekHome) {
    $NewPath = (($Parts + $KovrekHome) -join ";").Trim(";")
    [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
    $env:Path = "$KovrekHome;$env:Path"
}

$Ver = & $PrimaryExe --version
Write-Host ""
Write-Host "Installed $Ver to $PrimaryExe"
Write-Host "Open a new terminal (or run directly in this session): kovrek --version"
