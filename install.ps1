$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Repo = "RenegadeImmortal-777/Kovrek"
$Asset = "kovrek-native-windows-x86_64.exe"
$KovrekHome = if ($env:KOVREK_HOME) { $env:KOVREK_HOME } else { Join-Path $env:LOCALAPPDATA "Kovrek" }
$BinDir = Join-Path $KovrekHome "bin"
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

if ($env:KOVREK_VERSION) {
    if ($env:KOVREK_VERSION -notmatch '^v[A-Za-z0-9._-]+$' -or $env:KOVREK_VERSION -match '\.\.') {
        throw "Invalid KOVREK_VERSION '$($env:KOVREK_VERSION)'."
    }
    $BaseUrl = "https://github.com/$Repo/releases/download/$($env:KOVREK_VERSION)"
} else {
    $BaseUrl = "https://github.com/$Repo/releases/latest/download"
}

$Url = "$BaseUrl/$Asset"
$SumsUrl = "$BaseUrl/SHA256SUMS.txt"

$NativeExe = Join-Path $BinDir "kovrek-native.exe"
$PrimaryExe = Join-Path $KovrekHome "kovrek.exe"
$Nonce = [Guid]::NewGuid().ToString("N")
$TmpExe = Join-Path $BinDir "kovrek-download-$Nonce.tmp.exe"
$TmpSums = Join-Path $BinDir "SHA256SUMS-$Nonce.txt"

try {
    Write-Host "Downloading $Asset and SHA256SUMS.txt from $BaseUrl ..."
    Invoke-WebRequest -Uri $Url -OutFile $TmpExe -UseBasicParsing
    Invoke-WebRequest -Uri $SumsUrl -OutFile $TmpSums -UseBasicParsing

    $ExpectedHash = $null
    foreach ($Line in Get-Content -Path $TmpSums) {
        if ($Line -match '^\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*$') {
            $HashCandidate = $Matches[1].ToLowerInvariant()
            $NameCandidate = $Matches[2] -replace '^\./', ''
            if ($NameCandidate -eq $Asset) {
                $ExpectedHash = $HashCandidate
                break
            }
        }
    }
    if (-not $ExpectedHash) {
        throw "Could not find SHA-256 checksum entry for '$Asset' in SHA256SUMS.txt."
    }

    $ActualHash = (Get-FileHash -Path $TmpExe -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ActualHash -ne $ExpectedHash) {
        throw "SHA-256 verification failed for $Asset (expected $ExpectedHash, got $ActualHash)."
    }

    Move-Item -Force $TmpExe $NativeExe
    Copy-Item -Force $NativeExe $PrimaryExe
} finally {
    if (Test-Path $TmpExe) { Remove-Item -Force $TmpExe -ErrorAction SilentlyContinue }
    if (Test-Path $TmpSums) { Remove-Item -Force $TmpSums -ErrorAction SilentlyContinue }
}

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
