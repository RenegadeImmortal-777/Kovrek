param(
    [int]$Iterations = 10
)

$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BenchDir = $PSScriptRoot

$ExeCandidates = @(
    (Join-Path $Root "bin\kovrek-native.exe"),
    (Join-Path $Root "engine-rs\target\release\kovrek.exe")
)

$Kovrek = $ExeCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $Kovrek) {
    Write-Host "Building release binary via cargo build --release ..."
    cargo build --manifest-path (Join-Path $Root "engine-rs\Cargo.toml") --release --locked | Out-Null
    $Kovrek = Join-Path $Root "engine-rs\target\release\kovrek.exe"
}

Write-Host "Kovrek Benchmark Suite"
Write-Host "Binary : $Kovrek"
Write-Host "Version: $(& $Kovrek --version)"
Write-Host "OS     : $([System.Runtime.InteropServices.RuntimeInformation]::OSDescription)"
Write-Host "Runs   : $Iterations iterations per benchmark"
Write-Host ""

$BenchFiles = @(
    "bench_fib_jit.kvr",
    "bench_tensor_matmul.kvr",
    "bench_verify_contract.kvr"
)

foreach ($file in $BenchFiles) {
    $path = Join-Path $BenchDir $file
    & $Kovrek bench $path $Iterations
    if ($LASTEXITCODE -ne 0) {
        throw "Benchmark failed: $file"
    }
}

Write-Host ""
Write-Host "Static Verification Check (bench_verify_contract.kvr):"
& $Kovrek verify (Join-Path $BenchDir "bench_verify_contract.kvr")
if ($LASTEXITCODE -ne 0) {
    throw "Static verify check failed"
}

Write-Host ""
Write-Host "AOT Native Compile & Execute (bench_fib_jit.kvr):"
$TmpExe = Join-Path $env:TEMP ("kovrek_bench_fib_{0}.exe" -f $PID)
try {
    $compileSw = [System.Diagnostics.Stopwatch]::StartNew()
    & $Kovrek aot (Join-Path $BenchDir "bench_fib_jit.kvr") $TmpExe
    $compileSw.Stop()
    if ($LASTEXITCODE -ne 0) {
        throw "AOT compile failed"
    }

    $aotTimes = @()
    for ($i = 0; $i -lt $Iterations; $i++) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        & $TmpExe | Out-Null
        $sw.Stop()
        if ($LASTEXITCODE -ne 0) {
            throw "AOT executable exited with $LASTEXITCODE"
        }
        $aotTimes += $sw.Elapsed.TotalMilliseconds
    }
    $bestAot = ($aotTimes | Measure-Object -Minimum).Minimum
    $meanAot = ($aotTimes | Measure-Object -Average).Average
    Write-Host ("bench_fib_jit (AOT native): {0} run(s) | compile={1:N1}ms | best={2:N3}ms | mean={3:N3}ms" -f $Iterations, $compileSw.Elapsed.TotalMilliseconds, $bestAot, $meanAot)
} finally {
    if (Test-Path $TmpExe) {
        Remove-Item $TmpExe -Force -ErrorAction SilentlyContinue
    }
}
