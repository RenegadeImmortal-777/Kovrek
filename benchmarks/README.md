# Kovrek Benchmarks

Reproducible benchmark and verification workloads for Kovrek's VM, Tensor engine, Static Verifier, and AOT native compiler.

## Included Workloads

| Workload | What it exercises | File |
| :--- | :--- | :--- |
| **Compute / Loop & AOT** | 2,000x `fib_iter(35)` + `fib_rec(22)` (VM vs native AOT) | [bench_fib_jit.kvr](bench_fib_jit.kvr) |
| **Tensor Pipeline** | 51x 16x16 `tensor_matmul` + `tensor_relu` | [bench_tensor_matmul.kvr](bench_tensor_matmul.kvr) |
| **Contracts & Verify** | Static `kovrek verify` + 5,000 runtime `requires`/`ensures` checks | [bench_verify_contract.kvr](bench_verify_contract.kvr) |

## Run Locally

### Windows (PowerShell)
```powershell
powershell -ExecutionPolicy Bypass -File .\benchmarks\run_benchmarks.ps1
```

### Linux / macOS
```bash
bash ./benchmarks/run_benchmarks.sh
```

## Latest Measured Results

Measured with `.\benchmarks\run_benchmarks.ps1` against `bin/kovrek-native.exe` (`Kovrek 12.0.0-sovereign`) on Windows (`Microsoft Windows 10.0.26200`, 10 iterations per workload):

| Benchmark | Mode | Best | Mean | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `bench_fib_jit.kvr` | VM / JIT (`kovrek bench`, in-process) | `8.179 ms` | `8.515 ms` | 32 bytecode ops; 2,000x `fib_iter(35)` + `fib_rec(22)` |
| `bench_tensor_matmul.kvr` | VM Tensor (`kovrek bench`, in-process) | `1.025 ms` | `1.199 ms` | 63 bytecode ops; 51x 16x16 `tensor_matmul` + `tensor_relu` |
| `bench_verify_contract.kvr` | VM Contracts (`kovrek bench`, in-process) | `52.963 ms` | `55.510 ms` | 40 bytecode ops; 5,000x `requires`/`ensures` checks |
| `bench_verify_contract.kvr` | Static Prover (`kovrek verify`) | — | — | `ok: true`, `contracts_proven: 4`, `functions_checked: 2`, `invariants_checked: 11` |
| `bench_fib_jit.kvr` | AOT Native (`kovrek aot`, fresh process/run) | `39.862 ms` | `77.484 ms` | `8,221.1 ms` compile; per-run timings include OS process spawn overhead |

> Note: `kovrek bench` times in-process VM execution across iterations without process startup cost, whereas the AOT native rows spawn a fresh OS process on each iteration.
