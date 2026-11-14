#!/usr/bin/env bash
set -euo pipefail

ITERATIONS="${1:-10}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

KOVREK=""
for candidate in \
  "$ROOT/bin/kovrek-native" \
  "$ROOT/engine-rs/target/release/kovrek" \
  "$(command -v kovrek 2>/dev/null || true)"; do
  if [ -n "$candidate" ] && [ -x "$candidate" ]; then
    KOVREK="$candidate"
    break
  fi
done

if [ -z "$KOVREK" ]; then
  echo "Building release binary via cargo build --release ..."
  cargo build --manifest-path "$ROOT/engine-rs/Cargo.toml" --release --locked
  KOVREK="$ROOT/engine-rs/target/release/kovrek"
fi

echo "Kovrek Benchmark Suite"
echo "Binary : $KOVREK"
echo "Version: $("$KOVREK" --version)"
echo "OS     : $(uname -srm)"
echo "Runs   : $ITERATIONS iterations per benchmark"
echo ""

for file in bench_fib_jit.kvr bench_tensor_matmul.kvr bench_verify_contract.kvr; do
  "$KOVREK" bench "$SCRIPT_DIR/$file" "$ITERATIONS"
done

echo ""
echo "Static Verification Check (bench_verify_contract.kvr):"
"$KOVREK" verify "$SCRIPT_DIR/bench_verify_contract.kvr"

echo ""
echo "AOT Native Compile (bench_fib_jit.kvr):"
TMP_OUT="$(mktemp -u /tmp/kovrek_bench_fib_XXXXXX)"
trap 'rm -f "$TMP_OUT"' EXIT
"$KOVREK" aot "$SCRIPT_DIR/bench_fib_jit.kvr" "$TMP_OUT"
"$TMP_OUT"
echo "AOT native run passed cleanly: $TMP_OUT"
