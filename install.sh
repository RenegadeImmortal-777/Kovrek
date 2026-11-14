#!/usr/bin/env sh
set -eu

REPO="RenegadeImmortal-777/Kovrek"
KOVREK_HOME="${KOVREK_HOME:-$HOME/.kovrek}"
BIN_DIR="$KOVREK_HOME/bin"
LOCAL_BIN="${XDG_BIN_HOME:-$HOME/.local/bin}"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)
    case "$ARCH" in
      x86_64|amd64) ASSET="kovrek-native-linux-x86_64" ;;
      *)
        echo "Unsupported Linux architecture '$ARCH'. Prebuilt binaries support x86_64; build from source with:" >&2
        echo "  git clone https://github.com/$REPO.git && cargo build --manifest-path Kovrek/engine-rs/Cargo.toml --release" >&2
        exit 1
        ;;
    esac
    ;;
  Darwin)
    case "$ARCH" in
      arm64|aarch64) ASSET="kovrek-native-macos-arm64" ;;
      *)
        echo "Unsupported macOS architecture '$ARCH'. Prebuilt binaries support arm64; build from source with:" >&2
        echo "  git clone https://github.com/$REPO.git && cargo build --manifest-path Kovrek/engine-rs/Cargo.toml --release" >&2
        exit 1
        ;;
    esac
    ;;
  *)
    echo "Unsupported OS '$OS'. On Windows use: irm https://raw.githubusercontent.com/$REPO/master/install.ps1 | iex" >&2
    exit 1
    ;;
esac

if [ -n "${KOVREK_VERSION:-}" ]; then
  URL="https://github.com/$REPO/releases/download/$KOVREK_VERSION/$ASSET"
else
  URL="https://github.com/$REPO/releases/latest/download/$ASSET"
fi

mkdir -p "$BIN_DIR"
TMP_BIN="$BIN_DIR/.kovrek.tmp.$$"
trap 'rm -f "$TMP_BIN"' EXIT INT TERM

echo "Downloading $ASSET from $URL ..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$URL" -o "$TMP_BIN"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$TMP_BIN" "$URL"
else
  echo "Error: curl or wget is required to install Kovrek." >&2
  exit 1
fi

chmod +x "$TMP_BIN"
mv "$TMP_BIN" "$BIN_DIR/kovrek"

if [ -d "$LOCAL_BIN" ] || mkdir -p "$LOCAL_BIN" 2>/dev/null; then
  ln -sf "$BIN_DIR/kovrek" "$LOCAL_BIN/kovrek" 2>/dev/null || true
fi

echo ""
echo "Installed: $("$BIN_DIR/kovrek" --version 2>/dev/null || echo "$BIN_DIR/kovrek")"
case ":${PATH:-}:" in
  *":$BIN_DIR:"*|*":$LOCAL_BIN:"*) ;;
  *)
    echo "Add Kovrek to your PATH if needed:"
    echo "  export PATH=\"$BIN_DIR:\$PATH\""
    ;;
esac
echo "Try: kovrek verify <(echo '@verify fn f(x: Int) -> Int { requires(x >= 1, \"pos\"); return 10 / x; }')"
