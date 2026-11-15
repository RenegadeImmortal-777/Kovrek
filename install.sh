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
  case "$KOVREK_VERSION" in
    v*[!/]* )
      case "$KOVREK_VERSION" in
        *..*|*[!A-Za-z0-9._-]*)
          echo "Error: invalid KOVREK_VERSION '$KOVREK_VERSION'." >&2
          exit 1
          ;;
      esac
      ;;
    *)
      echo "Error: KOVREK_VERSION must start with 'v' (got '$KOVREK_VERSION')." >&2
      exit 1
      ;;
  esac
  BASE_URL="https://github.com/$REPO/releases/download/$KOVREK_VERSION"
else
  BASE_URL="https://github.com/$REPO/releases/latest/download"
fi

URL="$BASE_URL/$ASSET"
SUMS_URL="$BASE_URL/SHA256SUMS.txt"

download_file() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --proto '=https' --tlsv1.2 "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --https-only -O "$2" "$1"
  else
    echo "Error: curl or wget is required to install Kovrek." >&2
    exit 1
  fi
}

compute_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print tolower($1)}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | awk '{print tolower($NF)}'
  else
    echo "Error: sha256sum, shasum, or openssl is required to verify binary integrity." >&2
    exit 1
  fi
}

mkdir -p "$BIN_DIR"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kovrek-install.XXXXXX")"
TMP_BIN="$TMP_DIR/$ASSET"
TMP_SUMS="$TMP_DIR/SHA256SUMS.txt"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

echo "Downloading $ASSET and SHA256SUMS.txt from $BASE_URL ..."
download_file "$URL" "$TMP_BIN"
download_file "$SUMS_URL" "$TMP_SUMS"

EXPECTED_SUM="$(awk -v asset="$ASSET" '
  {
    name = $2
    sub(/^\*/, "", name)
    sub(/^\.\//, "", name)
    if (name == asset) {
      print tolower($1)
      exit
    }
  }
' "$TMP_SUMS")"

case "$EXPECTED_SUM" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f])
    ;;
  *)
    echo "Error: could not find valid SHA-256 digest for '$ASSET' in SHA256SUMS.txt." >&2
    exit 1
    ;;
esac

ACTUAL_SUM="$(compute_sha256 "$TMP_BIN")"
if [ "$ACTUAL_SUM" != "$EXPECTED_SUM" ]; then
  echo "Error: SHA-256 verification failed for $ASSET!" >&2
  echo "  expected: $EXPECTED_SUM" >&2
  echo "  actual:   $ACTUAL_SUM" >&2
  exit 1
fi

chmod 755 "$TMP_BIN"
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
