#!/usr/bin/env bash
# Download a toolchain-verify release archive for this runner and verify SHA256SUMS.
set -euo pipefail

VERSION="${INPUT_VERSION:-}"
if [ -z "$VERSION" ]; then
  # Prefer the action ref when it looks like a version tag.
  if [[ "${ACTION_REF:-}" =~ ^v[0-9] ]]; then
    VERSION="$ACTION_REF"
  else
    VERSION="v0.1.0"
  fi
fi
# Strip leading v for asset names that use {{.Version}} without v — GoReleaser
# includes the leading v in .Version when the tag is v0.1.0 by default? Actually
# GoReleaser .Version is the tag without the v prefix when tags are v-prefixed.
# Our archive template uses {{ .Version }} which is "0.1.0" for tag v0.1.0.
TAG="$VERSION"
[[ "$TAG" == v* ]] || TAG="v$TAG"
VER="${TAG#v}"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 2 ;;
esac
case "$OS" in
  linux|darwin) EXT=tar.gz; BIN=toolchain-verify ;;
  mingw*|msys*|cygwin*|windows) OS=windows; EXT=zip; BIN=toolchain-verify.exe ;;
  *) echo "unsupported os: $OS" >&2; exit 2 ;;
esac

ASSET="toolchain-verify_${VER}_${OS}_${ARCH}.${EXT}"
BASE="https://github.com/Sanilas-ai/toolchain-verify/releases/download/${TAG}"
DEST="${RUNNER_TEMP:-/tmp}/toolchain-verify-${TAG}"
mkdir -p "$DEST"
cd "$DEST"

echo "Downloading $BASE/$ASSET"
AUTH=()
if [ -n "${GH_TOKEN:-}" ]; then
  AUTH=(-H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/octet-stream")
fi
curl -fsSL "${AUTH[@]}" -o "$ASSET" "$BASE/$ASSET"
curl -fsSL "${AUTH[@]}" -o SHA256SUMS "$BASE/SHA256SUMS"

# Verify the one asset we downloaded (portable: sha256sum or shasum)
if command -v sha256sum >/dev/null 2>&1; then
  grep " ${ASSET}\$" SHA256SUMS | sha256sum -c -
elif command -v shasum >/dev/null 2>&1; then
  grep " ${ASSET}\$" SHA256SUMS | shasum -a 256 -c -
else
  echo "no sha256 tool on runner" >&2
  exit 2
fi

rm -rf extracted
mkdir extracted
case "$EXT" in
  tar.gz) tar -xzf "$ASSET" -C extracted ;;
  zip) unzip -q "$ASSET" -d extracted ;;
esac
# Binary may be at top level or nested
BIN_PATH="$(find extracted -type f -name "$BIN" | head -n1)"
if [ -z "$BIN_PATH" ]; then
  echo "binary $BIN not found in archive" >&2
  ls -laR extracted >&2
  exit 2
fi
chmod +x "$BIN_PATH"
echo "Installed $($BIN_PATH version 2>/dev/null || true) at $BIN_PATH"
echo "binary=$BIN_PATH" >> "$GITHUB_OUTPUT"
