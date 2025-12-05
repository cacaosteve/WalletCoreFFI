#!/usr/bin/env bash
# install_linux.sh
#
# Installs the WalletCore Rust FFI artifacts on Linux:
# - Installs the shared library (libwalletcore.so) into <prefix>/lib
# - Installs the public C header (walletcore.h) into <prefix>/include
# - Generates and installs a pkg-config file (<prefix>/lib/pkgconfig/walletcore.pc)
#
# Defaults:
#   PREFIX=/usr/local
#   TARGET=<auto-detected from uname -m>
#   PROFILE=release
#
# You may override:
#   PREFIX=/opt/walletcore
#   TARGET=x86_64-unknown-linux-gnu | aarch64-unknown-linux-gnu | ... (Cargo target triple)
#   PROFILE=debug | release
#   LIB_SO=<path/to/libwalletcore.so>
#   HEADER=<path/to/walletcore.h>
#
# Example:
#   # Build the Rust library first (outside this script):
#   #   $ (cd monero-oxide-output && cargo build --release --target x86_64-unknown-linux-gnu)
#   # Then install with:
#   $ PREFIX=/usr/local TARGET=x86_64-unknown-linux-gnu ./Scripts/install_linux.sh
#
# After install (optional):
#   $ sudo ldconfig
#   $ pkg-config --libs --cflags walletcore
#
# Notes:
# - This script assumes it resides in MoneroWalletCoreFFI/Scripts/.
# - It will attempt to extract Version from monero-oxide-output/Cargo.toml.
# - If installing to a system prefix, you may need to run with sudo.

set -euo pipefail

# ---------------
# Resolve paths
# ---------------
THIS_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "$0")"
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPTS_DIR}/.." && pwd)"

CRATE_DIR="${REPO_ROOT}/monero-oxide-output"
HEADER_DEFAULT="${REPO_ROOT}/CLibMoneroWalletCore/walletcore.h"

# ---------------
# Defaults
# ---------------
PREFIX="${PREFIX:-/usr/local}"
PROFILE="${PROFILE:-release}"
HEADER="${HEADER:-$HEADER_DEFAULT}"

# Auto-detect target triple if not provided
detect_target_triple() {
  local arch
  arch="$(uname -m || true)"
  case "${arch}" in
    x86_64) echo "x86_64-unknown-linux-gnu" ;;
    aarch64) echo "aarch64-unknown-linux-gnu" ;;
    arm64) echo "aarch64-unknown-linux-gnu" ;;
    *) echo "x86_64-unknown-linux-gnu" ;;
  esac
}
TARGET="${TARGET:-$(detect_target_triple)}"

LIB_SO="${LIB_SO:-${CRATE_DIR}/target/${TARGET}/${PROFILE}/libwalletcore.so}"

LIBDIR="${PREFIX}/lib"
INCLUDEDIR="${PREFIX}/include"
PKGCONFIGDIR="${LIBDIR}/pkgconfig"

DRY_RUN="${DRY_RUN:-0}"

# ---------------
# Helpers
# ---------------
log() { echo "[$(basename "$0")] $*"; }
die() { echo "[$(basename "$0")] error: $*" >&2; exit 1; }

need_file() {
  local path="$1"
  [[ -f "$path" ]] || die "required file not found: $path"
}

ensure_dir() {
  local dir="$1"
  if [[ ! -d "$dir" ]]; then
    log "creating directory: $dir"
    if [[ "$DRY_RUN" == "1" ]]; then
      echo "mkdir -p \"$dir\""
    else
      mkdir -p "$dir"
    fi
  fi
}

copy_file() {
  local src="$1"
  local dst="$2"
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "install -m 0644 \"$src\" \"$dst\""
  else
    install -m 0644 "$src" "$dst"
  fi
}

# Extract version from Cargo.toml (falls back to 0.0.0)
extract_version() {
  local cargo_toml="${CRATE_DIR}/Cargo.toml"
  if [[ -f "$cargo_toml" ]]; then
    # grep the first version = "X.Y.Z" under [package]
    awk '
      /^\[package\]/ { inpkg=1; next }
      /^\[/ { inpkg=0 }
      inpkg && $1 ~ /^version/ {
        match($0, /version *= *"([^"]+)"/, m)
        if (m[1] != "") { print m[1]; exit 0 }
      }
    ' "$cargo_toml"
  fi
}

VERSION="${VERSION:-$(extract_version)}"
VERSION="${VERSION:-0.0.0}"

# ---------------
# CLI parsing
# ---------------
usage() {
  cat <<EOF
Usage: PREFIX=/usr/local TARGET=<triple> PROFILE=release ${0##*/} [--dry-run] [--prefix DIR] [--target TRIPLE] [--profile release|debug] [--lib PATH] [--header PATH]

Options:
  --dry-run             Print actions without performing them
  --prefix DIR          Install prefix (default: ${PREFIX})
  --target TRIPLE       Cargo target triple (default: ${TARGET})
  --profile NAME        Build profile: release|debug (default: ${PROFILE})
  --lib PATH            Path to libwalletcore.so (default: derived from target/profile)
  --header PATH         Path to walletcore.h (default: ${HEADER_DEFAULT})
  -h, --help            Show this help

Environment variables:
  PREFIX, TARGET, PROFILE, LIB_SO, HEADER, VERSION, DRY_RUN

Install locations:
  lib:       ${LIBDIR}
  include:   ${INCLUDEDIR}
  pkgconfig: ${PKGCONFIGDIR}

EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN="1"; shift ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --target) TARGET="$2"; shift 2 ;;
    --profile) PROFILE="$2"; shift 2 ;;
    --lib) LIB_SO="$2"; shift 2 ;;
    --header) HEADER="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (use --help)" ;;
  esac
done

# Recompute dir paths after CLI changes
LIBDIR="${PREFIX}/lib"
INCLUDEDIR="${PREFIX}/include"
PKGCONFIGDIR="${LIBDIR}/pkgconfig"

# ---------------
# Validations
# ---------------
need_file "${LIB_SO}"
need_file "${HEADER}"

# ---------------
# Summary
# ---------------
log "Install summary:"
echo "  PREFIX      = ${PREFIX}"
echo "  TARGET      = ${TARGET}"
echo "  PROFILE     = ${PROFILE}"
echo "  LIB_SO      = ${LIB_SO}"
echo "  HEADER      = ${HEADER}"
echo "  VERSION     = ${VERSION}"
echo "  LIBDIR      = ${LIBDIR}"
echo "  INCLUDEDIR  = ${INCLUDEDIR}"
echo "  PKGCONFIGDIR= ${PKGCONFIGDIR}"
if [[ "$DRY_RUN" == "1" ]]; then
  echo "  DRY_RUN     = yes"
fi
echo

# ---------------
# Install steps
# ---------------
ensure_dir "${LIBDIR}"
ensure_dir "${INCLUDEDIR}"
ensure_dir "${PKGCONFIGDIR}"

# Copy shared library
log "Installing libwalletcore.so -> ${LIBDIR}/"
copy_file "${LIB_SO}" "${LIBDIR}/libwalletcore.so"

# Copy public header
log "Installing walletcore.h -> ${INCLUDEDIR}/"
copy_file "${HEADER}" "${INCLUDEDIR}/walletcore.h"

# Generate pkg-config file
PC_PATH="${PKGCONFIGDIR}/walletcore.pc"
log "Generating pkg-config: ${PC_PATH}"

PC_CONTENT="$(cat <<EOF
prefix=${PREFIX}
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: walletcore
Description: Monero WalletCore FFI
Version: ${VERSION}
Libs: -L\${libdir} -lwalletcore
Cflags: -I\${includedir}
EOF
)"

if [[ "$DRY_RUN" == "1" ]]; then
  echo "cat > \"$PC_PATH\" <<'__PC__'"
  echo "${PC_CONTENT}"
  echo "__PC__"
else
  printf "%s\n" "${PC_CONTENT}" > "${PC_PATH}"
  chmod 0644 "${PC_PATH}" || true
fi

echo
log "Install complete."
echo "Next steps (optional):"
echo "  • Update the shared library cache (if supported): sudo ldconfig"
echo "  • Verify pkg-config: pkg-config --libs --cflags walletcore"
echo
echo "If your Swift package uses:"
echo "  .systemLibrary(name: \"CLibMoneroWalletCore\", pkgConfig: \"walletcore\", providers: [...])"
echo "Then SwiftPM should now be able to find and link libwalletcore on Linux."
echo
echo "Troubleshooting:"
echo "  • If your compiler/linker can't find the library, ensure ${LIBDIR} is in your runtime loader path (e.g., /etc/ld.so.conf.d) and run ldconfig."
echo "  • You can also export at runtime:"
echo "      export LD_LIBRARY_PATH=${LIBDIR}:\$LD_LIBRARY_PATH"
echo
