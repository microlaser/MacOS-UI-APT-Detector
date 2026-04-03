#!/usr/bin/env bash
# =============================================================
#  build.sh — macOS APT UI Interference Detector
#  Compiles macos_apt_detector_v*.c using free Xcode CLT (clang)
#
#  Usage:  bash build.sh [source.c]
#    If no argument is given the script auto-detects the newest
#    macos_apt_detector*.c file in the same directory.
# =============================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────
RED='\033[1;31m'; YELLOW='\033[1;33m'; GREEN='\033[1;32m'
CYAN='\033[1;36m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
die()     { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }

# ── Locate script directory ───────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Resolve source file ───────────────────────────────────────
if [[ "${1:-}" != "" ]]; then
    # Explicit argument
    SRC="$(basename "$1")"
else
    # Auto-detect: pick the newest macos_apt_detector*.c in SCRIPT_DIR
    FOUND=$(ls -t "${SCRIPT_DIR}"/macos_apt_detector*.c 2>/dev/null | head -1)
    if [[ -z "${FOUND}" ]]; then
        die "No macos_apt_detector*.c found in ${SCRIPT_DIR}.\n" \
            "      Pass the source filename as an argument:\n" \
            "        bash build.sh macos_apt_detector_v3.c"
    fi
    SRC="$(basename "${FOUND}")"
fi

# ── Derive target name from source name (strip .c extension) ──
# e.g. macos_apt_detector_v3.c  →  macos_apt_detector_v3
TARGET="${SRC%.c}"

MIN_MACOS="12.0"

FRAMEWORKS=(
    CoreFoundation
    ApplicationServices
    IOKit
    Security
)

CFLAGS=(-Wall -Wextra -O2 "-mmacosx-version-min=${MIN_MACOS}")
LDFLAGS=(-lproc)
for fw in "${FRAMEWORKS[@]}"; do
    LDFLAGS+=(-framework "$fw")
done

# ── Header ───────────────────────────────────────────────────
echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║   macOS APT Detector — Build Script                   ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# ── 1. Platform check ─────────────────────────────────────────
info "Checking platform..."
if [[ "$(uname -s)" != "Darwin" ]]; then
    die "This script is for macOS only (detected: $(uname -s))."
fi
MACOS_VER=$(sw_vers -productVersion)
success "macOS ${MACOS_VER} detected."

# ── 2. Xcode Command Line Tools ───────────────────────────────
info "Checking for Xcode Command Line Tools..."
if ! xcode-select -p &>/dev/null; then
    warn "Xcode CLT not found. Attempting install (you may see a GUI prompt)..."
    xcode-select --install
    echo ""
    warn "Re-run this script after the Xcode CLT installer finishes."
    exit 0
fi
success "Xcode CLT found at: $(xcode-select -p)"

# ── 3. Locate clang ───────────────────────────────────────────
info "Locating clang..."
if ! command -v clang &>/dev/null; then
    die "clang not found. Install Xcode CLT: xcode-select --install"
fi
CLANG_VER=$(clang --version | head -1)
success "Found: ${CLANG_VER}"

# ── 4. Source file check ──────────────────────────────────────
info "Looking for source: ${SRC}"
SRC_PATH="${SCRIPT_DIR}/${SRC}"

if [[ ! -f "${SRC_PATH}" ]]; then
    die "Source file not found: ${SRC_PATH}"
fi
success "Source found: ${SRC_PATH}"

# ── 5. Compile ────────────────────────────────────────────────
OUT_PATH="${SCRIPT_DIR}/${TARGET}"
info "Compiling → ${OUT_PATH}"

CMD=(clang "${CFLAGS[@]}" -o "${OUT_PATH}" "${SRC_PATH}" "${LDFLAGS[@]}")

echo ""
echo "  Command: ${CMD[*]}"
echo ""

if ! "${CMD[@]}"; then
    die "Compilation failed. See errors above."
fi

success "Build succeeded: ${OUT_PATH}"

# ── 6. Strip debug symbols ────────────────────────────────────
if command -v strip &>/dev/null; then
    strip "${OUT_PATH}"
    success "Stripped debug symbols."
fi

# ── 7. Verify the binary ──────────────────────────────────────
info "Verifying binary..."
FILE_INFO=$(file "${OUT_PATH}")
success "${FILE_INFO}"

ARCH=$(uname -m)
if echo "${FILE_INFO}" | grep -qi "${ARCH}"; then
    success "Architecture matches current CPU (${ARCH})."
else
    warn "Binary architecture may differ from current CPU (${ARCH})."
fi

# ── 8. Run hints (use exact derived target name) ──────────────
# Pad target name for display inside fixed-width box
DISP="./${TARGET}"
PAD_SUDO=$(printf "%-49s" "    sudo ${DISP}")
PAD_USER=$(printf "%-49s" "    ${DISP}")

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║   Build complete!                                     ║"
echo "╠═══════════════════════════════════════════════════════╣"
echo "║                                                       ║"
printf "║   Run (full visibility, recommended):                 ║\n"
printf "║     sudo %-45s║\n" "${DISP}"
printf "║                                                       ║\n"
printf "║   Run (user-space only):                              ║\n"
printf "║     %-49s║\n" "${DISP}"
printf "║                                                       ║\n"
echo   "║   Note: TCC.db, kext, and full process env scans      ║"
echo   "║   require root (sudo) for complete results.           ║"
echo   "╚═══════════════════════════════════════════════════════╝"
echo ""
