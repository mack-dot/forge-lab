#!/bin/sh
# freeze_leg2.sh - pin Leg 2 to the frozen spec packet. POSIX sh, no dependencies
# beyond coreutils + a sha256 tool (sha256sum on Linux, shasum -a 256 on macOS).
#
# ORDERING RULE (load-bearing): this freeze record, and the spec_packet_hash it
# carries, are committed and pushed PUBLICLY BEFORE Escrow Leg 1 is ever pushed. Leg 2
# is frozen against the spec BEFORE any differential testing against Leg 1 exists. That
# is what makes the two-leg agreement a genuine clean-room N-version check (a NATIVE
# CHECK), not a copy. Do not run this after seeing Leg 1.
#
# Usage:
#   freeze_leg2.sh <leg2_source_dir> <leg2_binary> [<packet_dir_to_verify>]
#
# Emits leg2_frozen.json (to stdout and to ./leg2_frozen.json) with:
#   spec_packet_hash, leg2_source_tree_sha256, leg2_binary_sha256,
#   rustc_version_string, built_offline:true, timestamp, labels{...}.
#
# NOTE: this script does NOT build anything. It reads an already-built binary. The
# rustc version is only queried (rustc --version); set RUSTC_VERSION_OVERRIDE to skip
# even that query.

set -eu

# The frozen spec_packet_hash (see FREEZE.md; algorithm documented there).
# Re-release 5 (genesis check-order precedence pinned: kind-gate before seq_no).
# Retired: cd51e45..., 76f4ab54..., 51d1d035..., fb1c7d83...
SPEC_PACKET_HASH="127b515567e2172846473d66c797d803289c89c4fdf3547f53cc343d4ffb20e7"

# ---- sha256 helpers (portable) ------------------------------------------------
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}
sha256_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
}

# Tree hash: sorted "<relpath>  <sha256>" lines over a directory, then sha256 of the
# listing. Excludes VCS and build dirs. Used for the Leg-2 SOURCE tree.
tree_hash() {
  dir="$1"
  ( cd "$dir" && \
    find . -type f \
      ! -path './.git/*' \
      ! -path './target/*' \
      ! -path '*/__pycache__/*' \
      ! -name '*.pyc' \
    | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r f; do
        printf '%s  %s\n' "$f" "$(sha256_file "$f")"
      done ) | sha256_stdin
}

# Spec-packet hash: a WHITELIST of exactly the freeze set (README.md, SPEC.md,
# ACCEPTANCE.md, gen_vectors.py, and every file under golden_vectors/). This is
# robust against stray non-set docs (RATIFICATION/FINDINGS/brief) ever being dropped
# into the packet dir. It MUST match the algorithm documented in FREEZE.md.
spec_packet_tree_hash() {
  dir="$1"
  ( cd "$dir" && \
    { printf '%s\n' README.md SPEC.md ACCEPTANCE.md gen_vectors.py
      find golden_vectors -type f ! -name '*.pyc' | sed 's|^\./||'; } \
    | LC_ALL=C sort | while IFS= read -r f; do
        printf '%s  %s\n' "$f" "$(sha256_file "$f")"
      done ) | sha256_stdin
}

# ---- args ---------------------------------------------------------------------
if [ "$#" -lt 2 ]; then
  echo "usage: $0 <leg2_source_dir> <leg2_binary> [<packet_dir_to_verify>]" >&2
  exit 2
fi
SRC_DIR="$1"
BIN="$2"
PACKET_DIR="${3:-}"

[ -d "$SRC_DIR" ] || { echo "no such source dir: $SRC_DIR" >&2; exit 2; }
[ -f "$BIN" ] || { echo "no such binary: $BIN" >&2; exit 2; }

# ---- optional: verify the spec packet hash independently -----------------------
if [ -n "$PACKET_DIR" ]; then
  [ -d "$PACKET_DIR" ] || { echo "no such packet dir: $PACKET_DIR" >&2; exit 2; }
  GOT="$(spec_packet_tree_hash "$PACKET_DIR")"
  if [ "$GOT" != "$SPEC_PACKET_HASH" ]; then
    echo "SPEC PACKET HASH MISMATCH" >&2
    echo "  expected $SPEC_PACKET_HASH" >&2
    echo "  got      $GOT" >&2
    exit 1
  fi
  echo "spec packet hash verified: $GOT" >&2
fi

# ---- compute the Leg-2 fingerprints -------------------------------------------
SRC_HASH="$(tree_hash "$SRC_DIR")"
BIN_HASH="$(sha256_file "$BIN")"

if [ -n "${RUSTC_VERSION_OVERRIDE:-}" ]; then
  RUSTC_VER="$RUSTC_VERSION_OVERRIDE"
elif command -v rustc >/dev/null 2>&1; then
  RUSTC_VER="$(rustc --version 2>/dev/null || echo UNKNOWN)"
else
  RUSTC_VER="UNKNOWN (rustc not found)"
fi

TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ---- emit json ----------------------------------------------------------------
# Minimal JSON by hand (values are hex/known strings; no escaping needed except the
# rustc version string, which we keep plain).
OUT="leg2_frozen.json"
{
  printf '{\n'
  printf '  "spec_packet_hash": "%s",\n' "$SPEC_PACKET_HASH"
  printf '  "leg2_source_tree_sha256": "%s",\n' "$SRC_HASH"
  printf '  "leg2_binary_sha256": "%s",\n' "$BIN_HASH"
  printf '  "rustc_version_string": "%s",\n' "$RUSTC_VER"
  printf '  "built_offline": true,\n'
  printf '  "timestamp": "%s",\n' "$TS"
  printf '  "labels": {\n'
  printf '    "verifier": "NATIVE CHECK",\n'
  printf '    "agreement": "FINITE TEST",\n'
  printf '    "end_to_end": false\n'
  printf '  }\n'
  printf '}\n'
} | tee "$OUT"
