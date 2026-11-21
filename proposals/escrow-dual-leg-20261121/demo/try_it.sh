#!/bin/sh
# Try Forge's escrow verifier in 30 seconds. Standard cargo, no Dafny toolchain.
# Builds the zero-dependency Rust verifier (Leg 2) and runs it on four committed inputs.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
V="$HERE/../spec/golden_vectors"
echo "Building the zero-dependency Rust verifier (cargo, no Dafny)..."
( cd "$HERE/../leg2" && cargo build --release -q )
B="$HERE/../leg2/target/release/leg2-verify"
verdict() { # $1 case  $2 pubkeys
  "$B" "$V/$1.log.bin" --manifest "$V/$1.manifest.bin" --pubkeys "$2" --observed-now 1700000500 --json \
    | grep -o '"verdict":"[^"]*"' | head -1 | cut -d'"' -f4
}
printf '\n  %-34s %s\n' "input" "verdict"
printf '  %-34s %s\n' "---------------------------------" "----------------------"
printf '  %-34s %s\n' "a valid refund log"              "$(verdict accept_one_step     "$V/a.pub,$V/b.pub")"
printf '  %-34s %s\n' "a spend OVER the cap"            "$(verdict reject_over_cap      "$V/a.pub,$V/b.pub")"
printf '  %-34s %s\n' "a FORGED identity key (0100..00)" "$(verdict reject_bad_key       "$V/badA.pub,$V/b.pub")"
printf '  %-34s %s\n' "a REPLAYED duplicate step"       "$(verdict reject_duplicate_id "$V/a.pub,$V/b.pub")"
printf '\nEach verdict is deterministic from the bytes. An independent Dafny-PROVED verifier agrees on all\n'
printf 'of these and on 1,999/1,999 differential cases (0 diffs); see ../REPORT.md. end_to_end=false.\n'
