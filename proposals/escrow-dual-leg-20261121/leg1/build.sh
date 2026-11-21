#!/bin/zsh
# build.sh — verify + compile Leg 1 (escrow) with the pinned toolchain.
set -e
export PATH=/opt/homebrew/bin:$PATH          # pinned Node 24.3.0 first
DAFNY=/Users/mackianni/forge/.toolchain/dafny-4.11.0/dafny/dafny
HERE=${0:A:h}
cd "$HERE"

echo "## dafny --version"
"$DAFNY" --version

echo "## dafny verify (single proof slot, one file at a time)"
"$DAFNY" verify Sha.dfy
"$DAFNY" verify Ed.dfy
"$DAFNY" verify Leg1Escrow.dfy

echo "## compile -> Python (primary; immune to dafny#6584)"
"$DAFNY" build --target py --no-verify EscrowMain.dfy -o build/escrow

echo "## compile -> JavaScript (second backend, for the #6584 cross-check)"
"$DAFNY" build --target js --no-verify BackendCheck.dfy -o build/bcjs

echo "## done"
