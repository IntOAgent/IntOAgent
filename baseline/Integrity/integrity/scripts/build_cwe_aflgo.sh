#!/usr/bin/env bash
# build_cwe_aflgo.sh — 4-phase AFLGo build for a single CWE micro-benchmark.
#
# Arguments:
#   $1  CWE name        e.g. "cwe190"
#   $2  source file     e.g. "tests/cwe190_overflow.c"
#   $3  opt flags       e.g. "-O1" or "-O0"
#   $4  AFLGO_DIR       path to aflgo repo
#   $5  BUILD           build output dir (e.g. build/)
#   $6  AFLGO_TMP       temp dir for AFLGo data
#   $7  PASS_SO         path to IntegrityPass.so
#   $8  RT_OBJ          path to integrity_rt.o
#   $9  OUTPUT          final binary path
#
# Called by Makefile's cwe-aflgo targets.

set -euo pipefail

CWE="$1"
SRC="$2"
OFLAGS="$3"
AFLGO_DIR="$4"
BUILD="$5"
TMP_BASE="$6"
PASS_SO="$7"
RT_OBJ="$8"
OUTPUT="$9"

TMP="$TMP_BASE/$CWE"
AFLGO_CLANG="$AFLGO_DIR/instrument/aflgo-clang"
AFLGO_PASS="$AFLGO_DIR/instrument/aflgo-pass.so"
AFLGO_RT="$AFLGO_DIR/instrument/aflgo-runtime.o"
DIST_PY="$AFLGO_DIR/distance/gen_distance_fast.py"
DRIVER="tests/fuzz_driver_afl.c"

info() { echo -e "\033[1;36m[*]\033[0m [$CWE] $*"; }
ok()   { echo -e "\033[1;32m[+]\033[0m [$CWE] $*"; }
die()  { echo -e "\033[1;31m[!]\033[0m [$CWE] $*" >&2; exit 1; }

PRE_BC="$BUILD/${CWE}.pre.bc"
INT_BC="$BUILD/${CWE}.int.bc"
P1_OBJ="$BUILD/${CWE}_p1.o"
DIST_BC="$BUILD/${CWE}.dist.bc"
P3_OBJ="$BUILD/${CWE}_p3.o"
MERGED_BC="$TMP/${CWE}.0.0.0.bc"
DIST_FILE="$TMP/distance.cfg.txt"

mkdir -p "$TMP/dot-files"
rm -f "$TMP/BBtargets.txt"

# ---------------------------------------------------------------------------
# Phase 0: Integrity compile → .int.bc + BBtargets.txt
# ---------------------------------------------------------------------------
info "Phase 0: Integrity instrumentation + BBtargets.txt"

clang-14 $OFLAGS -g -emit-llvm -c -o "$PRE_BC" "$SRC"

INTEGRITY_OUTDIR="$TMP" \
    opt-14 -enable-new-pm=0 -load "$PASS_SO" -integrity \
    -o "$INT_BC" "$PRE_BC" 2>/dev/null

NTARGETS=$(wc -l < "$TMP/BBtargets.txt" 2>/dev/null || echo 0)
ok "BBtargets.txt: $NTARGETS entries"
[[ "$NTARGETS" -gt 0 ]] || die "No guard branches generated — check Integrity pass"

# ---------------------------------------------------------------------------
# Phase 1: AFLGo preprocessing — generate CFG dot files
# ---------------------------------------------------------------------------
info "Phase 1: AFLGo preprocessing (CFG dot files)"

# Use opt-14 directly: aflgo-clang loads the pass via -Xclang -load (clang plugin
# infrastructure) where cl::opt args aren't populated before runOnModule().
# opt -load, by contrast, parses cl::opt before running the pass.
opt-14 -enable-new-pm=0 -O0 \
    -load "$AFLGO_PASS" \
    -targets="$TMP/BBtargets.txt" \
    -outdir="$TMP" \
    -o /dev/null "$INT_BC" 2>/dev/null || true

# Produce a placeholder object (not linked into final binary; only needed so
# downstream make rules see a file was emitted).
clang-14 -g $OFLAGS -c -x ir -o "$P1_OBJ" "$INT_BC" 2>/dev/null

NDOTS=$(ls "$TMP/dot-files/cfg."*.dot 2>/dev/null | wc -l || echo 0)
ok "  $NDOTS CFG dot files generated"

# The AFLGo pass names BBs as "file:line:" (with trailing colon) for uniqueness
# in the IR, but the distance calculator looks up entries without the colon.
# Strip trailing colons from BBnames.txt so lookup keys match.
if [[ -f "$TMP/BBnames.txt" ]]; then
    sed -i 's/:$//' "$TMP/BBnames.txt"
fi

# ---------------------------------------------------------------------------
# Create merged bitcode for callgraph extraction
# (gen_distance_fast.py requires a *.0.0.*.bc in the binaries directory)
# ---------------------------------------------------------------------------
info "Creating merged bitcode for callgraph"
llvm-link-14 "$INT_BC" -o "$MERGED_BC" 2>/dev/null
ok "  Merged: $MERGED_BC"

# ---------------------------------------------------------------------------
# Phase 2: Distance computation
# ---------------------------------------------------------------------------
info "Phase 2: Computing distances to guard-branch targets"

python3 "$DIST_PY" "$TMP" "$TMP" 2>&1 | grep -v "^$" | tail -8

[[ -f "$DIST_FILE" ]] || die "distance.cfg.txt not produced"
NLINES=$(wc -l < "$DIST_FILE")
ok "  distance.cfg.txt: $NLINES BB distances"

# ---------------------------------------------------------------------------
# Phase 3: Distance instrumentation compile
# ---------------------------------------------------------------------------
info "Phase 3: AFLGo distance instrumentation"

# Step 3a: opt-14 runs the AFLGo pass in distance mode, emitting instrumented BC.
# -O0 preserves the Integrity guard branches already in INT_BC.
opt-14 -enable-new-pm=0 -O0 \
    -load "$AFLGO_PASS" \
    -distance="$DIST_FILE" \
    -o "$DIST_BC" "$INT_BC"

# Step 3b: Compile the instrumented BC to a native object.
clang-14 -g -O1 -c -x ir -o "$P3_OBJ" "$DIST_BC"

ok "  Distance-instrumented object: $P3_OBJ"

# ---------------------------------------------------------------------------
# Phase 4: Link fuzz binary
# ---------------------------------------------------------------------------
info "Phase 4: Linking $OUTPUT"

# aflgo-clang in link mode automatically appends aflgo-runtime.o.
# We also append integrity_rt.o for __integrity_report.
AFLGO="$AFLGO_DIR" AFL_CC=clang-14 AFL_QUIET=1 \
    "$AFLGO_CLANG" \
    -g -O1 \
    "$DRIVER" \
    "$P3_OBJ" \
    "$RT_OBJ" \
    -o "$OUTPUT"

ok "Built: $OUTPUT"
ok ""
ok "Run with AFLGo directed fuzzing:"
ok "  mkdir -p corpus && python3 -c \"import sys; sys.stdout.buffer.write(b'\\x00'*8)\" > corpus/seed"
ok "  $AFLGO_DIR/afl-2.57b/afl-fuzz -z exp -c 20m -i corpus -o out_$CWE -- $OUTPUT"
