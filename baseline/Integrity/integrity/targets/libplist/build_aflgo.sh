#!/usr/bin/env bash
# targets/libplist/build_aflgo.sh
#
# Builds libplist with Integrity + AFLGo directed fuzzing instrumentation.
#
# Integration design:
#   - Integrity LLVM pass inserts "guard branches" at every arithmetic op.
#     These guard branches are the AFLGo TARGET SITES: the fuzzer is directed
#     to generate inputs that reach (and trigger) these branches.
#   - AFLGo computes shortest-path distances from every basic block to the
#     guard branch BBs (using call graph + CFG), then weights seed scheduling
#     so inputs that execute code closer to guard branches get more mutations.
#   - Result: AFLGo steers fuzzing toward integer error sites; Integrity's
#     runtime records errors without crashing (continue-on-error).
#
# 5-phase pipeline:
#   Phase 0  — Integrity-only compile: accumulate BBtargets.txt + plain .o
#   Phase 1  — AFLGo preprocessing compile: generate CFG dot files + BBnames
#   (gap)    — llvm-link all .int.bc → merged.0.0.0.bc for callgraph
#   Phase 2  — gen_distance_fast.py: compute distances → distance.cfg.txt
#   Phase 3  — AFLGo distance compile: Integrity + AFLGo distance embedding
#   Phase 4  — Link fuzz binaries + prepare corpus
#
# Prerequisites:
#   clang-14, opt-14, llvm-link-14, llvm-config-14, python3,
#   networkx, pydot, pydotplus (pip3 install networkx pydot pydotplus)
#   AFLGo repo built (instrument/ and afl-2.57b/)
#
# Usage:
#   cd /home/xxx/PHDlife/fuxian/integrity
#   AFLGO_DIR=/home/xxx/PHDlife/fuxian/aflgo ./targets/libplist/build_aflgo.sh
#
# Output:
#   build/fuzz_libplist_bplist_aflgo
#   build/fuzz_libplist_xplist_aflgo
#   build/fuzz_libplist_jplist_aflgo
#   build/fuzz_libplist_oplist_aflgo

set -euo pipefail

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRITY_DIR="$(realpath "$SCRIPT_DIR/../..")"
LIBPLIST_SRC="$(realpath "$INTEGRITY_DIR/../libplist")"
WRAPPER="$INTEGRITY_DIR/scripts/integrity-cc-aflgo"
RT_OBJ="$INTEGRITY_DIR/build/integrity_rt.o"
PASS_SO="$INTEGRITY_DIR/build/IntegrityPass.so"

AFLGO_DIR="${AFLGO_DIR:-/home/xxx/PHDlife/fuxian/aflgo}"
AFLGO_CLANG="$AFLGO_DIR/instrument/aflgo-clang"
AFLGO_RT="$AFLGO_DIR/instrument/aflgo-runtime.o"
AFLGO_FUZZ="$AFLGO_DIR/afl-2.57b/afl-fuzz"
DIST_BIN="$AFLGO_DIR/distance/distance_calculator/distance.bin"
DIST_PY="$AFLGO_DIR/distance/gen_distance_fast.py"

BUILD_BASE="$INTEGRITY_DIR/build/libplist_aflgo"
LIBPLIST_BUILD="$BUILD_BASE/libplist-build"
INSTALL_DIR="$BUILD_BASE/install"
TMP_DIR="$BUILD_BASE/aflgo-tmp"   # AFLGo data: BBtargets, dot-files, distances
MERGED_BC_DIR="$BUILD_BASE/merged-bc"  # merged whole-program bitcode
FUZZ_OUT="$INTEGRITY_DIR/build"

FUZZER_SRC_DIR="$LIBPLIST_SRC/fuzz"
FORMATS=(bplist xplist jplist oplist)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info() { echo -e "\033[1;36m[*]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*"; }
die()  { echo -e "\033[1;31m[!]\033[0m $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
[[ -f "$PASS_SO"      ]] || die "IntegrityPass.so not found. Run: make build/IntegrityPass.so"
[[ -f "$RT_OBJ"       ]] || die "integrity_rt.o not found. Run: make build/integrity_rt.o"
[[ -f "$AFLGO_CLANG"  ]] || die "aflgo-clang not found at $AFLGO_CLANG"
[[ -f "$AFLGO_RT"     ]] || die "aflgo-runtime.o not found at $AFLGO_RT"
[[ -f "$AFLGO_FUZZ"   ]] || die "afl-fuzz not found at $AFLGO_FUZZ"
[[ -f "$DIST_BIN"     ]] || die "distance.bin not found at $DIST_BIN"
[[ -d "$LIBPLIST_SRC" ]] || die "libplist source not found at $LIBPLIST_SRC"

python3 -c "import networkx, pydot" 2>/dev/null || \
    die "Python deps missing. Run: pip3 install networkx pydot pydotplus"

# ---------------------------------------------------------------------------
# Step 0: Build Integrity toolchain
# ---------------------------------------------------------------------------
info "Building Integrity toolchain..."
make -C "$INTEGRITY_DIR" build/IntegrityPass.so build/integrity_rt.o \
    --no-print-directory -j"$(nproc)"
ok "Integrity toolchain ready."

# ---------------------------------------------------------------------------
# Step 1: autogen.sh to generate ./configure
# ---------------------------------------------------------------------------
info "Running autogen.sh on libplist..."
cd "$LIBPLIST_SRC"
./autogen.sh 2>&1 | tail -3
make distclean 2>/dev/null || true
ok "autogen.sh done."

# ---------------------------------------------------------------------------
# Prepare directories
# ---------------------------------------------------------------------------
info "Preparing build directories..."
rm -rf "$LIBPLIST_BUILD" "$TMP_DIR" "$MERGED_BC_DIR"
mkdir -p "$LIBPLIST_BUILD" "$INSTALL_DIR/include/plist" "$INSTALL_DIR/lib"
mkdir -p "$TMP_DIR/dot-files" "$MERGED_BC_DIR"

# ============================================================================
# PHASE 0: Integrity-only compile
#   - Produces plain (non-AFL-instrumented) .o files so the autotools build
#     system proceeds normally.
#   - IntegrityPass writes guard branch locations to BBtargets.txt.
# ============================================================================
info "=== PHASE 0: Integrity compile + BBtargets.txt generation ==="

cd "$LIBPLIST_BUILD"

# Configure once; CC wrapper handles phasing
CC="$WRAPPER" \
CFLAGS="-g -O1" \
CXX="clang++-14" \
CXXFLAGS="-g -O1" \
AFLGO_DIR="$AFLGO_DIR" \
AFLGO_PHASE=0 \
INTEGRITY_OUTDIR="$TMP_DIR" \
"$LIBPLIST_SRC/configure" \
    --without-cython \
    --disable-shared \
    --enable-static \
    --prefix="$INSTALL_DIR" \
    2>&1 | tail -8

ok "Configure done."

# Compile: each source file goes through:
#   clang -emit-llvm → opt -integrity (writes BBtargets.txt) → clang .o
AFLGO_DIR="$AFLGO_DIR" \
AFLGO_PHASE=0 \
INTEGRITY_OUTDIR="$TMP_DIR" \
make -C libcnary -j"$(nproc)" 2>&1 | tail -5

AFLGO_DIR="$AFLGO_DIR" \
AFLGO_PHASE=0 \
INTEGRITY_OUTDIR="$TMP_DIR" \
make -C src -j1 2>&1 | tail -10   # -j1 avoids concurrent BBtargets.txt writes

ok "Phase 0 build done."

NTARGETS=$(wc -l < "$TMP_DIR/BBtargets.txt" 2>/dev/null || echo 0)
ok "BBtargets.txt: $NTARGETS guard-branch locations written."

[[ "$NTARGETS" -gt 0 ]] || die "No guard branches found — check Integrity pass"

# ============================================================================
# PHASE 1: AFLGo preprocessing compile
#   - Re-compiles with aflgo-clang -targets/-outdir.
#   - The AFLGo pass reads BBtargets.txt and generates:
#       dot-files/cfg.*.dot  (per-function CFG graphs)
#       BBnames.txt          (all basic-block names)
#       BBcalls.txt          (BB → called-function edges)
#       Fnames.txt           (all function names)
#       Ftargets.txt         (functions containing target BBs)
# ============================================================================
info "=== PHASE 1: AFLGo preprocessing (generate CFG + call graph data) ==="

# Force recompile by removing objects
find "$LIBPLIST_BUILD" \( -name "*.o" -o -name "*.a" -o -name "*.la" -o -name "*.lo" \) | xargs rm -f 2>/dev/null || true

AFLGO_DIR="$AFLGO_DIR" \
AFLGO_PHASE=1 \
INTEGRITY_OUTDIR="$TMP_DIR" \
make -C libcnary -j"$(nproc)" 2>&1 | tail -5

AFLGO_DIR="$AFLGO_DIR" \
AFLGO_PHASE=1 \
INTEGRITY_OUTDIR="$TMP_DIR" \
make -C src -j1 2>&1 | tail -10

ok "Phase 1 done. CFG dot-files generated."
NDOTS=$(ls "$TMP_DIR/dot-files/cfg."*.dot 2>/dev/null | wc -l || echo 0)
ok "  $NDOTS CFG dot files in $TMP_DIR/dot-files/"

# ============================================================================
# Create whole-program bitcode for callgraph extraction.
#
# gen_distance_fast.py needs a *.0.0.*.bc file in the binaries directory.
# We produce this by:
#   1. Re-running emit-llvm + opt -integrity on each source → .int.bc
#   2. llvm-link all .int.bc into a single merged bitcode
#   3. Place it as merged.0.0.0.bc in $MERGED_BC_DIR
#
# This merged bitcode represents the whole program's call graph.
# ============================================================================
info "=== Creating whole-program bitcode for callgraph extraction ==="

INT_BCS=()
for SRC in "$LIBPLIST_SRC/src/"*.c "$LIBPLIST_SRC/libcnary/"*.c; do
    [[ -f "$SRC" ]] || continue
    BASE="$(basename "${SRC%.c}")"
    PRE_BC="$TMP_DIR/${BASE}.pre.bc"
    INT_BC="$TMP_DIR/${BASE}.int.bc"

    clang-14 -g -O1 -emit-llvm -c -o "$PRE_BC" "$SRC" 2>/dev/null || true
    if [[ -f "$PRE_BC" ]]; then
        opt-14 -enable-new-pm=0 -load "$PASS_SO" -integrity \
            -o "$INT_BC" "$PRE_BC" 2>/dev/null || cp "$PRE_BC" "$INT_BC"
        INT_BCS+=("$INT_BC")
    fi
done

if [[ ${#INT_BCS[@]} -gt 0 ]]; then
    llvm-link-14 "${INT_BCS[@]}" -o "$MERGED_BC_DIR/merged.0.0.0.bc" 2>/dev/null
    ok "Merged ${#INT_BCS[@]} bitcode files → $MERGED_BC_DIR/merged.0.0.0.bc"
else
    die "No .int.bc files produced — cannot create merged bitcode"
fi

# ============================================================================
# PHASE 2: Distance computation
#   gen_distance_fast.py uses:
#     $MERGED_BC_DIR/merged.0.0.0.bc  → opt -dot-callgraph → callgraph.dot
#     $TMP_DIR/dot-files/cfg.*.dot    → per-function CFG distances
#     $TMP_DIR/BBtargets.txt          → our guard-branch target locations
#   Output: $TMP_DIR/distance.cfg.txt
# ============================================================================
info "=== PHASE 2: Computing distances to guard-branch targets ==="

python3 "$DIST_PY" "$MERGED_BC_DIR" "$TMP_DIR" 2>&1 | tail -20

DIST_FILE="$TMP_DIR/distance.cfg.txt"
[[ -f "$DIST_FILE" ]] || die "distance.cfg.txt not generated — check gen_distance_fast.py output"

NLINES=$(wc -l < "$DIST_FILE")
ok "distance.cfg.txt: $NLINES BB distances computed."

# ============================================================================
# PHASE 3: AFLGo distance instrumentation compile
#   Re-compiles with aflgo-clang -distance=distance.cfg.txt.
#   Each BB now has its distance to the nearest guard branch embedded in the
#   AFL shared-memory bitmap (at MAP_SIZE and MAP_SIZE+8).
#   afl-fuzz reads these at runtime to compute per-input average distance,
#   then weights seed scheduling via the annealing power schedule.
# ============================================================================
info "=== PHASE 3: AFLGo distance instrumentation compile ==="

find "$LIBPLIST_BUILD" \( -name "*.o" -o -name "*.a" -o -name "*.la" -o -name "*.lo" \) | xargs rm -f 2>/dev/null || true

AFLGO_DIR="$AFLGO_DIR" \
AFLGO_PHASE=2 \
AFLGO_DIST="$DIST_FILE" \
INTEGRITY_OUTDIR="$TMP_DIR" \
make -C libcnary -j"$(nproc)" 2>&1 | tail -5

AFLGO_DIR="$AFLGO_DIR" \
AFLGO_PHASE=2 \
AFLGO_DIST="$DIST_FILE" \
INTEGRITY_OUTDIR="$TMP_DIR" \
make -C src -j1 2>&1 | tail -10

ok "Phase 3 (distance instrumented) build done."

# Install static library and headers
mkdir -p "$INSTALL_DIR/include/plist" "$INSTALL_DIR/lib"
cp "$LIBPLIST_SRC/include/plist/"*.h "$INSTALL_DIR/include/plist/" 2>/dev/null || true
cp "$LIBPLIST_BUILD/src/.libs/libplist-2.0.a" "$INSTALL_DIR/lib/"
LIBPLIST_A="$INSTALL_DIR/lib/libplist-2.0.a"
[[ -f "$LIBPLIST_A" ]] || die "Static library not found: $LIBPLIST_A"
ok "Installed to $INSTALL_DIR"

# ============================================================================
# PHASE 4: Link fuzz binaries
#   Each fuzzer binary bundles:
#     - The format-specific fuzzer harness (bplist_fuzzer.cc etc.)
#     - The Integrity+AFLGo instrumented libplist
#     - integrity_rt.o  (continues-on-error reporting)
#     - aflgo-runtime.o (provides __afl_area_ptr, __afl_prev_loc, forkserver)
# ============================================================================
info "=== PHASE 4: Linking AFLGo fuzz binaries ==="

# Compile the AFL shim (provides main() wrapping LLVMFuzzerTestOneInput).
# Must use aflgo-clang so __AFL_INIT()/__AFL_LOOP() macros are defined.
AFL_SHIM_SRC="$SCRIPT_DIR/afl_shim.c"
AFL_SHIM_OBJ="$BUILD_BASE/afl_shim.o"
AFLGO="$AFLGO_DIR" AFL_CC="clang-14" AFL_QUIET=1 \
    "$AFLGO_DIR/instrument/aflgo-clang" \
    -g -O1 -c "$AFL_SHIM_SRC" -o "$AFL_SHIM_OBJ"
ok "Compiled AFL shim: $AFL_SHIM_OBJ"

for fmt in "${FORMATS[@]}"; do
    FUZZER_CC="$FUZZER_SRC_DIR/${fmt}_fuzzer.cc"
    FUZZER_BIN="$FUZZ_OUT/fuzz_libplist_${fmt}_aflgo"
    [[ -f "$FUZZER_CC" ]] || { info "Skipping $fmt (no fuzzer source)"; continue; }

    info "Linking: fuzz_libplist_${fmt}_aflgo"

    # Compile the C++ harness to an object (no main — provided by AFL shim).
    HARNESS_OBJ="$BUILD_BASE/${fmt}_fuzzer.o"
    clang++-14 -g -O1 -c "$FUZZER_CC" \
        -I "$INSTALL_DIR/include" \
        -o "$HARNESS_OBJ" \
        -Wno-unused-result

    # Link: harness + shim + instrumented libplist + runtimes.
    # aflgo-clang++ injects aflgo-runtime.o automatically at link time.
    AFLGO="$AFLGO_DIR" \
    AFL_CC="clang-14" \
    AFL_CXX="clang++-14" \
    AFL_QUIET=1 \
    "$AFLGO_DIR/instrument/aflgo-clang++" \
        -g -O1 \
        "$AFL_SHIM_OBJ" \
        "$HARNESS_OBJ" \
        "$LIBPLIST_A" \
        "$RT_OBJ" \
        -o "$FUZZER_BIN"

    ok "Built: $FUZZER_BIN"
done

# ============================================================================
# Step 5: Prepare corpus directories
# ============================================================================
info "Preparing corpus directories..."
CORPUS_BASE="$INTEGRITY_DIR/corpus/libplist_aflgo"
for fmt in "${FORMATS[@]}"; do
    mkdir -p "$CORPUS_BASE/$fmt"
done

TESTDATA="$LIBPLIST_SRC/test/data"
if [[ -d "$TESTDATA" ]]; then
    cp "$TESTDATA"/*.bplist "$CORPUS_BASE/bplist/" 2>/dev/null || true
    cp "$TESTDATA"/*.plist  "$CORPUS_BASE/xplist/" 2>/dev/null || true
    cp "$TESTDATA"/*.json   "$CORPUS_BASE/jplist/" 2>/dev/null || true
    ok "Copied test data to corpus."
fi

# Minimal fallback seeds
printf 'bpaa' > "$CORPUS_BASE/bplist/seed" 2>/dev/null || true
printf '<?xml version="1.0"?><plist version="1.0"><true/></plist>' \
    > "$CORPUS_BASE/xplist/seed" 2>/dev/null || true
printf '{}' > "$CORPUS_BASE/jplist/seed" 2>/dev/null || true

# ============================================================================
# Done
# ============================================================================
echo ""
ok "All done! Run AFLGo directed fuzzing with:"
echo ""
echo "  # Recommended: 45 min exploration + 15 min exploitation (1-hour campaign)"
for fmt in "${FORMATS[@]}"; do
    BIN="$FUZZ_OUT/fuzz_libplist_${fmt}_aflgo"
    [[ -f "$BIN" ]] || continue
    echo "  $AFLGO_FUZZ -z exp -c 45m \\"
    echo "    -i $CORPUS_BASE/$fmt \\"
    echo "    -o $FUZZ_OUT/afl_out_${fmt} \\"
    echo "    -- $BIN @@"
    echo ""
done
echo "  # AFLGo flags:"
echo "  #   -z exp    exponential annealing power schedule"
echo "  #   -c 45m    switch to full exploitation after 45 minutes"
echo "  #   @@        AFL replaces @@ with the input file path"
echo ""
echo "  # After fuzzing, check integer errors in afl_out_*/crashes/ or stderr:"
echo "  #   [INTEGRITY] OVERFLOW at bplist.c:608:42"
echo "  #   [INTEGRITY] === Error Summary (N unique, 0 dropped) ==="
