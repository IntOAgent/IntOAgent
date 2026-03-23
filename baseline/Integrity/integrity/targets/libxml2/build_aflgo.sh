#!/usr/bin/env bash
# targets/libxml2/build_aflgo.sh
#
# Builds libxml2 with Integrity + AFLGo directed fuzzing instrumentation.
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
#   clang-14, opt-14, llvm-link-14, python3, networkx, pydot<3.0
#   pip3 install networkx "pydot<3.0"
#   AFLGo repo built (instrument/ and afl-2.57b/)
#
# Usage:
#   cd /path/to/integrity
#   AFLGO_DIR=/path/to/aflgo ./targets/libxml2/build_aflgo.sh
#
# Output:
#   build/fuzz_libxml2_xml_aflgo
#   build/fuzz_libxml2_html_aflgo
#   build/fuzz_libxml2_xpath_aflgo
#   build/fuzz_libxml2_regexp_aflgo

set -euo pipefail

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRITY_DIR="$(realpath "$SCRIPT_DIR/../..")"
LIBXML2_SRC="$(realpath "$INTEGRITY_DIR/../libxml2")"
WRAPPER="$INTEGRITY_DIR/scripts/integrity-cc-aflgo"
RT_OBJ="$INTEGRITY_DIR/build/integrity_rt.o"
PASS_SO="$INTEGRITY_DIR/build/IntegrityPass.so"

AFLGO_DIR="${AFLGO_DIR:-/home/xxx/PHDlife/fuxian/aflgo}"
AFLGO_CLANG="$AFLGO_DIR/instrument/aflgo-clang"
AFLGO_PASS="$AFLGO_DIR/instrument/aflgo-pass.so"
AFLGO_RT="$AFLGO_DIR/instrument/aflgo-runtime.o"
AFLGO_FUZZ="$AFLGO_DIR/afl-2.57b/afl-fuzz"
DIST_BIN="$AFLGO_DIR/distance/distance_calculator/distance.bin"
DIST_PY="$AFLGO_DIR/distance/gen_distance_fast.py"

BUILD_BASE="$INTEGRITY_DIR/build/libxml2_aflgo"
LIBXML2_BUILD="$BUILD_BASE/libxml2-build"
INSTALL_DIR="$BUILD_BASE/install"
TMP_DIR="$BUILD_BASE/aflgo-tmp"     # AFLGo data: BBtargets, dot-files, distances
MERGED_BC_DIR="$BUILD_BASE/merged-bc"  # merged whole-program bitcode
FUZZ_SRC="$LIBXML2_SRC/fuzz"
FUZZ_OUT="$INTEGRITY_DIR/build"

# Harnesses selected for integer-error relevance:
#   xml     — full XML parser (most arithmetic: lengths, offsets, counters)
#   html    — HTML parser (similar arithmetic, more lenient parsing)
#   xpath   — XPath evaluator (explicit integer arithmetic in expressions)
#   regexp  — regex NFA/DFA (state machine: counter + position arithmetic)
HARNESSES=(xml html xpath regexp)

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
[[ -f "$AFLGO_PASS"   ]] || die "aflgo-pass.so not found at $AFLGO_PASS"
[[ -f "$AFLGO_RT"     ]] || die "aflgo-runtime.o not found at $AFLGO_RT"
[[ -f "$AFLGO_FUZZ"   ]] || die "afl-fuzz not found at $AFLGO_FUZZ"
[[ -f "$DIST_BIN"     ]] || die "distance.bin not found at $DIST_BIN"
[[ -d "$LIBXML2_SRC"  ]] || die "libxml2 source not found at $LIBXML2_SRC"

python3 -c "import networkx, pydot" 2>/dev/null || \
    die "Python deps missing. Run: pip3 install networkx 'pydot<3.0'"

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
info "Running autogen.sh on libxml2..."
cd "$LIBXML2_SRC"
./autogen.sh 2>&1 | tail -3
make distclean 2>/dev/null || true
ok "autogen.sh done."

# ---------------------------------------------------------------------------
# Prepare directories
# ---------------------------------------------------------------------------
info "Preparing build directories..."
rm -rf "$LIBXML2_BUILD" "$TMP_DIR" "$MERGED_BC_DIR"
mkdir -p "$LIBXML2_BUILD" "$INSTALL_DIR/include" "$INSTALL_DIR/lib"
mkdir -p "$TMP_DIR/dot-files" "$MERGED_BC_DIR"
# Directory where integrity-cc-aflgo saves .int.bc files during Phase 0
BC_SAVE_DIR="$BUILD_BASE/saved-bc"
mkdir -p "$BC_SAVE_DIR"

# ============================================================================
# PHASE 0: Integrity-only compile
#   - Produces plain (non-AFL-instrumented) .o files so the autotools build
#     system proceeds normally.
#   - IntegrityPass writes guard branch locations to BBtargets.txt.
# ============================================================================
info "=== PHASE 0: Integrity compile + BBtargets.txt generation ==="

cd "$LIBXML2_BUILD"

CC="$WRAPPER" \
CFLAGS="-g -O1" \
AFLGO_DIR="$AFLGO_DIR" \
AFLGO_PHASE=0 \
INTEGRITY_OUTDIR="$TMP_DIR" \
"$LIBXML2_SRC/configure" \
    --disable-shared \
    --enable-static \
    --without-python \
    --without-http \
    --without-lzma \
    --prefix="$INSTALL_DIR" \
    2>&1 | tail -10

ok "Configure done."

# -j1: prevents concurrent writes to BBtargets.txt and BC_SAVE_DIR
# INTEGRITY_SAVE_BC_DIR: tells integrity-cc-aflgo to persist each .int.bc file
# so we can llvm-link them into a whole-program BC for callgraph extraction.
AFLGO_DIR="$AFLGO_DIR" \
AFLGO_PHASE=0 \
INTEGRITY_OUTDIR="$TMP_DIR" \
INTEGRITY_SAVE_BC_DIR="$BC_SAVE_DIR" \
make -j1 2>&1 | tail -15

ok "Phase 0 build done."

NTARGETS=$(wc -l < "$TMP_DIR/BBtargets.txt" 2>/dev/null || echo 0)
ok "BBtargets.txt: $NTARGETS guard-branch locations written."
[[ "$NTARGETS" -gt 0 ]] || die "No guard branches found — check Integrity pass"

NBC=$(ls "$BC_SAVE_DIR"/*.int.bc 2>/dev/null | wc -l || echo 0)
ok "Saved $NBC .int.bc files to $BC_SAVE_DIR"

# ============================================================================
# PHASE 1: AFLGo preprocessing compile
#   - Re-compiles with opt-14 -load aflgo-pass.so -targets/-outdir.
#   - The AFLGo pass reads BBtargets.txt and generates:
#       dot-files/cfg.*.dot  (per-function CFG graphs)
#       BBnames.txt          (all basic-block names)
#       BBcalls.txt          (BB → called-function edges)
#       Fnames.txt           (all function names)
#       Ftargets.txt         (functions containing target BBs)
# ============================================================================
info "=== PHASE 1: AFLGo preprocessing (generate CFG + call graph data) ==="

# Force recompile by removing all intermediate objects
find "$LIBXML2_BUILD" \( -name "*.o" -o -name "*.a" -o -name "*.la" -o -name "*.lo" \) \
    | xargs rm -f 2>/dev/null || true

AFLGO_DIR="$AFLGO_DIR" \
AFLGO_PHASE=1 \
INTEGRITY_OUTDIR="$TMP_DIR" \
make -j1 2>&1 | tail -15

ok "Phase 1 done. CFG dot-files generated."
NDOTS=$(ls "$TMP_DIR/dot-files/cfg."*.dot 2>/dev/null | wc -l || echo 0)
ok "  $NDOTS CFG dot files in $TMP_DIR/dot-files/"

# ============================================================================
# Create whole-program bitcode for callgraph extraction.
#
# gen_distance_fast.py needs a *.0.0.*.bc file in the binaries directory.
# We use the .int.bc files saved by integrity-cc-aflgo during Phase 0
# (via INTEGRITY_SAVE_BC_DIR). These were compiled with the full build system
# flags (correct -I paths, -D macros, config.h) — far more reliable than
# re-running clang-14 manually.
# ============================================================================
info "=== Creating whole-program bitcode for callgraph extraction ==="

# Only include the library objects (libxml2_la-*.int.bc), not the tool
# programs (xmllint-*, xmlcatalog-*) which each define main() and would
# cause "symbol multiply defined" errors during llvm-link.
INT_BCS=("$BC_SAVE_DIR/"libxml2_la-*.int.bc)
[[ -f "${INT_BCS[0]}" ]] || die "No libxml2_la-*.int.bc files in $BC_SAVE_DIR — Phase 0 may have failed"

llvm-link-14 "${INT_BCS[@]}" -o "$MERGED_BC_DIR/merged.0.0.0.bc"
ok "Merged ${#INT_BCS[@]} library bitcode files → $MERGED_BC_DIR/merged.0.0.0.bc"

# ============================================================================
# PHASE 2: Distance computation
#   gen_distance_fast.py uses:
#     $MERGED_BC_DIR/merged.0.0.0.bc  → opt -dot-callgraph → callgraph.dot
#     $TMP_DIR/dot-files/cfg.*.dot    → per-function CFG distances
#     $TMP_DIR/BBtargets.txt          → guard-branch target locations
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
#   Re-compiles with integrity-cc-aflgo AFLGO_PHASE=2.
#   Each BB now has its distance to the nearest guard branch embedded in the
#   AFL shared-memory bitmap. afl-fuzz reads these at runtime to compute
#   per-input average distance and weights seed scheduling accordingly.
# ============================================================================
info "=== PHASE 3: AFLGo distance instrumentation compile ==="

find "$LIBXML2_BUILD" \( -name "*.o" -o -name "*.a" -o -name "*.la" -o -name "*.lo" \) \
    | xargs rm -f 2>/dev/null || true

AFLGO_DIR="$AFLGO_DIR" \
AFLGO_PHASE=2 \
AFLGO_DIST="$DIST_FILE" \
INTEGRITY_OUTDIR="$TMP_DIR" \
make -j1 2>&1 | tail -15

ok "Phase 3 (distance instrumented) build done."

# Install static library and headers
make install 2>&1 | tail -5
LIBXML2_A="$INSTALL_DIR/lib/libxml2.a"
[[ -f "$LIBXML2_A" ]] || die "Static library not found: $LIBXML2_A"
ok "Installed to $INSTALL_DIR"

# ============================================================================
# PHASE 4: Link fuzz binaries
#   Each fuzzer binary bundles:
#     - AFL shim (provides main() + __AFL_INIT/__AFL_LOOP)
#     - The format-specific fuzzer harness + fuzz.c helper
#     - The Integrity+AFLGo instrumented libxml2
#     - integrity_rt.o  (continue-on-error reporting)
#     - aflgo-runtime.o (provides forkserver + AFL bitmap)
# ============================================================================
info "=== PHASE 4: Linking AFLGo fuzz binaries ==="

# Compile the AFL shim with aflgo-clang (defines __AFL_INIT/__AFL_LOOP macros)
AFL_SHIM_SRC="$SCRIPT_DIR/afl_shim.c"
AFL_SHIM_OBJ="$BUILD_BASE/afl_shim.o"
AFLGO="$AFLGO_DIR" AFL_CC="clang-14" AFL_QUIET=1 \
    "$AFLGO_CLANG" \
    -g -O1 -c "$AFL_SHIM_SRC" -o "$AFL_SHIM_OBJ"
ok "Compiled AFL shim: $AFL_SHIM_OBJ"

# Compile fuzz.c helper (shared by all harnesses)
FUZZ_C_OBJ="$BUILD_BASE/fuzz_helper.o"
clang-14 -g -O1 -c "$FUZZ_SRC/fuzz.c" \
    -I "$INSTALL_DIR/include/libxml2" \
    -I "$FUZZ_SRC" \
    -o "$FUZZ_C_OBJ"
ok "Compiled fuzz helper: $FUZZ_C_OBJ"

for h in "${HARNESSES[@]}"; do
    HARNESS_SRC="$FUZZ_SRC/${h}.c"
    FUZZER_BIN="$FUZZ_OUT/fuzz_libxml2_${h}_aflgo"
    [[ -f "$HARNESS_SRC" ]] || { info "Skipping $h (no harness source)"; continue; }

    info "Linking: fuzz_libxml2_${h}_aflgo"

    # Compile harness to object (no main — provided by AFL shim)
    HARNESS_OBJ="$BUILD_BASE/${h}_harness.o"
    clang-14 -g -O1 -c "$HARNESS_SRC" \
        -I "$INSTALL_DIR/include/libxml2" \
        -I "$FUZZ_SRC" \
        -o "$HARNESS_OBJ"

    # Link: shim + harness + fuzz helper + instrumented libxml2 + runtimes
    # aflgo-clang injects aflgo-runtime.o automatically at link time
    AFLGO="$AFLGO_DIR" \
    AFL_CC="clang-14" \
    AFL_QUIET=1 \
    "$AFLGO_CLANG" \
        -g -O1 \
        "$AFL_SHIM_OBJ" \
        "$HARNESS_OBJ" \
        "$FUZZ_C_OBJ" \
        "$LIBXML2_A" \
        "$RT_OBJ" \
        -lz -lm \
        -o "$FUZZER_BIN"

    ok "Built: $FUZZER_BIN"
done

# ============================================================================
# Step 5: Prepare corpus directories
# ============================================================================
info "Preparing corpus directories..."
CORPUS_BASE="$INTEGRITY_DIR/corpus/libxml2_aflgo"
for h in "${HARNESSES[@]}"; do
    mkdir -p "$CORPUS_BASE/$h"
done

# Copy static seeds from the libxml2 fuzz directory
SEED_DIR="$FUZZ_SRC/static_seed"
if [[ -d "$SEED_DIR" ]]; then
    for h in "${HARNESSES[@]}"; do
        if [[ -d "$SEED_DIR/$h" ]]; then
            cp "$SEED_DIR/$h/"* "$CORPUS_BASE/$h/" 2>/dev/null || true
        fi
    done
    ok "Copied static seeds to corpus."
fi

# Copy test XML files as seeds
find "$LIBXML2_SRC/test" -name "*.xml" -size -64k 2>/dev/null \
    | head -50 | xargs -I{} cp {} "$CORPUS_BASE/xml/" 2>/dev/null || true
find "$LIBXML2_SRC/test" -name "*.html" -size -64k 2>/dev/null \
    | head -20 | xargs -I{} cp {} "$CORPUS_BASE/html/" 2>/dev/null || true

# Fallback minimal seeds
[[ -z "$(ls -A "$CORPUS_BASE/xml/" 2>/dev/null)" ]] && \
    printf '<root/>' > "$CORPUS_BASE/xml/seed"
[[ -z "$(ls -A "$CORPUS_BASE/html/" 2>/dev/null)" ]] && \
    printf '<html><body></body></html>' > "$CORPUS_BASE/html/seed"
[[ -z "$(ls -A "$CORPUS_BASE/xpath/" 2>/dev/null)" ]] && \
    printf '/root/child' > "$CORPUS_BASE/xpath/seed"
[[ -z "$(ls -A "$CORPUS_BASE/regexp/" 2>/dev/null)" ]] && \
    printf 'a*b+' > "$CORPUS_BASE/regexp/seed"

# ============================================================================
# Done
# ============================================================================
echo ""
ok "All done! Run AFLGo directed fuzzing with:"
echo ""
echo "  # Recommended: 45 min exploration + 15 min exploitation (1-hour campaign)"
for h in "${HARNESSES[@]}"; do
    BIN="$FUZZ_OUT/fuzz_libxml2_${h}_aflgo"
    [[ -f "$BIN" ]] || continue
    echo "  $AFLGO_FUZZ -z exp -c 45m \\"
    echo "    -i $CORPUS_BASE/$h \\"
    echo "    -o $FUZZ_OUT/afl_out_libxml2_${h} \\"
    echo "    -- $BIN @@"
    echo ""
done
echo "  # AFLGo flags:"
echo "  #   -z exp    exponential annealing power schedule"
echo "  #   -c 45m    switch to full exploitation after 45 minutes"
echo "  #   @@        AFL replaces @@ with the input file path"
echo ""
echo "  # After fuzzing, check integer errors in afl_out_*/crashes/ or stderr:"
echo "  #   [INTEGRITY] OVERFLOW at xmlmemory.c:N:M"
echo "  #   [INTEGRITY] === Error Summary (N unique, 0 dropped) ==="
