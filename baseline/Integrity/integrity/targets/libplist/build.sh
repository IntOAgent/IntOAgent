#!/usr/bin/env bash
# targets/libplist/build.sh
#
# One-stop script: builds libplist with Integrity instrumentation and
# produces four fuzz binaries (bplist, xplist, jplist, oplist).
#
# Prerequisites:
#   clang-14, opt-14, autoconf, automake, libtool, pkg-config
#
# Usage:
#   cd /home/xxx/PHDlife/fuxian/integrity
#   ./targets/libplist/build.sh
#
# Output:
#   build/fuzz_libplist_bplist
#   build/fuzz_libplist_xplist
#   build/fuzz_libplist_jplist
#   build/fuzz_libplist_oplist

set -euo pipefail

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRITY_DIR="$(realpath "$SCRIPT_DIR/../..")"
# libplist is a sibling of the integrity directory
LIBPLIST_SRC="$(realpath "$INTEGRITY_DIR/../libplist")"
WRAPPER="$INTEGRITY_DIR/scripts/integrity-cc"
RT_OBJ="$INTEGRITY_DIR/build/integrity_rt.o"
PASS_SO="$INTEGRITY_DIR/build/IntegrityPass.so"
BUILD_DIR="$INTEGRITY_DIR/build/libplist"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info() { echo -e "\033[1;36m[*]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*"; }
die()  { echo -e "\033[1;31m[!]\033[0m $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Step 0: Build Integrity toolchain if needed
# ---------------------------------------------------------------------------
info "Building Integrity pass and runtime..."
make -C "$INTEGRITY_DIR" build/IntegrityPass.so build/integrity_rt.o \
    --no-print-directory -j"$(nproc)"
ok "Integrity toolchain ready."

# ---------------------------------------------------------------------------
# Step 1: Generate libplist configure script (autogen.sh also configures
#          in-source; we immediately distclean to allow out-of-tree build)
# ---------------------------------------------------------------------------
info "Running autogen.sh on libplist (generates ./configure)..."
cd "$LIBPLIST_SRC"
./autogen.sh 2>&1 | tail -3
# autogen.sh leaves the source tree configured in-tree; clean it up
# so we can do an out-of-tree build below.
make distclean 2>/dev/null || true
ok "autogen.sh done (source cleaned for out-of-tree build)."

# ---------------------------------------------------------------------------
# Step 2: Out-of-tree configure with our wrapper
# Always start fresh so the LLVM pass changes (e.g., InternalLinkage fix)
# are picked up — the autotools Makefile doesn't know about IntegrityPass.so.
# ---------------------------------------------------------------------------
LIBPLIST_BUILD="$BUILD_DIR/libplist-build"
info "Cleaning old build dir: $LIBPLIST_BUILD"
rm -rf "$LIBPLIST_BUILD"
mkdir -p "$LIBPLIST_BUILD"
cd "$LIBPLIST_BUILD"

info "Configuring libplist (CC=integrity-cc)..."
# Flags for C files (the core parsing/integer-heavy code):
#   CC=integrity-cc           our wrapper applies the Integrity pass
#   CFLAGS: -g -O1 + sancov   debuginfo + LibFuzzer coverage
# Flags for C++ files (thin wrappers, no interesting integer ops):
#   CXX=clang++-14            plain compiler — skip Integrity instrumentation
#   so C++ test binaries link correctly against libstdc++
CC="$WRAPPER" \
CFLAGS="-g -O1 -fsanitize=fuzzer-no-link" \
CXX="clang++-14" \
CXXFLAGS="-g -O1 -fsanitize=fuzzer-no-link" \
"$LIBPLIST_SRC/configure" \
    --without-cython \
    --disable-shared \
    --enable-static \
    --prefix="$BUILD_DIR/install" \
    2>&1 | tail -10

ok "Configure done."

# ---------------------------------------------------------------------------
# Step 3: Build ONLY the library (skip tools/test — they pull in C++ link
#          issues and we don't need them for fuzzing).
# ---------------------------------------------------------------------------
info "Building libplist C library with Integrity instrumentation..."
cd "$LIBPLIST_BUILD"

# Build the internal tree library first
make -C libcnary -j"$(nproc)" 2>&1 | tail -5

# Build the core library (C + C++ sources → libplist-2.0.a + libplist++-2.0.a)
make -C src -j"$(nproc)" 2>&1 | tail -15

ok "libplist library built."

# ---------------------------------------------------------------------------
# Step 4: Install headers and static lib manually
# ---------------------------------------------------------------------------
info "Installing libplist headers and static library..."
INSTALL_DIR="$BUILD_DIR/install"
mkdir -p "$INSTALL_DIR/include/plist" "$INSTALL_DIR/lib"

# Headers
cp "$LIBPLIST_SRC/include/plist/plist.h" "$INSTALL_DIR/include/plist/"
cp "$LIBPLIST_SRC/include/plist/plist++.h" "$INSTALL_DIR/include/plist/" 2>/dev/null || true
cp "$LIBPLIST_SRC/include/plist/"*.h "$INSTALL_DIR/include/plist/" 2>/dev/null || true

# Static library (C API only — sufficient for all fuzz targets)
cp "$LIBPLIST_BUILD/src/.libs/libplist-2.0.a" "$INSTALL_DIR/lib/"

ok "Installed to $INSTALL_DIR"

LIBPLIST_A="$INSTALL_DIR/lib/libplist-2.0.a"
LIBPLIST_INC="$INSTALL_DIR/include"

[[ -f "$LIBPLIST_A" ]] || die "Static library not found: $LIBPLIST_A"

# ---------------------------------------------------------------------------
# Step 5: Build fuzz targets
# ---------------------------------------------------------------------------
FUZZER_SRC_DIR="$LIBPLIST_SRC/fuzz"
FUZZ_OUT_DIR="$INTEGRITY_DIR/build"
CXX="clang++-14"

FORMATS=(bplist xplist jplist oplist)

for fmt in "${FORMATS[@]}"; do
    FUZZER_CC="$FUZZER_SRC_DIR/${fmt}_fuzzer.cc"
    FUZZER_BIN="$FUZZ_OUT_DIR/fuzz_libplist_${fmt}"

    info "Compiling fuzzer: fuzz_libplist_${fmt}"

    "$CXX" -g -O1 -fsanitize=fuzzer \
        "$FUZZER_CC" \
        -I "$LIBPLIST_INC" \
        "$LIBPLIST_A" \
        "$RT_OBJ" \
        -o "$FUZZER_BIN" \
        -Wno-unused-result

    ok "Built: $FUZZER_BIN"
done

# ---------------------------------------------------------------------------
# Step 6: Prepare corpus directories
# ---------------------------------------------------------------------------
info "Preparing corpus directories..."
CORPUS_BASE="$INTEGRITY_DIR/corpus/libplist"
for fmt in "${FORMATS[@]}"; do
    mkdir -p "$CORPUS_BASE/$fmt"
done

# Copy libplist's own test data as initial corpus
TESTDATA="$LIBPLIST_SRC/test/data"
if [[ -d "$TESTDATA" ]]; then
    cp "$TESTDATA"/*.bplist "$CORPUS_BASE/bplist/" 2>/dev/null || true
    cp "$TESTDATA"/*.plist  "$CORPUS_BASE/xplist/" 2>/dev/null || true
    cp "$TESTDATA"/*.json   "$CORPUS_BASE/jplist/" 2>/dev/null || true
    cp "$TESTDATA"/*.ostep  "$CORPUS_BASE/oplist/" 2>/dev/null || true
    ok "Copied test data to corpus."
fi

# Fall back: minimal valid seeds for empty corpus dirs
echo 'bpaa' > "$CORPUS_BASE/bplist/seed" 2>/dev/null || true  # bplist magic
echo '<?xml version="1.0"?><plist version="1.0"><true/></plist>' \
    > "$CORPUS_BASE/xplist/seed" 2>/dev/null || true
echo '{}' > "$CORPUS_BASE/jplist/seed" 2>/dev/null || true
echo '{}' > "$CORPUS_BASE/oplist/seed" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
ok "All done! Run fuzzers with:"
for fmt in "${FORMATS[@]}"; do
    echo "    $FUZZ_OUT_DIR/fuzz_libplist_${fmt} -max_total_time=60 $CORPUS_BASE/$fmt/"
done
