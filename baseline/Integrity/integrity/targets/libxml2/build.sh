#!/usr/bin/env bash
# targets/libxml2/build.sh
#
# One-stop script: builds libxml2 with Integrity instrumentation and
# produces fuzz binaries (xml, html, xpath, regexp) using LibFuzzer.
#
# Prerequisites:
#   clang-14, opt-14, autoconf, automake, libtool, pkg-config, zlib-dev
#
# Usage:
#   cd /path/to/integrity
#   ./targets/libxml2/build.sh
#
# Output:
#   build/fuzz_libxml2_xml
#   build/fuzz_libxml2_html
#   build/fuzz_libxml2_xpath
#   build/fuzz_libxml2_regexp

set -euo pipefail

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRITY_DIR="$(realpath "$SCRIPT_DIR/../..")"
LIBXML2_SRC="$(realpath "$INTEGRITY_DIR/../libxml2")"
WRAPPER="$INTEGRITY_DIR/scripts/integrity-cc"
RT_OBJ="$INTEGRITY_DIR/build/integrity_rt.o"
PASS_SO="$INTEGRITY_DIR/build/IntegrityPass.so"
BUILD_DIR="$INTEGRITY_DIR/build/libxml2"
LIBXML2_BUILD="$BUILD_DIR/libxml2-build"
INSTALL_DIR="$BUILD_DIR/install"
FUZZ_SRC="$LIBXML2_SRC/fuzz"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info() { echo -e "\033[1;36m[*]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*"; }
die()  { echo -e "\033[1;31m[!]\033[0m $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Sanity checks
# ---------------------------------------------------------------------------
[[ -d "$LIBXML2_SRC" ]] || die "libxml2 source not found at $LIBXML2_SRC"
[[ -f "$LIBXML2_SRC/autogen.sh" ]] || die "autogen.sh not found in $LIBXML2_SRC"

# ---------------------------------------------------------------------------
# Step 0: Build Integrity toolchain if needed
# ---------------------------------------------------------------------------
info "Building Integrity pass and runtime..."
make -C "$INTEGRITY_DIR" build/IntegrityPass.so build/integrity_rt.o \
    --no-print-directory -j"$(nproc)"
ok "Integrity toolchain ready."

# ---------------------------------------------------------------------------
# Step 1: Generate libxml2 configure script
# ---------------------------------------------------------------------------
info "Running autogen.sh on libxml2 (generates ./configure)..."
cd "$LIBXML2_SRC"
./autogen.sh 2>&1 | tail -3
make distclean 2>/dev/null || true
ok "autogen.sh done."

# ---------------------------------------------------------------------------
# Step 2: Out-of-tree configure with Integrity wrapper
# ---------------------------------------------------------------------------
info "Cleaning old build dir: $LIBXML2_BUILD"
rm -rf "$LIBXML2_BUILD"
mkdir -p "$LIBXML2_BUILD"
cd "$LIBXML2_BUILD"

info "Configuring libxml2 (CC=integrity-cc)..."
CC="$WRAPPER" \
CFLAGS="-g -O1 -fsanitize=fuzzer-no-link" \
INTEGRITY_DIR="$INTEGRITY_DIR" \
"$LIBXML2_SRC/configure" \
    --disable-shared \
    --enable-static \
    --without-python \
    --without-http \
    --without-lzma \
    --prefix="$INSTALL_DIR" \
    2>&1 | tail -10
ok "Configure done."

# ---------------------------------------------------------------------------
# Step 3: Build the library
# ---------------------------------------------------------------------------
info "Building libxml2 with Integrity instrumentation..."
make -j"$(nproc)" 2>&1 | tail -15
ok "libxml2 built."

# ---------------------------------------------------------------------------
# Step 4: Install headers and static library
# ---------------------------------------------------------------------------
info "Installing to $INSTALL_DIR..."
make install 2>&1 | tail -5
ok "Installed."

LIBXML2_A="$INSTALL_DIR/lib/libxml2.a"
[[ -f "$LIBXML2_A" ]] || die "Static library not found: $LIBXML2_A"

# ---------------------------------------------------------------------------
# Step 5: Build fuzz targets
# ---------------------------------------------------------------------------
# Harnesses selected for integer-error relevance:
#   xml     — full XML parser (most arithmetic: lengths, offsets, counters)
#   html    — HTML parser (similar arithmetic, more lenient parsing)
#   xpath   — XPath evaluator (explicit integer arithmetic in expressions)
#   regexp  — regex NFA/DFA (state machine: counter + position arithmetic)
HARNESSES=(xml html xpath regexp)

FUZZ_OUT="$INTEGRITY_DIR/build"

for h in "${HARNESSES[@]}"; do
    HARNESS_SRC="$FUZZ_SRC/${h}.c"
    FUZZER_BIN="$FUZZ_OUT/fuzz_libxml2_${h}"

    [[ -f "$HARNESS_SRC" ]] || { info "Skipping $h (no harness source)"; continue; }

    info "Compiling fuzzer: fuzz_libxml2_${h}"

    clang-14 -g -O1 -fsanitize=fuzzer \
        "$HARNESS_SRC" \
        "$FUZZ_SRC/fuzz.c" \
        -I "$INSTALL_DIR/include/libxml2" \
        -I "$FUZZ_SRC" \
        "$LIBXML2_A" \
        "$RT_OBJ" \
        -lz -lm \
        -o "$FUZZER_BIN"

    ok "Built: $FUZZER_BIN"
done

# ---------------------------------------------------------------------------
# Step 6: Prepare corpus directories
# ---------------------------------------------------------------------------
info "Preparing corpus directories..."
CORPUS_BASE="$INTEGRITY_DIR/corpus/libxml2"
for h in "${HARNESSES[@]}"; do
    mkdir -p "$CORPUS_BASE/$h"
done

# Copy libxml2's own seed data
SEED_DIR="$FUZZ_SRC/static_seed"
if [[ -d "$SEED_DIR" ]]; then
    for h in "${HARNESSES[@]}"; do
        if [[ -d "$SEED_DIR/$h" ]]; then
            cp "$SEED_DIR/$h/"* "$CORPUS_BASE/$h/" 2>/dev/null || true
        fi
    done
    ok "Copied static seeds to corpus."
fi

# Copy test XML files as xml/html corpus seeds
find "$LIBXML2_SRC/test" -name "*.xml" -size -64k 2>/dev/null \
    | head -50 | xargs -I{} cp {} "$CORPUS_BASE/xml/" 2>/dev/null || true
find "$LIBXML2_SRC/test" -name "*.html" -size -64k 2>/dev/null \
    | head -20 | xargs -I{} cp {} "$CORPUS_BASE/html/" 2>/dev/null || true

# Fallback minimal seeds
[[ -z "$(ls -A "$CORPUS_BASE/xml/" 2>/dev/null)" ]] && \
    echo '<root/>' > "$CORPUS_BASE/xml/seed"
[[ -z "$(ls -A "$CORPUS_BASE/html/" 2>/dev/null)" ]] && \
    echo '<html><body></body></html>' > "$CORPUS_BASE/html/seed"
[[ -z "$(ls -A "$CORPUS_BASE/xpath/" 2>/dev/null)" ]] && \
    echo '/root/child' > "$CORPUS_BASE/xpath/seed"
[[ -z "$(ls -A "$CORPUS_BASE/regexp/" 2>/dev/null)" ]] && \
    echo 'a*b+' > "$CORPUS_BASE/regexp/seed"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
ok "All done! Run fuzzers with:"
FUZZ_OUT="$INTEGRITY_DIR/build"
for h in "${HARNESSES[@]}"; do
    echo "    $FUZZ_OUT/fuzz_libxml2_${h} -max_total_time=60 $CORPUS_BASE/${h}/"
done
