#!/usr/bin/env bash
# targets/sqlite/build_shell.sh — Build the SQLite shell.c fuzzing harness.
#
# This harness includes shell.c directly so that shell.c functions such as
# local_getline, process_input, and do_meta_command are reachable during
# fuzzing.  The ossfuzz.c/dbfuzz2.c harnesses bypass shell.c entirely.
#
# Outputs:
#   build/fuzz_sqlite_shell           — Integrity-instrumented LibFuzzer binary
#   build/coverage/fuzz_sqlite_shell_cov — Coverage-instrumented binary
#
# Usage:
#   bash targets/sqlite/build_shell.sh
#   ./build/fuzz_sqlite_shell -max_total_time=120 corpus/sqlite/shell/ 2>shell.log

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRITY_DIR="$(realpath "$SCRIPT_DIR/../..")"
BUILD="$INTEGRITY_DIR/build/sqlite_shell"
SQLITE_SRC="/home/xxx/PHDlife/fuxian/sqlite"
CC="$INTEGRITY_DIR/scripts/integrity-cc"
BASE_CLANG="${INTEGRITY_CLANG:-clang-14}"
PASS="$INTEGRITY_DIR/build/IntegrityPass.so"
RT_OBJ="$INTEGRITY_DIR/build/integrity_rt.o"
HARNESS="$SCRIPT_DIR/fuzz_sqlite_shell.c"
COV_BUILD="$INTEGRITY_DIR/build/coverage"

SQLITE_DEFS=(
    -DSQLITE_THREADSAFE=0
    -DSQLITE_OMIT_LOAD_EXTENSION
    -DSQLITE_DEFAULT_MEMSTATUS=0
    -DSQLITE_MAX_EXPR_DEPTH=0
    -DSQLITE_ENABLE_RTREE
    -DSQLITE_ENABLE_FTS4
    -DSQLITE_ENABLE_FTS5
    -DSQLITE_ENABLE_DBSTAT_VTAB
    -DSQLITE_ENABLE_MATH_FUNCTIONS
    -DSQLITE_ENABLE_RBU
)

echo "=== SQLite shell.c Integrity Build ==="
echo "SQLite source: $SQLITE_SRC"
echo "Build dir:     $BUILD"
mkdir -p "$BUILD" "$COV_BUILD"

# ---------------------------------------------------------------------------
# Sanity checks
# ---------------------------------------------------------------------------
if [[ ! -f "$SQLITE_SRC/sqlite3.c" ]]; then
    echo "ERROR: sqlite3.c not found at $SQLITE_SRC/sqlite3.c"
    exit 1
fi
if [[ ! -f "$SQLITE_SRC/shell.c" ]]; then
    echo "ERROR: shell.c not found at $SQLITE_SRC/shell.c"
    exit 1
fi
if [[ ! -f "$PASS" ]]; then
    echo "ERROR: IntegrityPass.so not found. Run: make toolchain"
    exit 1
fi

# ---------------------------------------------------------------------------
# Phase 1: Instrument sqlite3.c (library core) with Integrity pass
# ---------------------------------------------------------------------------
echo ""
echo "[1/5] Compiling sqlite3.c with Integrity instrumentation..."
INTEGRITY_OUTDIR="$BUILD" \
    "$CC" -g -O1 -c \
    -I"$SQLITE_SRC" \
    "${SQLITE_DEFS[@]}" \
    "$SQLITE_SRC/sqlite3.c" \
    -o "$BUILD/sqlite3.o"
echo "      Done: $BUILD/sqlite3.o"

# ---------------------------------------------------------------------------
# Phase 2: Compile fuzz_sqlite_shell.c (which #includes shell.c) with
#          Integrity pass + LibFuzzer instrumentation.
#
#          -DSHELL_C_PATH sets the path for #include SHELL_C_PATH inside
#          fuzz_sqlite_shell.c, pointing it to the actual shell.c source.
# ---------------------------------------------------------------------------
echo ""
echo "[2/5] Compiling shell.c harness with Integrity instrumentation..."
INTEGRITY_OUTDIR="$BUILD" \
    "$CC" -g -O1 -c \
    -fsanitize=fuzzer-no-link \
    -I"$SQLITE_SRC" \
    "${SQLITE_DEFS[@]}" \
    "-DSHELL_C_PATH=\"$SQLITE_SRC/shell.c\"" \
    "$HARNESS" \
    -o "$BUILD/fuzz_sqlite_shell_harness.o"
echo "      Done: $BUILD/fuzz_sqlite_shell_harness.o"

# ---------------------------------------------------------------------------
# Phase 3: Link Integrity fuzzer binary
# ---------------------------------------------------------------------------
echo ""
echo "[3/5] Linking Integrity fuzz binary..."
"$BASE_CLANG" -g -O1 -fsanitize=fuzzer \
    "$BUILD/fuzz_sqlite_shell_harness.o" \
    "$BUILD/sqlite3.o" \
    "$RT_OBJ" \
    -lm -ldl -lz \
    -Wl,--wrap,exit \
    -o "$INTEGRITY_DIR/build/fuzz_sqlite_shell"
echo "      Built: build/fuzz_sqlite_shell"

# ---------------------------------------------------------------------------
# Phase 4: Build coverage binary (same sources, no Integrity pass)
# ---------------------------------------------------------------------------
echo ""
echo "[4/5] Building coverage binary..."

# sqlite3.c (coverage)
"$BASE_CLANG" -g -O1 -c \
    -fprofile-instr-generate -fcoverage-mapping \
    -I"$SQLITE_SRC" \
    "${SQLITE_DEFS[@]}" \
    "$SQLITE_SRC/sqlite3.c" \
    -o "$COV_BUILD/sqlite3_shell_cov.o"

# fuzz_sqlite_shell.c + shell.c (coverage)
"$BASE_CLANG" -g -O1 -c \
    -fsanitize=fuzzer-no-link \
    -fprofile-instr-generate -fcoverage-mapping \
    -I"$SQLITE_SRC" \
    "${SQLITE_DEFS[@]}" \
    "-DSHELL_C_PATH=\"$SQLITE_SRC/shell.c\"" \
    -DFUZZER_COVERAGE_BUILD \
    "$HARNESS" \
    -o "$COV_BUILD/fuzz_sqlite_shell_harness_cov.o"

# Link coverage binary (no --wrap,exit needed; __wrap_exit undefined → link error
# unless we provide a stub)
cat > "$COV_BUILD/exit_stub.c" <<'EOF'
/* Stub for coverage build: no exit interception needed */
void __real_exit(int code) { _exit(code); }
EOF
"$BASE_CLANG" -c -o "$COV_BUILD/exit_stub.o" "$COV_BUILD/exit_stub.c"

"$BASE_CLANG" -g -O1 -fsanitize=fuzzer \
    -fprofile-instr-generate -fcoverage-mapping \
    "$COV_BUILD/fuzz_sqlite_shell_harness_cov.o" \
    "$COV_BUILD/sqlite3_shell_cov.o" \
    "$COV_BUILD/exit_stub.o" \
    -lm -ldl -lz \
    -Wl,--wrap,exit \
    -o "$COV_BUILD/fuzz_sqlite_shell_cov"
echo "      Built: build/coverage/fuzz_sqlite_shell_cov"

# ---------------------------------------------------------------------------
# Phase 5: Seed corpus
# ---------------------------------------------------------------------------
echo ""
echo "[5/5] Setting up seed corpus..."
SHELL_CORPUS="$INTEGRITY_DIR/corpus/sqlite/shell"
mkdir -p "$SHELL_CORPUS"

if [[ ! -f "$SHELL_CORPUS/seed_select.sql" ]]; then
    echo "SELECT 1+1;"                                         > "$SHELL_CORPUS/seed_select.sql"
    echo "CREATE TABLE t(a,b); INSERT INTO t VALUES(1,2);"    > "$SHELL_CORPUS/seed_create.sql"
    echo "SELECT * FROM sqlite_master;"                        > "$SHELL_CORPUS/seed_master.sql"
    echo "SELECT abs(-1), hex(42), length('hello');"          > "$SHELL_CORPUS/seed_funcs.sql"
    echo "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt WHERE x<5) SELECT * FROM cnt;" \
                                                               > "$SHELL_CORPUS/seed_cte.sql"
    echo "SELECT max(2147483647+1);"                           > "$SHELL_CORPUS/seed_overflow.sql"
    echo "SELECT 1<<62;"                                       > "$SHELL_CORPUS/seed_shift.sql"
    echo ".tables"                                             > "$SHELL_CORPUS/seed_dot_tables"
    echo ".schema"                                             > "$SHELL_CORPUS/seed_dot_schema"
fi
echo "      Corpus: $(ls "$SHELL_CORPUS" | wc -l) seeds at $SHELL_CORPUS"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "=== Build complete ==="
echo ""
echo "Run:"
echo "  cd $INTEGRITY_DIR"
echo "  ./build/fuzz_sqlite_shell -max_total_time=120 corpus/sqlite/shell/ 2>build/fuzz_sqlite_shell.log"
echo ""
echo "Filter results:"
echo "  grep 'INTEGRITY' build/fuzz_sqlite_shell.log | sort -u"
