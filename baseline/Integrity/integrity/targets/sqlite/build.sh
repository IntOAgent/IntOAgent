#!/usr/bin/env bash
# targets/sqlite/build.sh — Build SQLite 3.52.0 with Integrity instrumentation.
#
# Harnesses:
#   fuzz_sqlite_sql    — ossfuzz.c: takes SQL text, runs via sqlite3_exec (in-memory DB)
#   fuzz_sqlite_db     — dbfuzz2.c: takes SQLite DB files, runs fixed SQL queries
#
# Requires:
#   build/IntegrityPass.so and build/integrity_rt.o already built (make toolchain)
#
# Usage:
#   bash targets/sqlite/build.sh
#   ./build/fuzz_sqlite_sql -max_total_time=60 corpus/sqlite/sql/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRITY_DIR="$(realpath "$SCRIPT_DIR/../..")"
BUILD="$INTEGRITY_DIR/build/sqlite"
SQLITE_SRC="/home/xxx/PHDlife/fuxian/sqlite"
CC="$INTEGRITY_DIR/scripts/integrity-cc"
BASE_CLANG="${INTEGRITY_CLANG:-clang-14}"
PASS="$INTEGRITY_DIR/build/IntegrityPass.so"
RT_OBJ="$INTEGRITY_DIR/build/integrity_rt.o"

# SQLite compile-time flags for fuzzing
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

echo "=== SQLite Integrity Build ==="
echo "SQLite source: $SQLITE_SRC"
echo "Build dir: $BUILD"
mkdir -p "$BUILD"

# ---------------------------------------------------------------------------
# Sanity checks
# ---------------------------------------------------------------------------
if [[ ! -f "$SQLITE_SRC/sqlite3.c" ]]; then
    echo "ERROR: sqlite3.c not found at $SQLITE_SRC/sqlite3.c"
    echo "  Run: cd $SQLITE_SRC && ./configure --disable-tcl && make sqlite3.c"
    exit 1
fi

if [[ ! -f "$PASS" ]]; then
    echo "ERROR: IntegrityPass.so not found. Run: make toolchain"
    exit 1
fi

# ---------------------------------------------------------------------------
# Phase 0: Instrument sqlite3.c → BC → object
# ---------------------------------------------------------------------------
echo ""
echo "[1/4] Compiling sqlite3.c amalgamation with Integrity instrumentation..."

INTEGRITY_OUTDIR="$BUILD" \
    "$CC" -g -O1 -c \
    -I"$SQLITE_SRC" \
    "${SQLITE_DEFS[@]}" \
    "$SQLITE_SRC/sqlite3.c" \
    -o "$BUILD/sqlite3.o"

echo "      Done: $BUILD/sqlite3.o"

# ---------------------------------------------------------------------------
# Phase 1: Compile harness objects (plain clang, no Integrity on harness code)
# ---------------------------------------------------------------------------
echo ""
echo "[2/4] Compiling harness: ossfuzz.c (SQL text fuzzer)..."
"$BASE_CLANG" -g -O1 -c \
    -I"$SQLITE_SRC" \
    -fsanitize=fuzzer-no-link \
    "$SQLITE_SRC/test/ossfuzz.c" \
    -o "$BUILD/ossfuzz.o"

echo "[2/4] Compiling harness: dbfuzz2.c (DB file fuzzer)..."
"$BASE_CLANG" -g -O1 -c \
    -I"$SQLITE_SRC" \
    -fsanitize=fuzzer-no-link \
    -DSQLITE_ENABLE_DBSTAT_VTAB \
    "$SQLITE_SRC/test/dbfuzz2.c" \
    -o "$BUILD/dbfuzz2.o"

# ---------------------------------------------------------------------------
# Phase 2: Link fuzz binaries
# ---------------------------------------------------------------------------
echo ""
echo "[3/4] Linking fuzz binaries..."

"$BASE_CLANG" -g -O1 -fsanitize=fuzzer \
    "$BUILD/ossfuzz.o" \
    "$BUILD/sqlite3.o" \
    "$RT_OBJ" \
    -lm -ldl -lz \
    -o "$INTEGRITY_DIR/build/fuzz_sqlite_sql"
echo "      Built: build/fuzz_sqlite_sql"

"$BASE_CLANG" -g -O1 -fsanitize=fuzzer \
    "$BUILD/dbfuzz2.o" \
    "$BUILD/sqlite3.o" \
    "$RT_OBJ" \
    -lm -ldl -lz \
    -o "$INTEGRITY_DIR/build/fuzz_sqlite_db"
echo "      Built: build/fuzz_sqlite_db"

# ---------------------------------------------------------------------------
# Phase 3: Seed corpus
# ---------------------------------------------------------------------------
echo ""
echo "[4/4] Setting up seed corpus..."

SQL_CORPUS="$INTEGRITY_DIR/corpus/sqlite/sql"
DB_CORPUS="$INTEGRITY_DIR/corpus/sqlite/db"
mkdir -p "$SQL_CORPUS" "$DB_CORPUS"

# SQL seeds: simple statements covering common SQLite paths
if [[ ! -f "$SQL_CORPUS/seed_select.sql" ]]; then
    echo "SELECT 1+1;" > "$SQL_CORPUS/seed_select.sql"
    echo "CREATE TABLE t1(a,b); INSERT INTO t1 VALUES(1,2); SELECT * FROM t1;" \
        > "$SQL_CORPUS/seed_create.sql"
    echo "SELECT abs(-1), hex(42), length('hello'), typeof(3.14);" \
        > "$SQL_CORPUS/seed_funcs.sql"
    echo "CREATE TABLE t1(a INTEGER PRIMARY KEY, b TEXT); INSERT INTO t1 VALUES(1,'x'); SELECT a+b FROM t1;" \
        > "$SQL_CORPUS/seed_types.sql"
    echo "CREATE VIRTUAL TABLE t USING fts4(content); INSERT INTO t VALUES('hello world'); SELECT * FROM t WHERE t MATCH 'hello';" \
        > "$SQL_CORPUS/seed_fts4.sql"
    echo "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt WHERE x<10) SELECT sum(x) FROM cnt;" \
        > "$SQL_CORPUS/seed_cte.sql"
    echo "SELECT max(2147483647+1);" \
        > "$SQL_CORPUS/seed_overflow.sql"
    echo "SELECT 1<<62, 1<<63, 0x7fffffff+1;" \
        > "$SQL_CORPUS/seed_shift.sql"
fi

# DB seeds: copy existing SQLite database seed files
for db in "$SQLITE_SRC/test/"fuzzdata*.db "$SQLITE_SRC/test/dbfuzz2-seed1.db"; do
    [[ -f "$db" ]] && cp -n "$db" "$DB_CORPUS/" 2>/dev/null || true
done
echo "      SQL corpus: $(ls "$SQL_CORPUS" | wc -l) seeds at $SQL_CORPUS"
echo "      DB corpus:  $(ls "$DB_CORPUS" | wc -l) seeds at $DB_CORPUS"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "=== Build complete ==="
echo ""
echo "Run the LibFuzzer harnesses:"
echo "  cd $INTEGRITY_DIR"
echo "  ./build/fuzz_sqlite_sql -max_total_time=120 corpus/sqlite/sql/ 2>sql.log"
echo "  ./build/fuzz_sqlite_db  -max_total_time=120 corpus/sqlite/db/  2>db.log"
echo ""
echo "Filter results:"
echo "  grep 'INTEGRITY' sql.log | sort -u"
