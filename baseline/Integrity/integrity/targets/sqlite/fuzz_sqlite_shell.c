/*
** fuzz_sqlite_shell.c — LibFuzzer harness for the SQLite interactive shell.
**
** Purpose: Exercise shell.c code paths (local_getline, process_input, etc.)
**          that are unreachable via the ossfuzz.c/dbfuzz2.c harnesses which
**          call the SQLite library API directly, bypassing shell.c entirely.
**
** Technique: #include shell.c directly (with main renamed) so that all its
**            static functions (ShellState, process_input, local_getline) are
**            visible to this compilation unit.  The Integrity pass then
**            instruments arithmetic in both shell.c and the harness glue.
**
** Build:
**   integrity-cc -g -O1 -c -fsanitize=fuzzer-no-link \
**       -DSHELL_C_PATH=\"/path/to/shell.c\" \
**       -I /path/to/sqlite-src \
**       fuzz_sqlite_shell.c -o fuzz_sqlite_shell_harness.o
**
** Link:
**   clang-14 -fsanitize=fuzzer -g -O1 \
**       fuzz_sqlite_shell_harness.o sqlite3.o integrity_rt.o \
**       -lm -ldl -lz -Wl,--wrap,exit -o fuzz_sqlite_shell
*/

#include <setjmp.h>
#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------
** Rename shell.c's main() to avoid conflict with LibFuzzer's main().
** ------------------------------------------------------------------- */
#define main sqlite3_shell_main_NOLINK

/* -------------------------------------------------------------------
** SQLite and shell compile-time flags (must match sqlite3.c build).
** ------------------------------------------------------------------- */
#ifndef SQLITE_THREADSAFE
#  define SQLITE_THREADSAFE 0
#endif
#ifndef SQLITE_OMIT_LOAD_EXTENSION
#  define SQLITE_OMIT_LOAD_EXTENSION
#endif
#ifndef SQLITE_DEFAULT_MEMSTATUS
#  define SQLITE_DEFAULT_MEMSTATUS 0
#endif
#ifndef SQLITE_MAX_EXPR_DEPTH
#  define SQLITE_MAX_EXPR_DEPTH 0
#endif
#ifndef SQLITE_ENABLE_RTREE
#  define SQLITE_ENABLE_RTREE
#endif
#ifndef SQLITE_ENABLE_FTS4
#  define SQLITE_ENABLE_FTS4
#endif
#ifndef SQLITE_ENABLE_FTS5
#  define SQLITE_ENABLE_FTS5
#endif
#ifndef SQLITE_ENABLE_DBSTAT_VTAB
#  define SQLITE_ENABLE_DBSTAT_VTAB
#endif
#ifndef SQLITE_ENABLE_MATH_FUNCTIONS
#  define SQLITE_ENABLE_MATH_FUNCTIONS
#endif
#ifndef SQLITE_ENABLE_RBU
#  define SQLITE_ENABLE_RBU
#endif

/* -------------------------------------------------------------------
** Include the SQLite shell source.
** SHELL_C_PATH must be set at compile time via -DSHELL_C_PATH=\"...\"
** ------------------------------------------------------------------- */
#ifndef SHELL_C_PATH
#  error "Define SHELL_C_PATH to the path of shell.c"
#endif
#include SHELL_C_PATH

/* Restore 'main' for our own entry points */
#undef main

/* -------------------------------------------------------------------
** exit() interception via --wrap,exit.
**
** shell.c calls exit() in rare paths (OOM, .open failure, bad nonce).
** We intercept these and longjmp back to the fuzzer loop instead of
** actually terminating the process.
** ------------------------------------------------------------------- */
static jmp_buf  g_exit_jmpbuf;
static volatile int g_in_fuzz = 0;

/* Provided by the linker when linked with -Wl,--wrap,exit */
void __real_exit(int code);

void __wrap_exit(int code) {
    if (g_in_fuzz) {
        longjmp(g_exit_jmpbuf, code ? code : 1);
    }
    __real_exit(code);
}

/* -------------------------------------------------------------------
** Global resources initialised once.
** ------------------------------------------------------------------- */
static FILE *g_devnull = NULL;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    g_devnull = fopen("/dev/null", "w");
    return 0;
}

/* -------------------------------------------------------------------
** Main fuzzer entry point.
** -------------------------------------------------------------------
** Strategy:
**   1. Write fuzz bytes to a tmpfile.
**   2. Initialise a fresh ShellState pointing at that tmpfile.
**   3. Call process_input() — which calls one_input_line() → local_getline().
**   4. Clean up.
** ------------------------------------------------------------------- */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    /* ---- Feed fuzz bytes as shell input via a tmpfile ---- */
    FILE *fin = tmpfile();
    if (!fin) return 0;
    fwrite(Data, 1, Size, fin);
    rewind(fin);

    /* ---- Minimal ShellState init (no sqlite3_config calls) ---- */
    ShellState data;
    memset(&data, 0, sizeof(data));
    data.normalMode = data.cMode = data.mode = MODE_List;
    data.autoExplain = 1;
    data.pAuxDb = &data.aAuxDb[0];
    data.shellFlgs = SHFLG_Lookaside;
    memcpy(data.colSeparator, SEP_Column, 2);
    memcpy(data.rowSeparator, SEP_Row, 2);

    /* Suppress all output */
    data.out = g_devnull ? g_devnull : stderr;

    /* Open an in-memory database */
    if (sqlite3_open(":memory:", &data.db) != SQLITE_OK) {
        fclose(fin);
        return 0;
    }

    /* Resource limits: prevent infinite loops */
    sqlite3_limit(data.db, SQLITE_LIMIT_VDBE_OP,  25000);  /* max VM ops (no infinite loops) */
    sqlite3_limit(data.db, SQLITE_LIMIT_LENGTH,   50000);  /* max string/blob */

    /* ---- Run process_input with FILE* → exercises local_getline ---- */
    stdin_is_interactive = 0;   /* global in shell.c */
    bail_on_error = 0;          /* global in shell.c */
    data.in = fin;              /* non-NULL → one_input_line uses FILE* path */

    g_in_fuzz = 1;
    if (setjmp(g_exit_jmpbuf) == 0) {
        process_input(&data);   /* static function from shell.c */
    }
    g_in_fuzz = 0;

    /* ---- Cleanup ---- */
    if (data.db) {
        sqlite3_close(data.db);
        data.db = 0;
    }
    /* process_input may have closed data.in on .quit / end-of-file handling */
    if (data.in && data.in != fin) {
        fclose(data.in);
    }
    fclose(fin);
    return 0;
}
