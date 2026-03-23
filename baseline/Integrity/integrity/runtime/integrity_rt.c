/**
 * integrity_rt.c — Runtime library for the Integrity instrumentation pass.
 *
 * Key design properties (matching the paper):
 *  - Continue-on-error: NEVER abort, exit, or raise a signal
 *  - Deduplication: ring-buffer of (file, line, col, errcode) tuples
 *  - Summary report at exit via atexit()
 *  - Extra counter in __libfuzzer_extra_counters for LibFuzzer coverage
 */

#include "integrity_rt.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* =========================================================================
 * LibFuzzer extra counters — one global counter for the runtime itself
 * ========================================================================= */
__attribute__((section("__libfuzzer_extra_counters")))
static volatile uint8_t __integrity_rt_counter = 0;

/* =========================================================================
 * Error name table
 * ========================================================================= */
static const char *errname(int code) {
  switch (code) {
    case 1: return "OVERFLOW";
    case 2: return "UNDERFLOW";
    case 3: return "DIV_BY_ZERO";
    case 4: return "SHIFT_OVF";
    case 5: return "MININT_DIV_NEG1";
    default: return "UNKNOWN";
  }
}

/* =========================================================================
 * Deduplication ring buffer (no dynamic allocation)
 * ========================================================================= */
#define MAX_UNIQUE_ERRORS 256
#define MAX_DROPPED_ERRORS 1000000

typedef struct {
  const char *file;
  int line;
  int col;
  int errcode;
  unsigned count; // how many times this exact error was seen
} ErrorEntry;

static ErrorEntry error_ring[MAX_UNIQUE_ERRORS];
static int        error_count = 0;    // number of unique errors stored
static long long  dropped_count = 0;  // errors dropped due to ring full

/* Simple lookup: returns index if found, -1 otherwise */
static int find_error(const char *file, int line, int col, int errcode) {
  for (int i = 0; i < error_count; i++) {
    ErrorEntry *e = &error_ring[i];
    if (e->line == line && e->col == col && e->errcode == errcode &&
        e->file != NULL && strcmp(e->file, file) == 0)
      return i;
  }
  return -1;
}

/* =========================================================================
 * Main report function — called by instrumented code
 * ========================================================================= */
void __integrity_report(const char *file, int line, int col, int errcode) {
  /* Signal LibFuzzer that a new event occurred */
  __integrity_rt_counter++;

  /* Check dedup ring */
  int idx = find_error(file, line, col, errcode);
  if (idx >= 0) {
    error_ring[idx].count++;
    return; // Already reported
  }

  /* Ring full: drop */
  if (error_count >= MAX_UNIQUE_ERRORS) {
    dropped_count++;
    return;
  }

  /* New unique error: store it */
  ErrorEntry *e = &error_ring[error_count++];
  e->file    = file;
  e->line    = line;
  e->col     = col;
  e->errcode = errcode;
  e->count   = 1;

  /* Print immediately to stderr */
  fprintf(stderr, "[INTEGRITY] %s at %s:%d:%d\n",
          errname(errcode), file ? file : "<unknown>", line, col);
  fflush(stderr);
}

/* =========================================================================
 * Summary dump at program exit
 * ========================================================================= */
static void integrity_summary(void) {
  fprintf(stderr,
          "[INTEGRITY] === Error Summary (%d unique, %lld dropped) ===\n",
          error_count, dropped_count);
  for (int i = 0; i < error_count; i++) {
    ErrorEntry *e = &error_ring[i];
    fprintf(stderr, "[INTEGRITY]   [%d] %s at %s:%d:%d (count=%u)\n",
            i + 1, errname(e->errcode),
            e->file ? e->file : "<unknown>",
            e->line, e->col, e->count);
  }
  fflush(stderr);
}

/* =========================================================================
 * Constructor: register atexit handler
 * ========================================================================= */
__attribute__((constructor))
static void integrity_init(void) {
  atexit(integrity_summary);
}
