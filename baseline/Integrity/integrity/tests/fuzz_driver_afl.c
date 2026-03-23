/**
 * fuzz_driver_afl.c — AFL persistent-mode harness for Integrity test targets.
 *
 * Compatible with both AFL (via __AFL_LOOP deferred forkserver) and plain
 * execution (when AFL macros expand to no-ops without aflgo-clang).
 *
 * Usage:
 *   Compiled with aflgo-clang, which defines __AFL_LOOP() and __AFL_INIT().
 *   The binary reads 8 bytes from stdin (two int32_t values a, b) per iteration.
 *
 * Key properties:
 *   - NEVER crashes or aborts: errors are recorded by integrity_rt.c
 *   - Reads from stdin (AFL file-based or pipe mode via @@)
 *   - Persistent mode: __AFL_LOOP(10000) runs up to 10000 inputs per fork
 */

#include <unistd.h>
#include <stdint.h>
#include <string.h>

/* Declared in each CWE test file (cwe190_overflow.c, etc.) */
int32_t target_function(int32_t a, int32_t b);

int main(void) {
  uint8_t buf[8];

  /* Deferred forkserver + persistent loop: AFL forks here, then each child
     processes up to 10000 inputs before exiting. This avoids the overhead
     of forking for every single input. */
  __AFL_INIT();

  while (__AFL_LOOP(10000)) {
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
    if (n < 8) continue;

    int32_t a, b;
    memcpy(&a, buf,     4);
    memcpy(&b, buf + 4, 4);

    target_function(a, b);
    /* Always returns normally — errors logged to stderr by runtime */
  }

  return 0;
}
