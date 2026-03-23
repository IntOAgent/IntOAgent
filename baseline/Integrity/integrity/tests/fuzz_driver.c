/**
 * fuzz_driver.c — LibFuzzer harness for Integrity test targets.
 *
 * The target function is declared externally; define TARGET_FUNCTION
 * at compile time or rely on linker to find target_function().
 *
 * Key properties:
 *  - Always returns 0 (never crash/abort)
 *  - Errors are reported to stderr by the runtime library
 *  - Reads exactly 8 bytes: two int32_t values (a, b)
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Declared in each CWE test file */
int32_t target_function(int32_t a, int32_t b);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 8) return 0;

  int32_t a, b;
  memcpy(&a, Data,     4);
  memcpy(&b, Data + 4, 4);

  target_function(a, b);

  return 0; /* Always 0: errors are non-crashing */
}
