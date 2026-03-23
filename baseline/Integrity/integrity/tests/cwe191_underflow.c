/**
 * CWE-191: Integer Underflow (Wrap or Wraparound)
 *
 * Signed integer subtraction that underflows when `a` is near INT_MIN
 * and `b` is a large positive value. The Integrity pass instruments
 * the `a - b` operation and reports UNDERFLOW.
 */
#include <stdint.h>

int32_t target_function(int32_t a, int32_t b) {
  /* CWE-191: signed subtraction underflow */
  int32_t result = a - b;
  return result;
}
