/**
 * CWE-190: Integer Overflow or Wraparound
 *
 * Simple signed integer addition that overflows when both inputs
 * are near INT_MAX. The Integrity pass instruments the `a + b`
 * operation and reports OVERFLOW via __integrity_report().
 */
#include <stdint.h>

int32_t target_function(int32_t a, int32_t b) {
  /* CWE-190: signed addition overflow */
  int32_t result = a + b;
  return result;
}
