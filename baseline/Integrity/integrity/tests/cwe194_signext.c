/**
 * CWE-194: Unexpected Sign Extension / Narrow Type Overflow
 *
 * Multiplication of two int8_t values produces a result that is
 * truncated back to int8_t. This truncation can lose significant bits
 * when the product exceeds the int8_t range (-128..127).
 *
 * Example: 16 * 16 = 256, but truncated to int8_t gives 0.
 *          12 * 12 = 144, but truncated to int8_t gives -112.
 *
 * The Integrity pass (compiled at -O0 to preserve the i8 trunc):
 *  - sees a 32-bit mul with a trunc i32->i8 user
 *  - inferWidth() returns 8
 *  - promotes operands to i16, checks against i8 bounds
 *  - reports OVERFLOW / UNDERFLOW
 */
#include <stdint.h>

int32_t target_function(int32_t a, int32_t b) {
  int8_t na = (int8_t)a;
  int8_t nb = (int8_t)b;
  /* CWE-194: narrow-type multiplication; result truncated to i8 */
  int8_t narrow_result = na * nb;
  return (int32_t)narrow_result;
}
