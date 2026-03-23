/**
 * CWE-369: Divide By Zero
 *
 * Two bugs:
 *  1. Division by zero when b == 0
 *  2. INT_MIN / -1 causes signed overflow (MININT_DIV_NEG1)
 *
 * Both are detected by the Integrity pass's instrumentDivRem().
 */
#include <stdint.h>

int32_t target_function(int32_t a, int32_t b) {
  /* CWE-369: divide by zero; also catches INT_MIN / -1 */
  int32_t result = a / b;
  return result;
}
