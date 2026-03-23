#ifndef INTEGRITY_RT_H
#define INTEGRITY_RT_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Report an integer error. Called by instrumented code.
 * NEVER aborts — continue-on-error semantics.
 *
 * @param file     Source file name
 * @param line     Source line number
 * @param col      Source column number
 * @param errcode  Error type (see below)
 */
void __integrity_report(const char *file, int line, int col, int errcode);

/* Error codes */
#define INTEGRITY_OVERFLOW    1
#define INTEGRITY_UNDERFLOW   2
#define INTEGRITY_DIV_ZERO    3
#define INTEGRITY_SHIFT_OVF   4
#define INTEGRITY_MININT_NEG1 5

#ifdef __cplusplus
}
#endif

#endif /* INTEGRITY_RT_H */
