/*
 * afl_shim.c — AFL-compatible main() wrapper for libxml2 LibFuzzer harnesses.
 *
 * The libxml2 harnesses (xml.c, html.c, etc.) expose:
 *   int LLVMFuzzerInitialize(int *argc, char ***argv)   [optional, may be absent]
 *   int LLVMFuzzerTestOneInput(const char *data, size_t size)
 *
 * This shim provides main(), calls Initialize once, then loops reading from a
 * file (AFL @@ mode) or stdin, and invokes the harness function each iteration.
 *
 * Compiled with aflgo-clang so __AFL_INIT() and __AFL_LOOP() are defined
 * by the wrapper's macros and resolved from aflgo-runtime.o.
 *
 * Usage: afl-fuzz -z exp -c 45m -i corpus -o out -- binary @@
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

/* Fallback no-ops when compiled outside afl-clang-fast */
#ifndef __AFL_LOOP
# define __AFL_INIT()   do {} while (0)
# define __AFL_LOOP(x)  (0)
#endif

/*
 * LLVMFuzzerInitialize is optional: declare as weak so the linker resolves
 * it to NULL when the harness does not define it.
 */
int LLVMFuzzerInitialize(int *argc, char ***argv)
    __attribute__((weak));

/*
 * LLVMFuzzerMutate is provided by the LibFuzzer runtime for use by
 * LLVMFuzzerCustomMutator callbacks.  Under AFL, mutation is handled
 * externally so this is a no-op that returns the original size.
 */
size_t LLVMFuzzerMutate(unsigned char *data, size_t size, size_t max_size)
{
    (void)data; (void)max_size;
    return size;
}

extern int LLVMFuzzerTestOneInput(const char *data, size_t size);

int main(int argc, char **argv)
{
    unsigned char *buf;
    size_t cap = 1u << 20;  /* 1 MiB — large enough for any XML document */

    /* Call the harness initializer exactly once (sets up xmlInitParser etc.) */
    if (LLVMFuzzerInitialize)
        LLVMFuzzerInitialize(&argc, &argv);

    buf = malloc(cap);
    if (!buf) return 1;

    __AFL_INIT();

    while (__AFL_LOOP(1000)) {
        FILE *f;
        if (argc > 1) {
            f = fopen(argv[1], "rb");
            if (!f) continue;
        } else {
            f = stdin;
        }
        size_t size = fread(buf, 1, cap, f);
        if (argc > 1) fclose(f);
        if (size > 0)
            LLVMFuzzerTestOneInput((const char *)buf, size);
    }

    free(buf);
    return 0;
}
