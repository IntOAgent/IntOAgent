/*
 * afl_shim.c — AFL-compatible main() wrapper for LibFuzzer harnesses.
 *
 * The libplist harnesses (bplist_fuzzer.cc etc.) expose LLVMFuzzerTestOneInput
 * but no main().  This shim provides main(), reads the input from a file
 * (AFL @@ mode) or stdin, and calls the harness function.
 *
 * Compiled with aflgo-clang so __AFL_INIT() and __AFL_LOOP() are defined
 * by the wrapper's -D macros and resolved from aflgo-runtime.o.
 *
 * Usage: afl-fuzz -z exp -c 45m -i corpus -o out -- binary @@
 */
#include <stdio.h>
#include <stdlib.h>

/* Fallback no-ops when compiled outside afl-clang-fast */
#ifndef __AFL_LOOP
# define __AFL_INIT()   do {} while (0)
# define __AFL_LOOP(x)  (0)
#endif

extern int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size);

int main(int argc, char **argv)
{
    unsigned char *buf;
    size_t cap = 1u << 20;  /* 1 MiB — large enough for any plist */

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
            LLVMFuzzerTestOneInput(buf, size);
    }

    free(buf);
    return 0;
}
