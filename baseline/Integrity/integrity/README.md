# Integrity: Finding Integer Errors by Targeted Fuzzing

A reproduction of the *Integrity* system from the paper
**"Finding Integer Errors by Targeted Fuzzing"**.
It detects non-crashing integer arithmetic errors
(overflow, underflow, divide-by-zero, shift overflow)
in C/C++ programs by inserting *guard branches* at every arithmetic
operation, then directing a fuzzer toward those branches via
[AFLGo](https://github.com/aflgo/aflgo)'s distance-based scheduling.

---

## Table of Contents

1. [How It Works](#how-it-works)
2. [Prerequisites](#prerequisites)
3. [Build the Toolchain](#build-the-toolchain)
4. [Quick-Start: CWE Micro-benchmarks](#quick-start-cwe-micro-benchmarks)
5. [Built-in Real-World Targets](#built-in-real-world-targets)
6. [Applying Integrity to a New Project](#applying-integrity-to-a-new-project)
   - [Step 0: Write a Fuzz Harness](#step-0-write-a-fuzz-harness)
   - [Step 1: LibFuzzer Mode (fast, no AFLGo)](#step-1-libfuzzer-mode)
   - [Step 2: AFLGo Directed Mode](#step-2-aflgo-directed-mode)
7. [Interpreting Results](#interpreting-results)
8. [Evaluation Results](#evaluation-results)
9. [Environment Variables Reference](#environment-variables-reference)
10. [Troubleshooting](#troubleshooting)

---

## How It Works

```
Source code
    │
    ▼  clang-14 -emit-llvm                   Compile to LLVM IR
    │
    ▼  opt-14 -load IntegrityPass.so          Insert guard branches
    │                                          at every arithmetic op
    │   for each ADD / SUB / MUL / SHL / DIV / REM:
    │     widen operands → compute result → check bounds
    │     if (overflow) { __integrity_report(...); }   ← guard branch
    │     continue execution normally (no abort!)
    │
    ▼  BBtargets.txt                           List of guard-branch BBs
    │
    ▼  AFLGo Phase 1: opt-14 -load aflgo-pass.so -targets=BBtargets.txt
    │  → CFG dot files + BBnames.txt + BBcalls.txt
    │
    ▼  gen_distance_fast.py
    │  → CG+CFG Dijkstra distances → distance.cfg.txt
    │
    ▼  AFLGo Phase 2: opt-14 -load aflgo-pass.so -distance=distance.cfg.txt
    │  → final instrumented binary (AFL bitmap + per-BB distance values)
    │
    ▼  afl-fuzz -z exp -c <time>              Directed fuzzing
       Seeds closer to guard branches
       get exponentially more mutations.
```

The key insight: integer errors don't crash by default, so ordinary
fuzzers ignore them. Integrity makes them *observable* (guard branches
fire `__integrity_report` then continue) and *targeted* (AFLGo's
annealing schedule concentrates fuzzing energy on paths leading to
those exact branches).

---

## Prerequisites

### System packages (Ubuntu 20.04 / 22.04)

```bash
sudo apt-get install -y \
    clang-14 llvm-14 llvm-14-dev llvm-14-tools \
    python3 python3-pip \
    autoconf automake libtool pkg-config \
    libxml2-dev libssl-dev
```

### Python packages

```bash
pip3 install networkx "pydot<3.0"
# IMPORTANT: pydot 4.x breaks networkx's read_dot(); must use pydot<3.0
```

### AFLGo

```bash
git clone https://github.com/aflgo/aflgo /path/to/aflgo
cd /path/to/aflgo

# Build the distance calculator
cd distance/distance_calculator && cmake . && make && cd ../..

# Build the modified afl-fuzz
cd afl-2.57b && make && cd ..

# Build the instrumentation pass (requires LLVM 14 fixes — see Troubleshooting)
cd instrument
clang++-14 -fPIC -shared -fno-rtti \
    $(llvm-config-14 --cxxflags) \
    -o aflgo-pass.so aflgo-pass.so.cc
cd ..
```

> **Note:** The AFLGo pass source (`instrument/aflgo-pass.so.cc`) needs
> several LLVM 14 API compatibility fixes and env-var fallbacks before
> it will work. See [Troubleshooting](#troubleshooting).

---

## Build the Toolchain

```bash
cd /path/to/integrity

# Build IntegrityPass.so, integrity_rt.o, and wrapper scripts
make toolchain

# Verify the pass was built
ls build/IntegrityPass.so build/integrity_rt.o
```

The toolchain consists of three components:

| File | Purpose |
|------|---------|
| `build/IntegrityPass.so` | LLVM legacy pass — inserts guard branches |
| `build/integrity_rt.o` | Runtime — `__integrity_report()` implementation |
| `scripts/integrity-cc` | Drop-in CC wrapper for build systems |
| `scripts/integrity-cc-aflgo` | CC wrapper with AFLGo 3-phase support |

---

## Quick-Start: CWE Micro-benchmarks

### LibFuzzer mode (no AFLGo, runs immediately)

```bash
make all
mkdir -p corpus
python3 -c "import sys; sys.stdout.buffer.write(b'\x00'*8)" > corpus/seed

# Run each benchmark for 30 seconds
./build/fuzz_cwe190 -max_total_time=30 corpus/   # Signed overflow: a+b
./build/fuzz_cwe191 -max_total_time=30 corpus/   # Signed underflow: a-b
./build/fuzz_cwe369 -max_total_time=30 corpus/   # Divide by zero: a/b
./build/fuzz_cwe194 -max_total_time=30 corpus/   # Narrow-type overflow: i8*i8
```

Expected output (within seconds):
```
[INTEGRITY] OVERFLOW at tests/cwe190_overflow.c:6:12
[INTEGRITY] === Error Summary (1 unique, 0 dropped) ===
[INTEGRITY]   OVERFLOW : 1 occurrence(s)
```

### AFLGo directed mode

```bash
AFLGO_DIR=/path/to/aflgo make cwe-aflgo

mkdir -p corpus
python3 -c "import sys; sys.stdout.buffer.write(b'\x00'*8)" > corpus/seed

# Run with annealing: explore for 15m, then exploit guard branches for 5m
/path/to/aflgo/afl-2.57b/afl-fuzz \
    -z exp -c 20m \
    -i corpus -o build/afl_out_cwe190 \
    -- ./build/fuzz_cwe190_aflgo
```

---

## Built-in Real-World Targets

Three real-world open-source libraries are pre-integrated.
Each has a `build.sh` (LibFuzzer) and optionally `build_aflgo.sh` (directed fuzzing).

### libplist — Apple binary plist parser

```bash
make libplist                   # Build with LibFuzzer
./build/fuzz_libplist_bplist -max_total_time=60 corpus/libplist/bplist/
./build/fuzz_libplist_xplist -max_total_time=60 corpus/libplist/xplist/
./build/fuzz_libplist_jplist -max_total_time=60 corpus/libplist/jplist/
./build/fuzz_libplist_oplist -max_total_time=60 corpus/libplist/oplist/

# AFLGo directed mode:
AFLGO_DIR=/path/to/aflgo make libplist-aflgo
/path/to/aflgo/afl-2.57b/afl-fuzz -z exp -c 45m \
    -i corpus/libplist_aflgo/bplist -o build/afl_out_bplist \
    -- ./build/fuzz_libplist_bplist_aflgo @@
```

**Results (120 s):** 109 unique integer error locations in `bplist.c`.

### libxml2 — XML/HTML parsing library

```bash
make libxml2                    # Build with LibFuzzer (4 harnesses)
./build/fuzz_libxml2_xml    -max_total_time=60 corpus/libxml2/xml/
./build/fuzz_libxml2_html   -max_total_time=60 corpus/libxml2/html/
./build/fuzz_libxml2_xpath  -max_total_time=60 corpus/libxml2/xpath/
./build/fuzz_libxml2_regexp -max_total_time=60 corpus/libxml2/regexp/

# AFLGo directed mode:
AFLGO_DIR=/path/to/aflgo make libxml2-aflgo
/path/to/aflgo/afl-2.57b/afl-fuzz -z exp -c 45m \
    -i corpus/libxml2_aflgo/xml -o build/afl_out_xml \
    -- ./build/fuzz_libxml2_xml_aflgo @@
```

**Results (120 s):** 810 unique integer error locations across 25 source files,
including overflow at `xpath.c:191` and shift overflow at `dict.c:993`.
See `libXML1_result.md` for the full breakdown.

### SQLite — SQL database engine

```bash
# Prerequisite: build SQLite amalgamation first
# cd /path/to/sqlite && ./configure --disable-tcl && make sqlite3.c

make sqlite                     # Build with LibFuzzer (2 harnesses)
./build/fuzz_sqlite_sql -max_total_time=60 corpus/sqlite/
./build/fuzz_sqlite_db  -max_total_time=60 corpus/sqlite/

# Shell harness (requires shell.c from the SQLite source tree):
bash targets/sqlite/build_shell.sh
./build/fuzz_sqlite_shell -max_total_time=60 corpus/sqlite/
```

**Results (120 s):** 49% reach rate on `sqlite3.c` targets, 0% trigger rate
(arithmetic at reached lines does not overflow with SQL test inputs).
See `baseline_result.md` and `experiments/shell_experiment_result.md`.

---

## Applying Integrity to a New Project

### Step 0: Write a Fuzz Harness

Create a file `fuzz_myproject.c` (or `.cc` for C++) that exposes
`LLVMFuzzerTestOneInput`:

```c
/* fuzz_myproject.c */
#include <stdint.h>
#include <stddef.h>
#include "myproject.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    /* Call your parsing / processing function here.
     * NEVER crash (no abort, no assert, no SIGSEGV).
     * Integrity will log integer errors for you. */
    myproject_parse(data, size);

    return 0;   /* always 0 */
}
```

For AFL mode, also create `fuzz_myproject_afl.c`:

```c
/* fuzz_myproject_afl.c — AFL shim */
#include <stdio.h>
#include <stdlib.h>
#include "myproject.h"

#ifndef __AFL_LOOP
# define __AFL_INIT()  do {} while (0)
# define __AFL_LOOP(x) (0)
#endif

int main(int argc, char **argv) {
    unsigned char *buf;
    size_t cap = 1u << 20;   /* 1 MiB */
    buf = malloc(cap);
    if (!buf) return 1;

    __AFL_INIT();
    while (__AFL_LOOP(1000)) {
        FILE *f = (argc > 1) ? fopen(argv[1], "rb") : stdin;
        if (!f) continue;
        size_t size = fread(buf, 1, cap, f);
        if (argc > 1) fclose(f);
        if (size > 0) LLVMFuzzerTestOneInput(buf, size);
    }
    free(buf);
    return 0;
}
```

---

### Step 1: LibFuzzer Mode

LibFuzzer mode is the fastest way to get started. It uses coverage-guided
fuzzing without distance computation.

**1a. Instrument your source files:**

```bash
INTEGRITY=/path/to/integrity
PASS=$INTEGRITY/build/IntegrityPass.so
RT=$INTEGRITY/build/integrity_rt.o

# For each source file:
clang-14 -g -O1 -emit-llvm -c -o myfile.pre.bc myfile.c
opt-14 -enable-new-pm=0 -load $PASS -integrity -o myfile.bc myfile.pre.bc
clang-14 -g -O1 -c -x ir -o myfile.o myfile.bc
```

**1b. Using the wrapper (recommended for autoconf projects):**

```bash
# Configure the project to use integrity-cc as the compiler
CC=$INTEGRITY/scripts/integrity-cc \
CXX=$INTEGRITY/scripts/integrity-c++ \
INTEGRITY_DIR=$INTEGRITY \
    ./configure --prefix=/tmp/myproject_install

make -j$(nproc)
```

**1c. Link the fuzz binary:**

```bash
clang-14 -g -O1 -fsanitize=fuzzer \
    fuzz_myproject.c \
    myfile.o \          # your instrumented objects
    $RT \               # integrity runtime (provides __integrity_report)
    -o fuzz_myproject
```

**1d. Run:**

```bash
mkdir -p corpus
cp examples/*.bin corpus/    # seed with real inputs if available

./fuzz_myproject \
    -max_total_time=300 \
    -jobs=4 -workers=4 \
    corpus/ \
    2>integrity.log

# Check findings
grep "INTEGRITY" integrity.log | sort -u
```

---

### Step 2: AFLGo Directed Mode

AFLGo directed mode targets the fuzzer toward the *exact* guard branches
inserted by the Integrity pass — more effective for complex parsers where
arithmetic errors are buried deep in the code.

The build pipeline has 4 phases:

```
Phase 0  →  Integrity IR + BBtargets.txt (guard-branch locations)
Phase 1  →  CFG dot files + BBnames.txt  (AFLGo preprocessing)
Phase 2  →  distance.cfg.txt             (Dijkstra on CG+CFG)
Phase 3  →  final instrumented binary    (Integrity + AFLGo distance)
```

#### Phase 0 — Integrity compile + BBtargets.txt

```bash
INTEGRITY=/path/to/integrity
AFLGO_DIR=/path/to/aflgo
OUTDIR=/tmp/myproject_aflgo
mkdir -p $OUTDIR/dot-files

PASS=$INTEGRITY/build/IntegrityPass.so
RT=$INTEGRITY/build/integrity_rt.o

# Compile source → pre-instrumented IR
clang-14 -g -O1 -emit-llvm -c -o $OUTDIR/myfile.pre.bc myfile.c

# Apply Integrity pass (writes BBtargets.txt to OUTDIR)
INTEGRITY_OUTDIR=$OUTDIR \
    opt-14 -enable-new-pm=0 -load $PASS -integrity \
    -o $OUTDIR/myfile.int.bc $OUTDIR/myfile.pre.bc

# Check that guard branches were generated
wc -l $OUTDIR/BBtargets.txt    # should be > 0
```

> **For autoconf projects:** use `integrity-cc-aflgo` with `AFLGO_PHASE=0`:
> ```bash
> AFLGO_PHASE=0 \
> INTEGRITY_OUTDIR=$OUTDIR \
> CC=$INTEGRITY/scripts/integrity-cc-aflgo \
> CXX=$INTEGRITY/scripts/integrity-c++-aflgo \
>     ./configure && make -j$(nproc)
> ```

#### Phase 1 — AFLGo preprocessing (CFG dot files)

```bash
AFLGO_PASS=$AFLGO_DIR/instrument/aflgo-pass.so

# Run AFLGo pass in preprocessing mode (use opt-14, NOT aflgo-clang)
opt-14 -enable-new-pm=0 -O0 \
    -load $AFLGO_PASS \
    -targets=$OUTDIR/BBtargets.txt \
    -outdir=$OUTDIR \
    -o /dev/null $OUTDIR/myfile.int.bc 2>/dev/null || true

# IMPORTANT: strip trailing colons added by the AFLGo pass to BB names
sed -i 's/:$//' $OUTDIR/BBnames.txt

ls $OUTDIR/dot-files/cfg.*.dot | wc -l    # should be > 0
```

> **Why `opt-14` directly?** When loaded via `aflgo-clang -Xclang -load`,
> the pass's `RegisterStandardPasses` extension points are not fired.
> `opt-14 -load` parses `cl::opt` arguments before running the pass —
> this is the correct way to use the AFLGo pass with LLVM 14.

#### Phase 2 — Distance computation

```bash
# Create merged bitcode for callgraph extraction
# (gen_distance_fast.py looks for *.0.0.*.bc in the binaries directory)
llvm-link-14 $OUTDIR/myfile.int.bc -o $OUTDIR/myfile.0.0.0.bc

# Compute distances (CG + per-CFG Dijkstra)
python3 $AFLGO_DIR/distance/gen_distance_fast.py $OUTDIR $OUTDIR

# Verify
wc -l $OUTDIR/distance.cfg.txt    # should be > 0
```

#### Phase 3 — Distance instrumentation + link

```bash
DIST_FILE=$OUTDIR/distance.cfg.txt

# Apply distance pass (use opt-14, NOT aflgo-clang)
opt-14 -enable-new-pm=0 -O0 \
    -load $AFLGO_PASS \
    -distance=$DIST_FILE \
    -o $OUTDIR/myfile.dist.bc $OUTDIR/myfile.int.bc

# Compile to object
clang-14 -g -O1 -c -x ir -o $OUTDIR/myfile.dist.o $OUTDIR/myfile.dist.bc

# Compile AFL shim (fuzz_myproject_afl.c from Step 0)
AFLGO=$AFLGO_DIR AFL_CC=clang-14 AFL_QUIET=1 \
    $AFLGO_DIR/instrument/aflgo-clang \
    -g -O1 -c fuzz_myproject_afl.c -o $OUTDIR/shim.o

# Link final binary (aflgo-clang adds aflgo-runtime.o automatically)
AFLGO=$AFLGO_DIR AFL_CC=clang-14 AFL_QUIET=1 \
    $AFLGO_DIR/instrument/aflgo-clang \
    -g -O1 \
    $OUTDIR/shim.o \
    $OUTDIR/myfile.dist.o \
    $RT \
    -o fuzz_myproject_aflgo
```

#### Run with AFLGo

```bash
mkdir -p corpus
echo -n "" > corpus/seed    # or copy real input files

# -z exp  : exponential annealing schedule
# -c 45m  : switch from exploration to exploitation after 45 minutes
# @@      : AFL replaces @@ with the path to each test input file
$AFLGO_DIR/afl-2.57b/afl-fuzz \
    -z exp -c 45m \
    -i corpus \
    -o afl_out \
    -- ./fuzz_myproject_aflgo @@

# Integer error reports appear in afl-fuzz stderr:
#   [INTEGRITY] OVERFLOW at myfile.c:123:45
```

---

## Interpreting Results

### Report format

```
[INTEGRITY] OVERFLOW at src/parser.c:608:42
[INTEGRITY] UNDERFLOW at src/parser.c:312:18
[INTEGRITY] === Error Summary (2 unique, 0 dropped) ===
[INTEGRITY]   OVERFLOW : 1 occurrence(s)
[INTEGRITY]   UNDERFLOW: 1 occurrence(s)
```

### Error codes

| Code | Meaning | When it fires |
|------|---------|---------------|
| `OVERFLOW` | Result exceeds type maximum | `a + b > INT_MAX` (signed) or `a + b > UINT_MAX` (unsigned) |
| `UNDERFLOW` | Result falls below type minimum | `a - b < INT_MIN` (signed) |
| `DIV_BY_ZERO` | Division with zero divisor | `a / 0` or `a % 0` |
| `MININT_DIV_NEG1` | INT_MIN / -1 (undefined behavior) | `INT_MIN / -1` |
| `SHIFT_OVF` | Left shift overflows | `1 << 32` on a 32-bit integer |

### Reproducing a finding

```bash
# The input that triggered the error is in the AFL output directory
ls afl_out/queue/      # all inputs that reached new coverage
ls afl_out/crashes/    # inputs that caused a crash (rare for integer errors)

# Replay a specific input
./fuzz_myproject_aflgo afl_out/queue/id:000042,... 2>&1 | grep INTEGRITY

# Cross-check with sanitizers
clang-14 -g -O1 -fsanitize=address,undefined \
    myfile.c fuzz_myproject_afl.c \
    -o check_myproject
./check_myproject < afl_out/queue/id:000042,...
```

### LibFuzzer vs AFLGo — which to use?

| | LibFuzzer | AFLGo Directed |
|---|---|---|
| **Speed** | Very fast (in-process) | Slower (fork-based) |
| **Targeting** | Random coverage-guided | Directed toward guard branches |
| **Best for** | Initial exploration | Deep paths in complex parsers |
| **Harness** | `LLVMFuzzerTestOneInput` | AFL shim wrapping `LLVMFuzzerTestOneInput` |
| **Command** | `./fuzz_target -max_total_time=60 corpus/` | `afl-fuzz -z exp -c 45m -i corpus -o out -- ./fuzz_target @@` |

---

## Evaluation Results

Reproduction results for the three built-in targets (120-second LibFuzzer campaigns):

| Project | Targets | Reached | Reach Rate | Triggered | Trigger Rate | Detail |
|---------|--------:|--------:|-----------:|----------:|-------------:|--------|
| SQLite (`sqlite3.c`) | 49 | 24 | 49.0% | 0 | 0.0% | `baseline_result.md` |
| SQLite (`shell.c`) | 41 | 3 | 8.6% | 0 | 0.0% | `experiments/shell_experiment_result.md` |
| libxml2 | 13 | 11 | 84.6% | 1 | 7.7% | `libXML1_result.md` |
| libplist | 10 | 6 | 60.0% | 1 | 10.0% | `libplist_desult.md` |
| **All** | **113** | **44** | **38.9%** | **2** | **1.8%** | `baseline_result.md` |

The `experiments/paper_evidence/` directory contains per-target coverage logs,
corpus snapshots, and the raw data used to produce the above numbers.

---

## Environment Variables Reference

### `integrity-cc` / `integrity-c++`

| Variable | Default | Description |
|----------|---------|-------------|
| `INTEGRITY_DIR` | auto-detected | Path to this repository |
| `INTEGRITY_CLANG` | `clang-14` / `clang++-14` | Underlying compiler |
| `INTEGRITY_OPT` | `opt-14` | LLVM optimizer binary |
| `INTEGRITY_OUTDIR` | (none) | If set, writes `BBtargets.txt` here |
| `INTEGRITY_VERBOSE` | `0` | Set to `1` for verbose compilation log |

### `integrity-cc-aflgo` / `integrity-c++-aflgo`

Inherits all `integrity-cc` variables, plus:

| Variable | Default | Description |
|----------|---------|-------------|
| `AFLGO_PHASE` | `0` | `0`=plain, `1`=CFG preprocessing, `2`=distance instrumentation |
| `AFLGO_DIR` | (required) | Path to the AFLGo repository |
| `INTEGRITY_OUTDIR` | (required for phases 1+2) | AFLGo working directory |
| `AFLGO_DIST` | (required for phase 2) | Path to `distance.cfg.txt` |

---

## Troubleshooting

### `opt-14` uses wrong LLVM version

Check which LLVM `opt-14` uses:
```bash
opt-14 --version | grep LLVM
# Should say: LLVM version 14.x.x
```

If `opt` (without `-14`) points to a different version, always use
`opt-14` explicitly, and pass `-enable-new-pm=0` to use the legacy
pass manager required by the AFLGo pass.

### `distance.cfg.txt` is empty (0 distances)

This is almost always caused by a mismatch in `BBnames.txt`. Check:
```bash
head -5 $OUTDIR/BBnames.txt
# Bad:  myfile.c:42:
# Good: myfile.c:42
```

If entries end with `:`, run:
```bash
sed -i 's/:$//' $OUTDIR/BBnames.txt
```

Then re-run `gen_distance_fast.py`. The trailing colon is inserted by
the AFLGo pass's `BB.setName(bb_name + ":")` call but the distance
calculator expects bare `file:line` keys.

### `pydot` / `networkx` error: `get_strict() takes 1 argument`

```bash
pip3 install "pydot<3.0"
```

pydot 4.x removed the argument from `get_strict()`. networkx 3.4.x
still passes `None` as a positional argument. Downgrading to pydot 2.x
fixes this.

### AFLGo pass generates 0 CFG dot files

Do **not** use `aflgo-clang -Xclang -load`. Use `opt-14 -load` directly:

```bash
# WRONG (clang plugin infrastructure doesn't fire RegisterStandardPasses):
aflgo-clang -g -O1 -targets=... -c myfile.bc -o myfile.o

# CORRECT:
opt-14 -enable-new-pm=0 -O0 \
    -load $AFLGO_PASS \
    -targets=$OUTDIR/BBtargets.txt \
    -outdir=$OUTDIR \
    -o /dev/null myfile.int.bc
```

### `aflgo-pass.so` LLVM 14 API errors

The AFLGo pass was written for LLVM 9-10. For LLVM 14, fix:

1. `IRBuilder::CreateLoad(Ptr)` → `CreateLoad(Type, Ptr)`
2. `IRBuilder::CreateGEP(Ptr, Idx)` → `CreateGEP(Type, Ptr, Idx)`
3. `sys::fs::OpenFlags::F_None` → `sys::fs::OF_None`

Also add env-var fallbacks at the start of `AFLCoverage::runOnModule()`:
```cpp
if (TargetsFile.empty() && getenv("AFLGO_TARGETS"))
    TargetsFile = getenv("AFLGO_TARGETS");
if (OutDirectory.empty() && getenv("AFLGO_OUTDIR"))
    OutDirectory = getenv("AFLGO_OUTDIR");
if (DistanceFile.empty() && getenv("AFLGO_DIST"))
    DistanceFile = getenv("AFLGO_DIST");
```

Rebuild:
```bash
cd $AFLGO_DIR/instrument
clang++-14 -fPIC -shared -fno-rtti \
    $(llvm-config-14 --cxxflags) \
    -o aflgo-pass.so aflgo-pass.so.cc
```

### `undefined reference to 'main'` when linking AFL binary

LibFuzzer harnesses expose `LLVMFuzzerTestOneInput`, not `main()`.
AFL requires a `main()`. Use the AFL shim from
[Step 0](#step-0-write-a-fuzz-harness) and compile it separately
before linking.

### libplist-style multi-file autoconf projects

For projects that use `libtool` (`.lo` / `.la` files):

- Clean **all** intermediate objects between phases: `.o`, `.a`, `.la`, `.lo`
- Force rebuild with `make -B` or by removing the object files

```bash
find $BUILDDIR \( -name "*.o" -o -name "*.a" -o -name "*.la" -o -name "*.lo" \) \
    -exec rm -f {} +
```

This is necessary because libtool may skip recompilation if `.lo` files
exist even after the underlying `.o` objects are removed.

---

## Project Layout

```
integrity/
├── pass/
│   └── IntegrityPass.cpp             LLVM legacy FunctionPass (guard branch insertion)
├── runtime/
│   ├── integrity_rt.h                Public header
│   └── integrity_rt.c                __integrity_report() implementation
├── tests/
│   ├── cwe190_overflow.c             Signed integer overflow test (a+b)
│   ├── cwe191_underflow.c            Signed integer underflow test (a-b)
│   ├── cwe369_divzero.c              Divide-by-zero test (a/b)
│   ├── cwe194_signext.c              Narrow-type overflow test (i8*i8)
│   ├── fuzz_driver.c                 LibFuzzer harness
│   └── fuzz_driver_afl.c             AFL shim harness
├── scripts/
│   ├── integrity-cc                  Drop-in CC wrapper (LibFuzzer mode)
│   ├── integrity-c++                 Drop-in CXX wrapper
│   ├── integrity-cc-aflgo            Drop-in CC wrapper (AFLGo 3-phase mode)
│   ├── integrity-c++-aflgo           Drop-in CXX wrapper (AFLGo mode)
│   └── build_cwe_aflgo.sh            Helper: 4-phase AFLGo build for CWE tests
├── targets/
│   ├── libplist/
│   │   ├── build.sh                  LibFuzzer build script
│   │   ├── build_aflgo.sh            AFLGo 4-phase build script
│   │   └── afl_shim.c               AFL main() + LLVMFuzzerMutate stub
│   ├── libxml2/
│   │   ├── build.sh                  LibFuzzer build script (4 harnesses)
│   │   ├── build_aflgo.sh            AFLGo build script
│   │   └── afl_shim.c               AFL shim with LLVMFuzzerMutate stub
│   └── sqlite/
│       ├── build.sh                  LibFuzzer build script (sql + db harnesses)
│       ├── build_shell.sh            Shell harness builder (includes shell.c)
│       └── fuzz_sqlite_shell.c       Shell harness (wraps process_input)
├── corpus/
│   └── seed                          8-byte zero seed for micro-benchmarks
├── experiments/
│   ├── shell_experiment_result.md    SQLite shell.c reach experiment results
│   └── paper_evidence/               Per-target logs, coverage data, corpus snapshots
├── baseline_result.md                Reach/trigger rates for all 113 targets
├── libXML1_result.md                 libxml2 AFLGo detailed findings
├── libplist_desult.md                libplist detailed findings
├── sqlite_desult.md                  SQLite detailed findings
└── Makefile                          Top-level build orchestration
```
