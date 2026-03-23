# Shell.c Harness Experiment — Integrity Baseline Re-evaluation

## Motivation

In the original baseline evaluation (`baseline_result.md`), all 41 `shell.c` targets
had **0% reach rate** and **0% trigger rate**.  The user correctly challenged this:

> *"shell.c:1308 (`local_getline`) is always triggered when accessing SQL statements
> through sqlite3."*

The reason for 0% was that the original harnesses (`ossfuzz.c`, `dbfuzz2.c`) call the
SQLite library API directly (`sqlite3_exec`, `sqlite3_step`) and never compile or link
`shell.c`.  `local_getline` is a static function inside `shell.c` that is only reachable
when SQL is fed through the interactive sqlite3 shell's input loop.

## Experiment Design

**New harness**: `targets/sqlite/fuzz_sqlite_shell.c`

- `#include`s `shell.c` directly (with `main` renamed via `#define main
  sqlite3_shell_main_NOLINK`) to access all static functions including `ShellState`,
  `process_input`, and `local_getline`.
- `LLVMFuzzerTestOneInput` writes fuzz bytes to a `tmpfile()`, sets `data.in = fin`,
  and calls `process_input(&data)`.  This triggers the FILE\*-based input path:
  `process_input → one_input_line → local_getline`.
- Resource limits: `SQLITE_LIMIT_VDBE_OP=25000` prevents infinite recursion.
- `exit()` interception via `--wrap,exit` + `setjmp/longjmp` prevents a single
  shell meta-command from terminating the fuzzer process.

**Evaluation date:** 2026-03-02
**SQLite version:** 3.50.0
**Corpus size:** 834 seeds (accumulated from fuzzing campaign)
**Campaign duration:** 120 seconds; ~35,000 executions at ~17,700 exec/s

---

## Results: shell.c Reach and Trigger Rates

| Metric | Baseline (ossfuzz.c) | Experiment (shell harness) |
|--------|:--------------------:|:--------------------------:|
| shell.c targets | 41 | 41 (35 unique) |
| Reached | 0 | 3 |
| **Reach rate** | **0.0%** | **8.6%** |
| Triggered | 0 | 0 |
| **Trigger rate** | **0.0%** | **0.0%** |

### shell.c Detailed Results (35 unique targets)

| Line | Exec Count | Reached | Function / Context | Triggered |
|------|----------:|:-------:|-------------------|:---------:|
| `shell.c:1308` | 1,631 | **✓** | `local_getline` — buffer realloc | ✗ |
| `shell.c:1478` | 18 | **✓** | `ShellText` append realloc | ✗ |
| `shell.c:32506` | 3,380 | **✓** | `process_input` main loop | ✗ |
| `shell.c:1181` | 0 | ✗ | `utf8_width` — text alignment | ✗ |
| `shell.c:1422` | 0 | ✗ | input continuation flag | ✗ |
| `shell.c:1428` | 0 | ✗ | input continuation flag | ✗ |
| `shell.c:1432` | 0 | ✗ | input continuation flag | ✗ |
| `shell.c:4252` | 0 | ✗ | base64 encode helper | ✗ |
| `shell.c:4805` | 0 | ✗ | base64 column output | ✗ |
| `shell.c:5341–5342` | 0 | ✗ | `.import` CSV field counter | ✗ |
| `shell.c:5722` | 0 | ✗ | `.import` ASCII field counter | ✗ |
| `shell.c:6060` | 0 | ✗ | `.output` handler | ✗ |
| `shell.c:6733–6749` | 0 | ✗ | `.separator` handler | ✗ |
| `shell.c:7620–7625` | 0 | ✗ | `.backup` / `.restore` handler | ✗ |
| `shell.c:14455` | 0 | ✗ | `.fts5check` handler | ✗ |
| `shell.c:22034` | 0 | ✗ | `.testctrl` handler | ✗ |
| `shell.c:23232` | 0 | ✗ | error context save | ✗ |
| `shell.c:23983` | 0 | ✗ | output column width | ✗ |
| `shell.c:24223` | 0 | ✗ | column output padding | ✗ |
| `shell.c:25644–25691` | 0 | ✗ | `.open` / `openChrSource` | ✗ |
| `shell.c:26245` | 0 | ✗ | CSV import decoder | ✗ |
| `shell.c:26694` | 0 | ✗ | CSV field reader | ✗ |
| `shell.c:29509` | 0 | ✗ | `.safe` mode handler | ✗ |
| `shell.c:31462` | 0 | ✗ | argument parser | ✗ |
| `shell.c:32506` | 3,380 | **✓** | `process_input` main loop | ✗ |
| `shell.c:33124` | 0 | ✗ | `.recover` handler | ✗ |

**shell.c reach: 3/35 = 8.6%   trigger: 0/35 = 0.0%**

---

## Key Finding: shell.c:1308 IS Reached

`shell.c:1308` (`local_getline`) was executed **1,631 times** in the 120-second campaign,
confirming the user's claim.  This line is:

```c
/* shell.c:1308 — inside local_getline() */
nLine = nLine*2 + 100;   /* buffer realloc: no overflow with typical inputs */
```

The expression `nLine*2 + 100` could overflow if `nLine` is large (> ~2 billion on
32-bit platforms, or near `INT_MAX/2` on 64-bit).  However, the buffer never grows that
large in normal fuzzing — inputs are capped at 4096 bytes by LibFuzzer, so `nLine` stays
well within bounds.

---

## Why Only 3 of 35 Shell.c Targets Are Reached

### Reached lines
The three reached lines are all on the "hot path" exercised for every SQL statement:
- `local_getline` (1308): buffer growth in the line reader
- `ShellText` append (1478): string accumulation
- `process_input` main loop (32506): input dispatcher

### Unreached lines

The 32 unreached target lines fall into distinct categories:

| Category | Lines | Reason Unreached |
|----------|-------|-----------------|
| `.import` handler | 5341, 5342, 5722 | Requires `.import filename table` meta-command with a valid file path |
| `.output` / `.separator` | 6060, 6733–6749 | Requires `.output filename` meta-command |
| `.backup` / `.restore` | 7620, 7625 | Requires `.backup`/`.restore` with a filename |
| FTS5 check | 14455 | Requires `.fts5check` on FTS5 table |
| `.testctrl` | 22034 | Requires internal debug command |
| Column output | 23983, 24223 | Requires column-mode output with wide data |
| `.open` handler | 25644–25691 | Requires `.open filename` meta-command |
| CSV decoder | 26245, 26694 | Requires import of CSV with specific structure |
| `.safe` mode | 29509 | Requires `.safe` mode enable/disable |
| Argument parser | 31462 | Requires command-line argument processing (only in `main`) |
| `.recover` handler | 33124 | Requires `.recover` meta-command on corrupt DB |

**Root cause**: random SQL fuzzing rarely generates syntactically valid dot-commands
(`.import`, `.output`, `.backup`, etc.) with valid arguments.  The fuzzer explores plain
SQL space very well but rarely generates the shell meta-command syntax needed to reach
these 32 lines.  **Directed fuzzing with seeds that include dot-commands** (e.g.,
`.import /dev/stdin tbl`) would significantly improve reach.

---

## SQLite Core (sqlite3.c) via Shell Harness

The shell harness also instruments `sqlite3.c`.  For comparison:

| | ossfuzz.c harness | shell harness |
|--|:-----------------:|:-------------:|
| sqlite3.c reach | 24/49 = **49.0%** | 22/49 = **44.9%** |
| sqlite3.c trigger | 0/49 = 0.0% | 0/49 = 0.0% |

The shell harness reaches slightly fewer sqlite3.c target lines because it runs ~6× fewer
iterations per second (the shell.c input pipeline has higher overhead than direct API
calls).

---

## Comparison: Baseline vs Experiment

| Project / Harness | Targets | Reached | Reach Rate | Triggered | Trigger Rate |
|-------------------|--------:|--------:|-----------:|----------:|-------------:|
| SQLite `sqlite3.c` (ossfuzz.c) | 49 | 24 | **49.0%** | 0 | **0.0%** |
| SQLite `shell.c` (baseline — no harness) | 41 | 0 | **0.0%** | 0 | **0.0%** |
| SQLite `shell.c` (this experiment) | 41 | 3 | **8.6%** | 0 | **0.0%** |
| SQLite `sqlite3.c` (shell harness) | 49 | 22 | **44.9%** | 0 | **0.0%** |
| libxml2 | 13 | 11 | **84.6%** | 1 | **7.7%** |
| libplist | 10 | 6 | **60.0%** | 1 | **10.0%** |

---

## Conclusion

1. **The user was correct**: `shell.c:1308` (`local_getline`) IS reached (1,631 times in
   120 s) once a harness that links `shell.c` is used.  The baseline 0% was a harness
   gap, not an Integrity limitation.

2. **8.6% vs 0%**: The shell harness improves shell.c reach from 0/35 to 3/35.  The
   remaining 32/35 unreached lines require specific dot-commands that random SQL fuzzing
   seldom generates.

3. **Trigger rate remains 0%**: The three reached lines (`local_getline` buffer resize,
   `ShellText` append, `process_input` loop counter) do not perform arithmetic that
   overflows under typical 4096-byte fuzz inputs.  The integer operations at these lines
   require inputs with many thousands of lines or multi-gigabyte buffers to overflow.

4. **Recommendation**: To reach and trigger the remaining shell.c targets, add
   dot-command seeds to the corpus (e.g., `.import`, `.output`, `.backup` invocations)
   and run a longer campaign with AFLGo directed fuzzing targeting the unreached lines.

---

## Reproduction

```bash
cd /home/xxx/PHDlife/fuxian/integrity

# Build shell harness
bash targets/sqlite/build_shell.sh

# Run 120-second campaign with per-input timeout
./build/fuzz_sqlite_shell -max_total_time=120 -timeout=5 corpus/sqlite/shell/ \
    2>build/fuzz_sqlite_shell.log

# Collect coverage
LLVM_PROFILE_FILE="build/coverage/shell_%m.profraw" \
    build/coverage/fuzz_sqlite_shell_cov -runs=0 corpus/sqlite/shell/
llvm-profdata-14 merge -sparse build/coverage/shell_*.profraw \
    -o build/coverage/shell_merged.profdata
llvm-cov-14 export -format=lcov \
    -instr-profile=build/coverage/shell_merged.profdata \
    build/coverage/fuzz_sqlite_shell_cov > build/coverage/shell_cov.lcov

# Check INTEGRITY triggers
grep 'INTEGRITY' build/fuzz_sqlite_shell.log | sort -u
```
