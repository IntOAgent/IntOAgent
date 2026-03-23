# Integrity: Finding Integer Errors by Targeted Fuzzing
# Makefile — builds the toolchain, micro-benchmarks, and real-world targets.
#
# Quick start (micro-benchmarks, LibFuzzer):
#   make all
#
# Real-world target with LibFuzzer:
#   make libplist
#   ./build/fuzz_libplist_bplist -max_total_time=60 corpus/libplist/bplist/
#
# Real-world target with AFLGo (directed fuzzing):
#   AFLGO_DIR=/path/to/aflgo make libplist-aflgo
#   # Then follow the printed instructions to run afl-fuzz -z exp -c 45m ...

CC      := clang-14
CXX     := clang++-14
OPT     := opt-14
LLDIS   := llvm-dis-14

BUILD   := build
PASS    := $(BUILD)/IntegrityPass.so
RT_OBJ  := $(BUILD)/integrity_rt.o
WRAPPER      := scripts/integrity-cc
WRAPPER_AFLGO := scripts/integrity-cc-aflgo

# AFLGo paths (override with AFLGO_DIR=... on command line)
AFLGO_DIR ?= /home/xxx/PHDlife/fuxian/aflgo

LLVM_CXXFLAGS := $(shell llvm-config-14 --cxxflags)

# Fuzzer driver object (compiled once, reused for all CWE micro-benchmarks)
DRV_OBJ := $(BUILD)/fuzz_driver.o

FUZZ_BINS := $(BUILD)/fuzz_cwe190 $(BUILD)/fuzz_cwe191 \
             $(BUILD)/fuzz_cwe369 $(BUILD)/fuzz_cwe194

.PHONY: all clean verify libplist libplist-clean libplist-aflgo libplist-aflgo-clean \
        libxml2 libxml2-clean libxml2-aflgo libxml2-aflgo-clean \
        sqlite sqlite-clean \
        cwe-aflgo cwe-aflgo-clean help

# -----------------------------------------------------------------------
# Default: build toolchain + micro-benchmark fuzz binaries
# -----------------------------------------------------------------------
all: toolchain $(FUZZ_BINS)
	@echo ""
	@echo "Built micro-benchmark fuzz binaries:"
	@for b in $(FUZZ_BINS); do echo "  $$b"; done
	@echo ""
	@echo "For real-world target: make libplist"

# -----------------------------------------------------------------------
# Toolchain: LLVM pass + runtime + wrapper script
# -----------------------------------------------------------------------
toolchain: $(PASS) $(RT_OBJ) $(WRAPPER)
	@echo "[toolchain] ready"

# Build the LLVM pass as a shared library
$(PASS): pass/IntegrityPass.cpp | $(BUILD)
	$(CXX) -shared -fPIC -fno-rtti $(LLVM_CXXFLAGS) \
	    -o $@ $< -lLLVM-14

# Build the runtime object (no fuzzer instrumentation — clean object)
$(RT_OBJ): runtime/integrity_rt.c runtime/integrity_rt.h | $(BUILD)
	$(CC) -g -O1 -c -o $@ $<

# Make the wrapper scripts executable
.PHONY: $(WRAPPER) $(WRAPPER_AFLGO)
$(WRAPPER):
	chmod +x scripts/integrity-cc scripts/integrity-c++ 2>/dev/null || true
$(WRAPPER_AFLGO):
	chmod +x scripts/integrity-cc-aflgo scripts/integrity-c++-aflgo 2>/dev/null || true

# -----------------------------------------------------------------------
# Micro-benchmark fuzz targets (CWE test programs)
# -----------------------------------------------------------------------
$(DRV_OBJ): tests/fuzz_driver.c | $(BUILD)
	$(CC) -g -O1 -fsanitize=fuzzer-no-link -c -o $@ $<

# Source → pre-instrumented BC
$(BUILD)/cwe190.pre.bc: tests/cwe190_overflow.c | $(BUILD)
	$(CC) -g -O1 -emit-llvm -c -o $@ $<

$(BUILD)/cwe191.pre.bc: tests/cwe191_underflow.c | $(BUILD)
	$(CC) -g -O1 -emit-llvm -c -o $@ $<

$(BUILD)/cwe369.pre.bc: tests/cwe369_divzero.c | $(BUILD)
	$(CC) -g -O1 -emit-llvm -c -o $@ $<

$(BUILD)/cwe194.pre.bc: tests/cwe194_signext.c | $(BUILD)
	# -O0: preserve the i8 trunc so inferWidth() returns 8
	$(CC) -g -O0 -emit-llvm -c -o $@ $<

# Apply Integrity pass
$(BUILD)/%.bc: $(BUILD)/%.pre.bc $(PASS)
	$(OPT) -enable-new-pm=0 -load $(PASS) -integrity -o $@ $<

# Compile instrumented BC → object
$(BUILD)/%.o: $(BUILD)/%.bc
	$(CC) -g -O1 -c -x ir -o $@ $<

# Link fuzz binaries
$(BUILD)/fuzz_cwe190: $(DRV_OBJ) $(BUILD)/cwe190.o $(RT_OBJ)
	$(CC) -g -O1 -fsanitize=fuzzer -o $@ $^

$(BUILD)/fuzz_cwe191: $(DRV_OBJ) $(BUILD)/cwe191.o $(RT_OBJ)
	$(CC) -g -O1 -fsanitize=fuzzer -o $@ $^

$(BUILD)/fuzz_cwe369: $(DRV_OBJ) $(BUILD)/cwe369.o $(RT_OBJ)
	$(CC) -g -O1 -fsanitize=fuzzer -o $@ $^

$(BUILD)/fuzz_cwe194: $(DRV_OBJ) $(BUILD)/cwe194.o $(RT_OBJ)
	$(CC) -g -O1 -fsanitize=fuzzer -o $@ $^

# -----------------------------------------------------------------------
# Real-world target: libplist
# Delegates to targets/libplist/build.sh which handles the full pipeline:
#   autogen → configure (CC=integrity-cc) → make → link fuzz binaries
# -----------------------------------------------------------------------
libplist: toolchain
	@bash targets/libplist/build.sh

libplist-clean:
	rm -rf $(BUILD)/libplist
	rm -f $(BUILD)/fuzz_libplist_bplist $(BUILD)/fuzz_libplist_xplist \
	      $(BUILD)/fuzz_libplist_jplist $(BUILD)/fuzz_libplist_oplist

# -----------------------------------------------------------------------
# AFLGo directed fuzzing: libplist
#
# Uses the 5-phase pipeline in targets/libplist/build_aflgo.sh:
#   0. Integrity compile → BBtargets.txt (guard-branch locations)
#   1. AFLGo preprocessing → CFG dot-files, BBnames, BBcalls, Ftargets
#   2. gen_distance_fast.py → distance.cfg.txt
#   3. AFLGo distance compile → Integrity + AFLGo instrumented objects
#   4. Link fuzz binaries
#
# The resulting fuzz binaries use afl-fuzz with distance-based scheduling:
#   seeds closer to guard branches get exponentially more mutation energy.
# -----------------------------------------------------------------------
libplist-aflgo: toolchain $(WRAPPER_AFLGO)
	@AFLGO_DIR=$(AFLGO_DIR) bash targets/libplist/build_aflgo.sh

libplist-aflgo-clean:
	rm -rf $(BUILD)/libplist_aflgo
	rm -f $(BUILD)/fuzz_libplist_*_aflgo
	rm -rf corpus/libplist_aflgo

# -----------------------------------------------------------------------
# Real-world target: libxml2
# Delegates to targets/libxml2/build.sh which handles the full pipeline:
#   autogen → configure (CC=integrity-cc) → make → link fuzz binaries
# Harnesses: xml (XML parser), html (HTML parser), xpath, regexp
# -----------------------------------------------------------------------
libxml2: toolchain
	@bash targets/libxml2/build.sh

libxml2-clean:
	rm -rf $(BUILD)/libxml2
	rm -f $(BUILD)/fuzz_libxml2_xml $(BUILD)/fuzz_libxml2_html \
	      $(BUILD)/fuzz_libxml2_xpath $(BUILD)/fuzz_libxml2_regexp

# -----------------------------------------------------------------------
# AFLGo directed fuzzing: libxml2
#
# Uses the 5-phase pipeline in targets/libxml2/build_aflgo.sh:
#   0. Integrity compile → BBtargets.txt (guard-branch locations)
#   1. AFLGo preprocessing → CFG dot-files, BBnames, BBcalls, Ftargets
#   2. gen_distance_fast.py → distance.cfg.txt
#   3. AFLGo distance compile → Integrity + AFLGo instrumented objects
#   4. Link fuzz binaries
# -----------------------------------------------------------------------
libxml2-aflgo: toolchain $(WRAPPER_AFLGO)
	@AFLGO_DIR=$(AFLGO_DIR) bash targets/libxml2/build_aflgo.sh

libxml2-aflgo-clean:
	rm -rf $(BUILD)/libxml2_aflgo
	rm -f $(BUILD)/fuzz_libxml2_*_aflgo
	rm -rf corpus/libxml2_aflgo

# -----------------------------------------------------------------------
# Real-world target: SQLite 3.52.0 (single-file amalgamation)
# Harnesses: sql (SQL text via ossfuzz.c), db (DB files via dbfuzz2.c)
# Prerequisite: cd /path/to/sqlite && ./configure --disable-tcl && make sqlite3.c
# -----------------------------------------------------------------------
sqlite: toolchain
	@bash targets/sqlite/build.sh

sqlite-clean:
	rm -rf $(BUILD)/sqlite
	rm -f $(BUILD)/fuzz_sqlite_sql $(BUILD)/fuzz_sqlite_db

# -----------------------------------------------------------------------
# AFLGo directed fuzzing: CWE micro-benchmarks
#
# Builds all 4 CWE fuzz targets using aflgo-clang so they can be run
# with afl-fuzz -z exp -c <time>.  Each binary has both Integrity guard
# branches (continue-on-error integer error detection) and AFLGo's
# distance-based instrumentation directing the fuzzer toward those guards.
# -----------------------------------------------------------------------
AFLGO_TMP  := $(BUILD)/aflgo-tmp
AFLGO_BINS := $(BUILD)/fuzz_cwe190_aflgo $(BUILD)/fuzz_cwe191_aflgo \
              $(BUILD)/fuzz_cwe369_aflgo $(BUILD)/fuzz_cwe194_aflgo

cwe-aflgo: toolchain $(WRAPPER_AFLGO) $(AFLGO_BINS)
	@echo ""
	@echo "Built AFLGo CWE fuzz binaries:"
	@for b in $(AFLGO_BINS); do echo "  $$b"; done
	@echo ""
	@echo "Run (example 30-second campaign — adjust -c as needed):"
	@echo "  mkdir -p corpus && python3 -c \"import sys; sys.stdout.buffer.write(b'\\x00'*8)\" > corpus/seed"
	@echo "  $(AFLGO_DIR)/afl-2.57b/afl-fuzz -z exp -c 20m -i corpus -o $(BUILD)/afl_out_cwe190 -- $(BUILD)/fuzz_cwe190_aflgo"

# Helper script invoked for each CWE target (avoids make recipe complexity)
AFLGO_CWE_SCRIPT := scripts/build_cwe_aflgo.sh

# CWE190 — signed integer overflow (a+b)
$(BUILD)/fuzz_cwe190_aflgo: tests/fuzz_driver_afl.c tests/cwe190_overflow.c $(RT_OBJ) $(PASS) | $(BUILD)
	@bash $(AFLGO_CWE_SCRIPT) cwe190 tests/cwe190_overflow.c -O1 \
	    $(AFLGO_DIR) $(BUILD) $(AFLGO_TMP) $(PASS) $(RT_OBJ) $@

# CWE191 — signed integer underflow (a-b)
$(BUILD)/fuzz_cwe191_aflgo: tests/fuzz_driver_afl.c tests/cwe191_underflow.c $(RT_OBJ) $(PASS) | $(BUILD)
	@bash $(AFLGO_CWE_SCRIPT) cwe191 tests/cwe191_underflow.c -O1 \
	    $(AFLGO_DIR) $(BUILD) $(AFLGO_TMP) $(PASS) $(RT_OBJ) $@

# CWE369 — divide by zero (a/b)
$(BUILD)/fuzz_cwe369_aflgo: tests/fuzz_driver_afl.c tests/cwe369_divzero.c $(RT_OBJ) $(PASS) | $(BUILD)
	@bash $(AFLGO_CWE_SCRIPT) cwe369 tests/cwe369_divzero.c -O1 \
	    $(AFLGO_DIR) $(BUILD) $(AFLGO_TMP) $(PASS) $(RT_OBJ) $@

# CWE194 — narrow-type multiplication overflow (i8*i8)
$(BUILD)/fuzz_cwe194_aflgo: tests/fuzz_driver_afl.c tests/cwe194_signext.c $(RT_OBJ) $(PASS) | $(BUILD)
	@bash $(AFLGO_CWE_SCRIPT) cwe194 tests/cwe194_signext.c -O0 \
	    $(AFLGO_DIR) $(BUILD) $(AFLGO_TMP) $(PASS) $(RT_OBJ) $@

cwe-aflgo-clean:
	rm -f $(AFLGO_BINS) $(BUILD)/cwe*.int.bc $(BUILD)/cwe*_p1.o $(BUILD)/cwe*_p3.o
	rm -rf $(AFLGO_TMP)

# -----------------------------------------------------------------------
# Seed corpus (for micro-benchmarks)
# -----------------------------------------------------------------------
corpus/seed:
	mkdir -p corpus
	python3 -c "import sys; sys.stdout.buffer.write(b'\x00' * 8)" > $@

# -----------------------------------------------------------------------
# Verify instrumentation (micro-benchmarks)
# -----------------------------------------------------------------------
verify: $(BUILD)/cwe190.bc
	@echo "=== Verifying __integrity_report in cwe190.bc ==="
	$(LLDIS) $(BUILD)/cwe190.bc -o - | grep "__integrity_report" | head -5
	@echo "=== OK ==="

# -----------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------
help:
	@echo "Targets:"
	@echo "  all               Build toolchain + CWE micro-benchmarks (LibFuzzer)"
	@echo "  toolchain         Build IntegrityPass.so + integrity_rt.o + wrappers"
	@echo "  libplist          Build libplist with Integrity (LibFuzzer)"
	@echo "  libplist-clean    Clean LibFuzzer libplist build"
	@echo "  libxml2           Build libxml2 with Integrity (LibFuzzer)"
	@echo "  libxml2-clean     Clean LibFuzzer libxml2 build"
	@echo "  cwe-aflgo         Build CWE micro-benchmarks with AFLGo"
	@echo "  cwe-aflgo-clean   Clean AFLGo CWE builds"
	@echo "  libplist-aflgo    Build libplist with Integrity+AFLGo (directed fuzzing)"
	@echo "  libplist-aflgo-clean  Clean AFLGo libplist build"
	@echo "  libxml2-aflgo     Build libxml2 with Integrity+AFLGo (directed fuzzing)"
	@echo "  libxml2-aflgo-clean   Clean AFLGo libxml2 build"
	@echo "  verify            Check instrumentation in CWE190 IR"
	@echo "  clean             Remove all build artifacts"
	@echo ""
	@echo "Running LibFuzzer targets:"
	@echo "  ./build/fuzz_cwe190 -max_total_time=30 corpus/"
	@echo "  ./build/fuzz_libplist_bplist -max_total_time=60 corpus/libplist/bplist/"
	@echo "  ./build/fuzz_libxml2_xml -max_total_time=60 corpus/libxml2/xml/"
	@echo ""
	@echo "Running AFLGo targets (directed fuzzing toward integer error sites):"
	@echo "  $(AFLGO_DIR)/afl-2.57b/afl-fuzz -z exp -c 20m -i corpus -o out -- ./build/fuzz_cwe190_aflgo"
	@echo "  $(AFLGO_DIR)/afl-2.57b/afl-fuzz -z exp -c 45m -i corpus/libplist_aflgo/bplist -o out -- ./build/fuzz_libplist_bplist_aflgo @@"
	@echo "  $(AFLGO_DIR)/afl-2.57b/afl-fuzz -z exp -c 45m -i corpus/libxml2_aflgo/xml -o out -- ./build/fuzz_libxml2_xml_aflgo @@"

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)
