# DAFL Fuzzing Results for libplist

This directory contains data related to fuzz testing `libplist` with DAFL.

## Files

- `coverage.info`: Records the reachability results from the fuzzing runs.
- `plist43.csv`: Records whether each target crash can be triggered.

## CSV Field Notes

- `target`: The target source file and line number under test.
- `N.A.`: Not Available. No valid trigger time is available.
- `0/1`: The crash was triggered 0 times in 1 experiment.
