#!/bin/sh
# Usage: verification/dieharder_run.sh <binary-file> <log-file>
# Runs a selected set of Dieharder tests ("Good" reliability ones) on a binary file.
# Dieharder rewinds the file when it runs out of data and reports the number of rewinds.
# Each test is limited to DH_TIMEOUT seconds (default 600). A test that hits the limit is logged
# as TIMEOUT and is NOT counted as a pass.
FILE="$1"; LOG="$2"; TO="${DH_TIMEOUT:-600}"; : > "$LOG"
for t in 0 1 2 3 4 8 9 10 11 12 13 15 16 17 100 101 102 200 201 202 203 204 205; do
  echo "### test $t" >> "$LOG"
  timeout "$TO" dieharder -g 201 -f "$FILE" -d $t >> "$LOG" 2>&1
  rc=$?
  if [ "$rc" -eq 124 ]; then echo "### TIMEOUT test $t after ${TO}s" >> "$LOG"; fi
done
echo "### finished" >> "$LOG"
