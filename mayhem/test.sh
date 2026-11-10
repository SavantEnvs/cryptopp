#!/usr/bin/env bash
#
# mayhem/test.sh — run Crypto++'s own known-answer test vectors (cryptest.exe, built by build.sh).
# cryptest.exe reports "Tests complete. Total tests = N. Failed tests = M." after checking every
# vector in TestVectors/ against the library; that is the oracle (counts are asserted, so a
# program that exits early or prints nothing fails).
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

EXE="$SRC/mayhem/build-test/cryptest.exe"
[ -x "$EXE" ] || { echo "missing $EXE: mayhem/build.sh did not build it" >&2; emit_ctrf cryptest 0 1; exit 1; }

# cryptest writes cryptest.dat into its cwd and finds TestVectors/ relative to it; run from a scratch
# dir that symlinks the vector directories.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"
ln -s "$SRC/TestVectors" TestVectors
ln -s "$SRC/TestData" TestData
log="$work/tv.log"
"$EXE" tv all > "$log" 2>&1
tail -c 600 "$log"

total="$(sed -n 's/^Tests complete\. Total tests = \([0-9][0-9]*\)\. Failed tests = \([0-9][0-9]*\)\.$/\1/p' "$log" | tail -n1)"
failed="$(sed -n 's/^Tests complete\. Total tests = \([0-9][0-9]*\)\. Failed tests = \([0-9][0-9]*\)\.$/\2/p' "$log" | tail -n1)"
if [ -z "$total" ] || [ -z "$failed" ] || [ "$total" -lt 1000 ]; then
  echo "cryptest.exe did not report a plausible 'Tests complete' summary" >&2
  emit_ctrf cryptest 0 1
  exit 1
fi
emit_ctrf cryptest $(( total - failed )) "$failed"
