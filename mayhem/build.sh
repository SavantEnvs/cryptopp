#!/usr/bin/env bash
#
# mayhem/build.sh — build Crypto++ and its fuzz harnesses. Runs in the commit image as `mayhem`
# in /mayhem (the base image exports CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/STANDALONE_FUZZ_MAIN).
#
#  1. oracle: cryptest.exe with the project's normal flags, built in mayhem/build-test (a symlink
#     farm over the sources, so its objects never mix with the sanitized in-tree objects).
#  2. libcryptopp.a in-tree, with ASan+UBSan (halting), DWARF 3 and SanCov instrumentation.
#  3. every harness in mayhem/harnesses, linked as a libFuzzer binary and a -standalone
#     reproducer into mayhem/out/.
# Nothing is fetched: it only needs the compiler and the checkout.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT="$SRC/mayhem/out"
mkdir -p "$OUT"

# 1) Oracle build: the project's normal flags, no sanitizers, no DWARF pin.
T="$SRC/mayhem/build-test"
mkdir -p "$T"
for f in "$SRC"/*.cpp "$SRC"/*.h "$SRC"/*.S "$SRC"/*.asm "$SRC"/*.proto "$SRC"/GNUmakefile; do
  [ "$(basename "$f")" = adhoc.cpp ] && continue
  [ -e "$f" ] && ln -sf "../../$(basename "$f")" "$T/"
done
ln -sfn ../../TestPrograms "$T/TestPrograms"
make -C "$T" -j"$MAYHEM_JOBS" cryptest.exe \
  CXXFLAGS="-DNDEBUG -O2 $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS"

# 2) The library under test, instrumented. DEBUG_FLAGS after SANITIZER_FLAGS so -gdwarf-3 wins.
LIBFLAGS="-O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
make -j"$MAYHEM_JOBS" libcryptopp.a CXXFLAGS="$LIBFLAGS"

# 3) Harnesses.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$OUT/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"

build_harness() {
  local name="$1"
  $CXX $LIBFLAGS -I"$SRC" -c "$SRC/mayhem/harnesses/$name.cpp" -o "$OUT/$name.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/$name.o" "$OUT/lsan_off.o" \
       "$SRC/libcryptopp.a" -pthread -o "$OUT/$name"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/standalone_main.o" "$OUT/$name.o" "$OUT/lsan_off.o" \
       "$SRC/libcryptopp.a" -pthread -o "$OUT/$name-standalone"
}
export -f build_harness
export OUT LIBFLAGS

ls mayhem/harnesses/*.cpp | xargs -n1 basename -s .cpp \
  | xargs -P "$MAYHEM_JOBS" -I{} bash -c 'build_harness {}'
