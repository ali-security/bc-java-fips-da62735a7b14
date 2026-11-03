#!/bin/bash
# Build and test org.bouncycastle:bc-fips 2.1.0 from this repackaging of the bc-fips sources jar.
# Runs inside ubuntu:jammy-20240911.1 with the toolchain installed by .github/workflows/seal-build.yml:
#   * gcc 11.4 / binutils 2.38 / nasm / cmake pinned from the Ubuntu snapshot archive of 2024-11-15
#     (the toolchain the published native libraries were built with),
#   * Azul Zulu 17.0.7 for Maven (public manifest: "Created-By: 17.0.7 (Azul Systems, Inc.)"),
#   * Zulu 8u432 / 9.0.7 / 11.0.25 / 15.0.10 as Maven toolchains (README "How to build").
#
# Usage: build-and-test.sh <source dir> <output dir> [test filter]
#   test filter: empty = full suite; otherwise space/comma separated names. Names that are
#   BcFipsSmokeTest checks (or "BcFipsSmokeTest" itself) select harness checks; the remaining
#   names are passed to Surefire as -Dtest.
set -euxo pipefail

SRC_DIR="$(cd "$1" && pwd)"
OUT_DIR="$2"
FILTER="$(echo "${3:-}" | tr ',' ' ' | xargs || true)"

# java.io.tmpdir on the build filesystem: the HMAC plugin's File.renameTo fails across filesystems.
MVN_ARGS="-B -e --no-transfer-progress -t /opt/m2/toolchains.xml -Dmaven.repo.local=/opt/m2/repository -Djava.io.tmpdir=/build/work/tmp"
BC_NATIVE_BUILD_TS="2024-11-15T15:56:42"
NATIVE_VARIANTS="probe:bc-probe avx:bc-fips-avx vaes:bc-fips-vaes vaesf:bc-fips-vaesf"
# Smoke-harness checks NOT executed (space/comma separated; passed as -Dbcfips.skip.tests, reported as
# SKIP with the reason from -Dbcfips.skip.reason.<name>). Currently empty.
BCFIPS_SKIP_TESTS=""
# NativeGCMOddChunkDecrypt is the CVE-2026-8149 regression check (native gcm128w.c process_buffer_dec
# odd-chunk decrypt). It belongs to that CVE patch, so it is registered in the suite
# (-Dbcfips.cve8149.regression=true) only when gcm128w.c carries the CVE-2026-8149 fix.
CVE8149_REGRESSION=false
if grep -qF 'memcpy(ctx->bufBlock, ctx->bufBlock + FOUR_BLOCKS, toCopy)' "$SRC_DIR/bc-fips/src/main/native/intel/gcm/gcm128w.c"; then
    CVE8149_REGRESSION=true
fi

# Split the filter into harness checks and Surefire selectors.
HARNESS_SRC="$SRC_DIR/.github/seal/BcFipsSmokeTest.java"
HARNESS_NAMES="$(grep -oE '(nativeCheck|check)\("[A-Za-z0-9_]+"' "$HARNESS_SRC" | sed -E 's/.*\("//; s/"$//' | sort -u | tr '\n' ' ')"
HARNESS_FILTER=""
JUNIT_FILTER=""
RUN_HARNESS=true
if [ -n "$FILTER" ]; then
    RUN_HARNESS=false
    for t in $FILTER; do
        if [ "$t" = "BcFipsSmokeTest" ] || [[ " $HARNESS_NAMES " == *" $t "* ]]; then
            HARNESS_FILTER="$HARNESS_FILTER $t"
            RUN_HARNESS=true
        else
            JUNIT_FILTER="${JUNIT_FILTER:+$JUNIT_FILTER,}$t"
        fi
    done
    HARNESS_FILTER="$(echo "$HARNESS_FILTER" | xargs)"
fi
SUREFIRE_ARGS=""
if [ -n "$FILTER" ]; then
    # Filtered run: only the selected JUnit tests (none when the filter names harness checks only).
    SUREFIRE_ARGS="-Dtest=${JUNIT_FILTER:-NoJUnitTestSelected} -Dsurefire.failIfNoSpecifiedTests=false"
fi

# The checkout stays untouched; build in a writable copy.
rm -rf /build/work /build/native-out
mkdir -p /build
cp -r "$SRC_DIR" /build/work
rm -rf /build/work/.git
mkdir -p /build/work/tmp
cd /build/work
MOD=/build/work/bc-fips
RES_NATIVE="$MOD/src/main/resources/native/linux/x86_64"
NATIVE_OUT=/build/native-out

# ---------------------------------------------------------------------------------------------
# 1) Compile the JNI native libraries from bc-fips/src/main/native (no Makefile/CMake ships in
#    the tree; the CMakeLists below is generated outside the source tree and mirrors the
#    bc-lts-java native CMakeLists layout: CMake 3.22 + gcc 11.4 + nasm, -std=c99 -O3, per-variant
#    ISA flags, BC_VARIANT / BUILD_TS definitions, absolute source paths). The absolute directory
#    the published libraries were compiled in is embedded via __FILE__ and the NASM FILE symbol.
# ---------------------------------------------------------------------------------------------
NROOT=/home/meganwoods/cw/bc-fips/bc-fips-2.1.0-java
# JNI header generation only; the headers do not affect the .so bytes.
JDK=/opt/jdks/jdk17
rm -rf "$NROOT"
mkdir -p "$NROOT"
cp -r "$MOD/src/main/native" "$NROOT/native_c"
HDR="$NROOT/jni-headers"
CLS="$NROOT/jni-classes"
mkdir -p "$HDR" "$CLS"
F="$MOD/src/main/java/org/bouncycastle/crypto/fips"
# JNI headers (org_bouncycastle_crypto_fips_*.h) for the classes with native methods.
"$JDK/bin/javac" -nowarn --release 8 -encoding UTF-8 -implicit:none -h "$HDR" -d "$CLS" -sourcepath "$MOD/src/main/java" \
  "$F/AESNativeCBC.java" "$F/AESNativeCFB.java" "$F/AESNativeCTR.java" "$F/AESNativeEngine.java" "$F/AESNativeGCM.java" \
  "$F/NativeEntropySource.java" "$F/NativeFeatures.java" "$F/NativeLibIdentity.java" "$F/SHA256NativeDigest.java" "$F/VariantSelector.java"
ls "$HDR"
cat > "$NROOT/native_c/CMakeLists.txt" <<CMAKE
cmake_minimum_required(VERSION 3.16)
project(bc-fips-c LANGUAGES C)
enable_language(ASM_NASM)
set(BUILD_TS "$BC_NATIVE_BUILD_TS")
set(CMAKE_C_FLAGS "-std=c99")
set(OPTIONS -Wconversion -Werror=return-type -static-libgcc -z noexecstack)
set(OPTIMISE_FLAG -O3)
set(PROBE_OPTIONS \${OPTIMISE_FLAG} -msse4.1 \${OPTIONS})
set(AVX_OPTIONS \${OPTIMISE_FLAG} -mavx -msha -maes -mpclmul -mrdrnd -mrdseed -mlzcnt \${OPTIONS})
set(VAES_OPTIONS \${OPTIMISE_FLAG} -mavx -msha -maes -mpclmul -mrdrnd -mrdseed -mlzcnt -mvaes -mavx2 \${OPTIONS})
set(VAESF_OPTIONS \${OPTIMISE_FLAG} -mavx -msha -maes -mpclmul -mrdrnd -mrdseed -mlzcnt -mvaes -mavx2 -mavx512f -mavx512bw -mvpclmulqdq \${OPTIONS})
include_directories($JDK/include $JDK/include/linux $HDR)
set(JNI_UTIL jniutil/bytearrays.c jniutil/bytearraycritical.c jniutil/exceptions.c)
set(COMMON intel/common.c intel/util/util.c intel/common_sysV.asm)
set(IDENT_IMPL intel/jni/ident_jni.c intel/jni/native_features.c)
set(RAND intel/jni/rand_jni.c)
set(SHA256 intel/sha/sha256.c intel/jni/sha256_jni.c)
# probe: as upstream, PROBE_OPTIONS only reach CXX sources, so the C probe builds with -std=c99 alone
add_library(bc-probe SHARED intel/jni/variant_selector_intel.c)
target_compile_options(bc-probe PRIVATE \$<\$<COMPILE_LANGUAGE:CXX>:\${PROBE_OPTIONS}>)
target_compile_definitions(bc-probe PUBLIC BUILD_TS=\"\${BUILD_TS}\")
foreach(V avx vaes vaesf)
  if(V STREQUAL "avx")
    set(W 128w)
    set(B 128)
    set(G 128w)
    set(OPTS \${AVX_OPTIONS})
    set(DEF BC_AVX)
  elseif(V STREQUAL "vaes")
    set(W 256w)
    set(B 256)
    set(G 128w)
    set(OPTS \${VAES_OPTIONS})
    set(DEF BC_VAES)
  else()
    set(W 512w)
    set(B 512)
    set(G 512w)
    set(OPTS \${VAESF_OPTIONS})
    set(DEF BC_VAESF)
  endif()
  add_library(bc-fips-\${V} SHARED \${COMMON} \${JNI_UTIL} \${IDENT_IMPL}
    intel/jni/ecb_jni.c intel/ecb/ecb\${W}.c intel/ecb/ecb.c
    intel/cbc/cbc.c intel/cbc/cbc\${B}.c intel/jni/cbc_jni.c
    intel/cfb/cfb.c intel/cfb/cfb\${B}.c intel/jni/cfb_jni.c
    intel/ctr/ctr.c intel/ctr/ctr\${W}.c intel/jni/ctr_jni.c
    \${RAND} \${SHA256}
    intel/gcm/gcm.c intel/gcm/gcm\${G}.c intel/jni/gcm_jni.c)
  target_compile_options(bc-fips-\${V} PRIVATE \$<\$<COMPILE_LANGUAGE:C>:\${OPTS}>)
  target_compile_definitions(bc-fips-\${V} PUBLIC \${DEF} BC_VARIANT=\"\${V}\" BUILD_TS=\"\${BUILD_TS}\")
endforeach()
CMAKE
cmake -S "$NROOT/native_c" -B "$NROOT/cmake-build"
make -C "$NROOT/cmake-build" VERBOSE=1

# The NASM object has no .note.GNU-stack, so ld marks PT_GNU_STACK RWX. The published libraries
# were linked exactly like that (their build-id hashes the RWX header) and then had the stack made
# non-executable post-link (execstack -c equivalent): clear PF_X on PT_GNU_STACK the same way.
clear_execstack() {
  local so="$1" phoff idx
  phoff=$(readelf -h "$so" | awk '/Start of program headers/ {print $5}')
  idx=$(readelf -l -W "$so" | awk '/^Program Headers:/ {f=1; next} f && /^ +[A-Z_]+ +0x/ {if ($1=="GNU_STACK") {print n; exit}; n++}')
  test -n "$idx"
  printf '\x06' | dd of="$so" bs=1 seek=$((phoff + idx*56 + 4)) conv=notrunc status=none
  readelf -l -W "$so" | grep GNU_STACK
}
for v in avx vaes vaesf; do
  clear_execstack "$NROOT/cmake-build/libbc-fips-$v.so"
done

# Replace the prebuilt libraries in the build copy (before `mvn package`: the module HMAC covers them).
set +x
echo "===== native libraries: rebuilt vs prebuilt (checkout) ====="
for d in $NATIVE_VARIANTS; do
  dir="${d%%:*}"; lib="lib${d#*:}.so"
  built="$NROOT/cmake-build/$lib"
  prebuilt="$SRC_DIR/bc-fips/src/main/resources/native/linux/x86_64/$dir/$lib"
  test -s "$built"
  mkdir -p "$NATIVE_OUT/$dir" "$RES_NATIVE/$dir"
  cp "$built" "$NATIVE_OUT/$dir/$lib"
  cp "$built" "$RES_NATIVE/$dir/$lib"
  echo "rebuilt  sha256 $(sha256sum "$built" | cut -d' ' -f1)  $dir/$lib"
  if [ -f "$prebuilt" ]; then
    echo "prebuilt sha256 $(sha256sum "$prebuilt" | cut -d' ' -f1)  $dir/$lib"
    if cmp -s "$built" "$prebuilt"; then
      echo "  -> $dir/$lib: rebuilt library is byte-identical to the prebuilt one"
    else
      echo "  -> $dir/$lib: rebuilt library DIFFERS from the prebuilt one (expected when native sources are patched)"
    fi
  else
    echo "prebuilt: none in checkout for $dir/$lib"
  fi
done
set -x

# ---------------------------------------------------------------------------------------------
# 2) Java build: in-repo hmac-maven-plugin, then bc-fips (unsigned; `sign` profile inactive), the
#    README's `mvn package`. The test phase runs the JUnit tests under bc-fips/src/test/java via
#    Surefire; the package phase runs maven-bundle-plugin then hmac-maven-plugin:generate-hmac.
# ---------------------------------------------------------------------------------------------
mvn $MVN_ARGS -pl plugins/hmac-maven-plugin -am install
mvn $MVN_ARGS $SUREFIRE_ARGS -pl bc-fips package

# Per-test JUnit results (Surefire XML), so each test case and any skip reason is in the log.
set +x
echo "===== JUnit (Surefire) per-test results ====="
for x in "$MOD"/target/surefire-reports/TEST-*.xml; do
  [ -f "$x" ] || continue
  echo "$(basename "$x"):"
  grep -oE '<testcase name="[^"]+" classname="[^"]+"|<skipped[^>]*>|<failure [^>]*>|<error [^>]*>' "$x" \
    | sed -E 's/<testcase name="([^"]+)" classname="([^"]+)"/  testcase \2.\1/' || true
done
set -x

mkdir -p "$OUT_DIR"
cp "$MOD"/target/bc-fips-2.1.0.jar "$OUT_DIR/"
ls -l "$OUT_DIR"
BUILT_JAR="$MOD/target/bc-fips-2.1.0.jar"

# The jar must carry the freshly compiled libraries.
for d in $NATIVE_VARIANTS; do
  dir="${d%%:*}"; lib="lib${d#*:}.so"
  jar_sha="$(unzip -p "$BUILT_JAR" "native/linux/x86_64/$dir/$lib" | sha256sum | cut -d' ' -f1)"
  built_sha="$(sha256sum "$NATIVE_OUT/$dir/$lib" | cut -d' ' -f1)"
  echo "jar native/linux/x86_64/$dir/$lib sha256 $jar_sha"
  test "$jar_sha" = "$built_sha"
done

# ---------------------------------------------------------------------------------------------
# 3) FIPS smoke harness against the BUILT jar: provider registration, FipsStatus.isReady() (power-on
#    self tests + jar HMAC integrity), algorithm KATs/roundtrips, and the native path (rebuilt libs
#    loaded, NativeEntropySource, DRBG seeded from it, native AES ECB/CBC/CFB/CTR/GCM KATs + bulk
#    roundtrips, native SHA-256). Runs every check on JDK 8/9/11/15/17 (the multi-release jar's
#    base, versions/9, /11, /15 layers plus the build JDK), then forces each CPU-supported native
#    variant on JDK 17.
# ---------------------------------------------------------------------------------------------
if [ "$RUN_HARNESS" != true ]; then
    echo "test filter '$FILTER' selects no BcFipsSmokeTest checks: smoke harness not run in this filtered build"
    exit 0
fi
HARNESS_DIR="$(mktemp -d /tmp/bcfips-harness.XXXXXX)"
cp "$HARNESS_SRC" "$HARNESS_DIR/BcFipsSmokeTest.java"
/opt/jdks/jdk8/bin/javac -source 1.8 -target 1.8 -cp "$BUILT_JAR" -d "$HARNESS_DIR" "$HARNESS_DIR/BcFipsSmokeTest.java"

HARNESS_PROPS=("-Dbcfips.expected.build_ts=$BC_NATIVE_BUILD_TS" "-Dbcfips.skip.tests=$BCFIPS_SKIP_TESTS" "-Dbcfips.cve8149.regression=$CVE8149_REGRESSION")
if [ "$CVE8149_REGRESSION" = true ]; then
    echo "CVE-2026-8149 fix present in gcm128w.c: NativeGCMOddChunkDecrypt regression check is part of the suite on every JDK and forced native variant"
else
    echo "gcm128w.c is the unpatched 2.1.0 base (no CVE-2026-8149 fix): the NativeGCMOddChunkDecrypt regression check belongs to that CVE patch and is not registered"
fi
for v in 8 9 11 15 17; do
    echo "===== bc-fips smoke harness on JDK ${v} ====="
    "/opt/jdks/jdk${v}/bin/java" "${HARNESS_PROPS[@]}" -cp "$BUILT_JAR:$HARNESS_DIR" BcFipsSmokeTest "$BUILT_JAR" "$HARNESS_FILTER" "$NATIVE_OUT" \
        | tee "$HARNESS_DIR/jdk${v}.log"
done

if [ -z "$FILTER" ]; then
    SUPPORTED="$(sed -n 's/^SUPPORTED_NATIVE_VARIANTS=//p' "$HARNESS_DIR/jdk17.log" | head -n1)"
    for variant in avx vaes vaesf; do
        if [[ " $SUPPORTED " == *" $variant "* ]]; then
            echo "===== bc-fips smoke harness on JDK 17, forced native variant ${variant} ====="
            /opt/jdks/jdk17/bin/java "${HARNESS_PROPS[@]}" -Dorg.bouncycastle.native.cpu_variant=$variant \
                -cp "$BUILT_JAR:$HARNESS_DIR" BcFipsSmokeTest "$BUILT_JAR" "" "$NATIVE_OUT"
        else
            echo "SKIP forced native variant ${variant}: the runner CPU does not support it (probe reports: '${SUPPORTED}')"
        fi
    done
fi
echo "bc-fips smoke harness passed on JDK 8, 9, 11, 15, 17"
