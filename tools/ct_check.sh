#!/bin/sh
# Constant-time check of the HEDGE device and gateway code paths with Valgrind memcheck.
# Usage: tools/ct_check.sh [opt-level ...]   (default: -O2 -Os -O3)
# Needs: gcc, valgrind (with headers: apt install valgrind).
set -e
cd "$(dirname "$0")/.."
V=vendor
OUT=${OUT:-results/ct_check.txt}
mkdir -p build-ct
: > "$OUT"
for O in ${@:-"-O2" "-Os" "-O3"}; do
  for VAR in hedged unhedged; do
    X=""; [ "$VAR" = unhedged ] && X="-DHEDGE_UNHEDGED"
    B=build-ct/ct_check_${VAR}${O}
    CF="$O -g -DHEDGE_CT_TESTING -DMLK_CONFIG_CT_TESTING_ENABLED -DMLK_CONFIG_PARAMETER_SET=768 $X \
        -Iinclude -I$V/romulus -I$V/mlkem -I$V/monocypher -I$V/sha3"
    gcc $CF -I$V/ascon/aead128 -I$V/ascon -Dcrypto_aead_encrypt=ascon_aead128_encrypt \
        -Dcrypto_aead_decrypt=ascon_aead128_decrypt -c $V/ascon/aead128/aead.c -o $B.aead.o
    gcc $CF -I$V/ascon/hash256 -I$V/ascon -Dcrypto_hash=ascon_hash256 -c $V/ascon/hash256/hash.c -o $B.hash.o
    gcc $CF -I$V/ascon/cxof128 -I$V/ascon -Dcrypto_cxof=ascon_cxof128 -Dcrypto_hash=ascon_cxof128_hash_unused \
        -c $V/ascon/cxof128/hash.c -o $B.cxof.o
    gcc $CF tools/ct_check.c src/prims.c src/comb.c src/kdf.c src/xwing.c src/handshake.c src/random_host.c \
        $V/romulus/romulus-n-aead.c $V/romulus/internal-romulus.c $V/romulus/internal-skinny-plus.c \
        $V/romulus/internal-util.c $V/mlkem/mlkem_native.c $V/monocypher/monocypher.c $V/sha3/sha3.c \
        $B.aead.o $B.hash.o $B.cxof.o -o $B
    echo "=== gcc $O, $VAR ===" | tee -a "$OUT"
    valgrind --error-exitcode=1 --track-origins=yes "$B" > build-ct/log.txt 2>&1 && st=clean || st=FLAGGED
    grep -E "ct_check:|ERROR SUMMARY" build-ct/log.txt | sed 's/==[0-9]*== //' | tee -a "$OUT"
    if [ $st = FLAGGED ]; then grep -A12 "depends on uninitialised\|Use of uninitialised" build-ct/log.txt | head -60 | tee -a "$OUT"; fi
  done
done
# positive control: the same check must flag a deliberately variable-time comparison
echo "=== positive control (gcc -O2, deliberate leak) ===" | tee -a "$OUT"
valgrind --error-exitcode=1 build-ct/ct_check_hedged-O2 leak > build-ct/log.txt 2>&1 && echo "NOT DETECTED (check is vacuous!)" | tee -a "$OUT" || \
  { grep -E "ERROR SUMMARY" build-ct/log.txt | sed 's/==[0-9]*== //' | tee -a "$OUT"; grep -m1 -A3 "depends on uninitialised" build-ct/log.txt | sed 's/==[0-9]*== //' | tee -a "$OUT"; }
