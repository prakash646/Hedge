#!/bin/sh
# Prove each lemma separately with a per-lemma wall-clock limit.
# usage: ./run_lemmas.sh [model.spthy] [seconds]   -> results_<model>.txt
export LANG=C.UTF-8 LC_ALL=C.UTF-8
F=${1:-hedge.spthy}; LIMIT=${2:-1800}
OUT=results_$(basename $F .spthy).txt
echo "# tamarin-prover $(tamarin-prover --version 2>/dev/null | grep -o 'tamarin-prover [0-9.]*' | head -1), maude $(maude --version 2>/dev/null); limit ${LIMIT}s per lemma" > $OUT
for L in $(grep -oE '^lemma [A-Za-z_0-9]+' $F | cut -d' ' -f2); do
  S=$(date +%s)
  R=$(timeout $LIMIT tamarin-prover --derivcheck-timeout=0 --prove=$L $F 2>&1 | grep -E "^  $L \(" | head -1)
  E=$(( $(date +%s) - S ))
  [ -z "$R" ] && R="  $L: TIMEOUT (> ${LIMIT}s)"
  echo "$R   [wall ${E}s]" >> $OUT
done
grep -q "WARNING" $OUT || true
echo DONE >> $OUT
