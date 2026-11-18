#!/bin/sh
export LANG=C.UTF-8 LC_ALL=C.UTF-8
S=$(date +%s)
R=$(timeout ${3:-900} tamarin-prover --derivcheck-timeout=0 --prove=$2 $1 2>&1 | grep -E "^  $2 \(" | head -1)
[ -z "$R" ] && R="  $2: TIMEOUT"
echo "$R   [wall $(( $(date +%s)-S ))s]"
