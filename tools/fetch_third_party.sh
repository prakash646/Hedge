#!/bin/sh
# Fetch the pinned upstream repositories into third_party/.
# Needed only for the STM32 assembly builds (make -C stm32 VARIANT=asm|fast|basefast)
# and for regenerating test vectors; the default builds use vendor/ only.
set -e
cd "$(dirname "$0")/.."
mkdir -p third_party && cd third_party
fetch() { # name url commit
  [ -d "$1" ] || git clone -q "$2" "$1"
  git -C "$1" checkout -q "$3"
  echo "$1 @ $3"
}
fetch ascon-c                       https://github.com/ascon/ascon-c                          446347f
fetch lwc-finalists                 https://github.com/rweather/lwc-finalists                 77b23e6
fetch mlkem-native                  https://github.com/pq-code-package/mlkem-native           7da6bd1
fetch Monocypher                    https://github.com/LoupVaillant/Monocypher                e65d277
fetch tiny_sha3                     https://github.com/mjosaarinen/tiny_sha3                  dcbb319
fetch draft-connolly-cfrg-xwing-kem https://github.com/dconnolly/draft-connolly-cfrg-xwing-kem 984c2f7
fetch pyascon                       https://github.com/meichlseder/pyascon                    ed24e54
