/* Host randomness (Linux/macOS): getentropy(). The Pico build supplies its own.
 * Also provides randombytes() required by mlkem-native's API (unused by the
 * derandomized calls HEDGE makes, but needed at link time).
 * SPDX-License-Identifier: MIT */
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include "hedge.h"

int hedge_randombytes(uint8_t *out, size_t n)
{
    while (n > 0) {
        size_t chunk = n > 256 ? 256 : n;
        if (getentropy(out, chunk) != 0) return -1;
        out += chunk;
        n -= chunk;
    }
    return 0;
}

int randombytes(uint8_t *out, size_t outlen);
int randombytes(uint8_t *out, size_t outlen) { return hedge_randombytes(out, outlen); }
