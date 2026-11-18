/* VARIANT=fast: route Monocypher's X25519 entry points to E. Lenngren's
 * Cortex-M4 assembly (github.com/Emill/X25519-Cortex-M4, commit e85f816).
 * monocypher.o is built with its own crypto_x25519* renamed to mono_x25519*.
 * Both implementations clamp the scalar, so results are identical; the
 * firmware's X-Wing known-answer test checks this on the device.
 * SPDX-License-Identifier: MIT */
#include <stdint.h>
#include "x25519-cortex-m4.h"
void crypto_x25519(uint8_t raw_shared_secret[32], const uint8_t your_secret_key[32],
                   const uint8_t their_public_key[32])
{ curve25519_scalarmult(raw_shared_secret, your_secret_key, their_public_key); }
void crypto_x25519_public_key(uint8_t public_key[32], const uint8_t secret_key[32])
{ static const uint8_t base[32] = { 9 }; curve25519_scalarmult(public_key, secret_key, base); }
