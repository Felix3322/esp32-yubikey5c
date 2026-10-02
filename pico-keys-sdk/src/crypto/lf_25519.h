/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * Ed25519 (RFC 8032, pure EdDSA with SHA-512) and X25519 (RFC 7748) for
 * builds whose mbedTLS has no EdDSA (ESP-IDF, upstream mbedTLS).
 *
 * Constant time with respect to secret data (no secret-dependent branches
 * or table indices). Secrets are the 32-byte seed (Ed25519) and the 32-byte
 * scalar (X25519); intermediate secrets are wiped before returning.
 *
 * All functions return 0 on success, -1 on failure.
 */

#ifndef _LF_25519_H_
#define _LF_25519_H_

#include <stddef.h>
#include <stdint.h>

#define LF_ED25519_SEED_LEN     32
#define LF_ED25519_PUB_LEN      32
#define LF_ED25519_SIG_LEN      64
#define LF_X25519_LEN           32

/* Public key A = [s]B from the seed (s = clamped SHA-512(seed)[0..31]). */
extern int lf_ed25519_public_key(uint8_t pub[LF_ED25519_PUB_LEN], const uint8_t seed[LF_ED25519_SEED_LEN]);

/* Signature of msg. pub must be the key of seed (it is hashed into the
 * signature); pass NULL to have it recomputed. */
extern int lf_ed25519_sign(uint8_t sig[LF_ED25519_SIG_LEN], const uint8_t *msg, size_t len,
                           const uint8_t seed[LF_ED25519_SEED_LEN], const uint8_t *pub);

/* 0 if sig is a valid signature of msg under pub (rejects non-canonical S
 * and points that do not decode). */
extern int lf_ed25519_verify(const uint8_t sig[LF_ED25519_SIG_LEN], const uint8_t *msg, size_t len,
                             const uint8_t pub[LF_ED25519_PUB_LEN]);

/* X25519: out = clamp(scalar) * u(point). Fails (-1) on an all-zero result
 * (low-order point), as RFC 7748 recommends for key agreement. */
extern int lf_x25519(uint8_t out[LF_X25519_LEN], const uint8_t scalar[LF_X25519_LEN],
                     const uint8_t point[LF_X25519_LEN]);

/* X25519 public key: clamp(scalar) * 9. */
extern int lf_x25519_public_key(uint8_t pub[LF_X25519_LEN], const uint8_t scalar[LF_X25519_LEN]);

#endif
