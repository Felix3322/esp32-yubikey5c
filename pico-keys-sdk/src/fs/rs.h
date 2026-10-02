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
 * Reed-Solomon error correction over GF(2^8) for the storage layer.
 *
 * Systematic RS(n, n - RS_NSYM) code, n <= 255: primitive polynomial 0x11D,
 * generator alpha = 2, first consecutive root alpha^0. These are the
 * parameters of the common "reedsolo" implementation, which the host tests use
 * as reference. With RS_NSYM = 32 parity bytes a block of up to 223 data bytes
 * survives up to 16 corrupted bytes anywhere in data or parity.
 *
 * This is error correction for flash retention, not cryptography: it offers no
 * protection against deliberate modification.
 */

#ifndef _RS_H_
#define _RS_H_

#include <stddef.h>
#include <stdint.h>

#define RS_NSYM         32
#define RS_MAX_DATA     (255 - RS_NSYM)   /* 223 */

/* Parity bytes needed to protect len bytes split into RS_MAX_DATA blocks. */
#define RS_PARITY_LEN(len) ((((len) + RS_MAX_DATA - 1) / RS_MAX_DATA) * RS_NSYM)

/* Computes RS_NSYM parity bytes for one block of 1..RS_MAX_DATA bytes. */
extern void rs_encode_block(const uint8_t *data, size_t len, uint8_t parity[RS_NSYM]);

/* Corrects one block in place (data and parity). Returns the number of
 * corrected bytes (0 if the block was intact) or -1 if it is uncorrectable. */
extern int rs_decode_block(uint8_t *data, size_t len, uint8_t parity[RS_NSYM]);

/* Whole buffer helpers: the buffer is cut into RS_MAX_DATA byte blocks (the
 * last one shorter) and parity holds RS_PARITY_LEN(len) bytes. */
extern void rs_encode(const uint8_t *data, size_t len, uint8_t *parity);
/* Returns the total number of corrected bytes, or -1 if any block failed
 * (blocks that could be corrected are corrected anyway). */
extern int rs_decode(uint8_t *data, size_t len, uint8_t *parity);

#endif
