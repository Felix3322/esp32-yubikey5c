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
 * Secure key store (sks): authenticated encryption of objects at rest.
 *
 * Record layout: 'L' 'K' version ns | nonce(12) | ciphertext | tag(16)
 * Key:  HKDF-SHA256(ikm = device root key, salt = SHA256(serial),
 *                   info = "LibreFido/sks/v1" || ns || epoch(ns))
 * AAD:  the 4 byte header || object id (big endian)
 *
 * Namespaces isolate applications cryptographically: an object sealed for
 * PIV cannot be opened as FIDO/OpenPGP/OATH data (different key and AAD),
 * and an object cannot be moved to another id undetected. Rotating a
 * namespace epoch makes every record of that namespace unrecoverable
 * (application reset = crypto-shredding).
 */

#ifndef _SKS_H_
#define _SKS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "file.h"

enum {
    SKS_NS_FIDO = 1,
    SKS_NS_OPENPGP = 2,
    SKS_NS_PIV = 3,
    SKS_NS_OATH = 4,
    SKS_NS_OTP = 5,
    SKS_NS_CONFIG = 6,
    SKS_NS_ATTEST = 7,
    SKS_NS_MAX = 8,
};

#define SKS_VERSION     1
#define SKS_HDR_LEN     4
#define SKS_NONCE_LEN   12
#define SKS_TAG_LEN     16
#define SKS_OVERHEAD    (SKS_HDR_LEN + SKS_NONCE_LEN + SKS_TAG_LEN)

#define EF_SKS_EPOCHS   0xE022

/* out must hold len + SKS_OVERHEAD bytes. */
extern int sks_seal(uint8_t ns, uint16_t id, const uint8_t *pt, size_t len, uint8_t *out);
/* in_len includes the overhead; pt must hold in_len - SKS_OVERHEAD bytes. */
extern int sks_open(uint8_t ns, uint16_t id, const uint8_t *in, size_t in_len, uint8_t *pt);
/* True if the buffer carries an sks record of namespace ns. */
extern bool sks_is_sealed(uint8_t ns, const uint8_t *in, size_t in_len);
/* New random epoch for ns: all its records become undecryptable. */
extern int sks_rotate(uint8_t ns);

/*
 * File helpers: the record is bound to the file id (AAD), so a sealed file
 * cannot be copied over another one.
 *
 * sks_file_put() seals pt and writes it to ef (does not call
 * low_flash_available(); the caller commits).
 *
 * sks_file_get() opens ef into pt (capacity cap) and sets *len. A file
 * written before sealing existed (plaintext) is returned as is with
 * *legacy = true, so the caller can re-seal it (migration, but only when
 * lf_migrate_ok(): an unconfirmed firmware may still roll back to one that
 * cannot read sealed records). Profiles created secure never accept
 * plaintext (lf_profile_sealed_only()). A sealed record that fails
 * authentication is never returned as plaintext: PICOKEY_WRONG_DATA.
 */
extern int sks_file_put(uint8_t ns, file_t *ef, const uint8_t *pt, size_t len);
extern int sks_file_get(uint8_t ns, const file_t *ef, uint8_t *pt, size_t cap, size_t *len, bool *legacy);

#endif // _SKS_H_
