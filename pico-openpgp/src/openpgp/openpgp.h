/*
 * This file is part of the Pico OpenPGP distribution (https://github.com/polhenarejos/pico-openpgp).
 * Copyright (c) 2022 Pol Henarejos.
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

#ifndef __OPENPGP_H_
#define __OPENPGP_H_

#include "stdlib.h"
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
#include <pico/stdlib.h>
#endif

#include "pico_keys.h"
#include "apdu.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ecdsa.h"
#include "crypto_utils.h"
#include "files.h"

extern bool has_pw1;
extern bool has_pw2;
extern bool has_pw3;
extern bool has_rc;
extern uint8_t session_pw1[32];
extern uint8_t session_rc[32];
extern uint8_t session_pw3[32];
extern uint8_t dek[IV_SIZE + 32];

/* How a private key record is kept: as is, encrypted with the OpenPGP data
 * key (EF_DEK), or sealed in the PIV namespace of the secure key store
 * (while an update is unconfirmed, new PIV records keep the plaintext format
 * of earlier firmware). KEY_MODE_PIV_SEALED is for key_record_write() only:
 * sealed in any case (a key moved from a sealed record). */
#define KEY_MODE_PLAIN  0
#define KEY_MODE_DEK    1
#define KEY_MODE_PIV    2
#define KEY_MODE_PIV_SEALED 3

extern int key_record_write(file_t *ef, int mode, uint8_t *kdata, uint16_t len);
extern int key_record_read(file_t *ef, int mode, uint8_t *kdata, size_t cap, int *len);
extern int store_keys(void *key_ctx, int type, uint16_t key_id, int mode);
extern void make_rsa_response(mbedtls_rsa_context *rsa);
extern void make_ecdsa_response(mbedtls_ecdsa_context *ecdsa);
extern int ecdsa_sign(mbedtls_ecdsa_context *ctx,
                      const uint8_t *data,
                      size_t data_len,
                      uint8_t *out,
                      size_t *out_len);
extern int rsa_sign(mbedtls_rsa_context *ctx,
                    const uint8_t *data,
                    size_t data_len,
                    uint8_t *out,
                    size_t *out_len);
extern int load_private_key_rsa(mbedtls_rsa_context *ctx, file_t *fkey, int mode);
extern int load_private_key_ecdsa(mbedtls_ecdsa_context *ctx, file_t *fkey, int mode);
extern int pin_reset_retries(const file_t *pin, bool force);

#define ALGO_RSA        0x01
#define ALGO_ECDH       0x12
#define ALGO_ECDSA      0x13
#define ALGO_EDDSA      0x16
#define ALGO_AES        0x70
#define ALGO_AES_128    0x71
#define ALGO_AES_192    0x72
#define ALGO_AES_256    0x74

#define LF_CURVE_ED25519    1
#define LF_CURVE_X25519     2
#ifdef LF_HAVE_25519
#include "crypto/lf_25519.h"
/* Keys on Curve25519 kept by lf_25519 (OpenPGP EdDSA ed25519 and ECDH
 * cv25519, PIV Ed25519 and X25519). The private key record is a type byte
 * and the 32-byte Ed25519 seed or X25519 scalar (little endian); the X25519
 * record is the one mbedTLS writes for Curve25519 (group id, scalar little
 * endian), so cv25519 keys of earlier firmware keep working. */
#define LF_KEY_ED25519      0xED
#define LF_KEY_X25519       ((uint8_t) MBEDTLS_ECP_DP_CURVE25519)
/* LF_CURVE_* of an OpenPGP algorithm attribute (algorithm id, OID): EdDSA
 * on ed25519 or ECDH on cv25519; 0 for anything else. */
extern int lf25519_attr_curve(const uint8_t *algo, uint16_t algo_len);
extern int lf25519_public(int curve, const uint8_t secret[32], uint8_t pub[32]);
/* A new secret (X25519: clamped). */
extern void lf25519_generate(int curve, uint8_t secret[32]);
extern int lf25519_store(uint16_t fid, int curve, const uint8_t secret[32], int mode);
/* The secret of a record of that curve (any other record: wrong data). */
extern int lf25519_load(file_t *ef, int curve, uint8_t secret[32], int mode);
/* 7F49 { 86 <the 32-byte public key> }, appended to the response. */
extern void make_25519_response(const uint8_t pub[32]);
#endif
/* OpenPGP keys on Curve25519 use lf_25519, unless the mbedTLS fork with
 * EdDSA is built in (ENABLE_EDDSA): that keeps its own code path. */
#if defined(LF_HAVE_25519) && !defined(MBEDTLS_EDDSA_C)
#define OPGP_LF_25519 1
#endif

extern void select_file(file_t *pe);
extern int parse_do(uint16_t *fids, int mode);
extern int load_dek();
extern int check_pin(const file_t *pin, const uint8_t *data, size_t len);
extern mbedtls_ecp_group_id get_ec_group_id_from_attr(const uint8_t *algo, size_t algo_len);
extern int reset_sig_count();
extern uint16_t algo_dec, algo_aut, pk_dec, pk_aut;
extern bool wait_button_pressed_fid(uint16_t fid);
extern void scan_files_openpgp();
/* Factory state of the OpenPGP application only (TERMINATE DF). */
extern int openpgp_reset(void);
extern void release_dek();
/* Ends all OpenPGP authentication (PW1, PW3, Reset Code) and wipes it. */
extern void openpgp_logout(void);
/* OpenPGP data objects a host may name (GET DATA / PUT DATA tag as sent).
 * The file table is shared with PIV, FIDO and the device files: a raw P1P2
 * must never go to search_by_fid() without passing one of these. */
extern bool openpgp_do_readable(uint16_t tag);
extern bool openpgp_do_writable(uint16_t tag);
/* Cardholder certificate instance chosen by SELECT DATA (default: first). */
extern file_t *openpgp_ch_cert_file(void);
extern int inc_sig_count();
extern int dek_encrypt(uint8_t *data, size_t len);
extern int dek_decrypt(uint8_t *data, size_t len);
/* EF_DEK: IV and up to four 32-byte slots (PW1, Reset Code, PW3, PIV
 * mark), sealed in the OpenPGP namespace of the secure key store (files of
 * earlier firmware: plaintext until the firmware is confirmed). */
#define DEK_FILE_MAX    (IV_SIZE + 32 * 4)
extern uint16_t dek_file_len(void);
extern int dek_file_read(uint8_t *buf, uint16_t *len);
extern int dek_file_write(const uint8_t *buf, uint16_t len);
/* Seals a plaintext data key file and OpenPGP PIN verifiers of earlier
 * firmware (once confirmed). */
extern void dek_file_migrate(void);
/* Data key, opened from slot src with the PW the command verified, into
 * slot 0 (PW1), 1 (RC) or 2 (PW3) of EF_DEK under wrap_key (NULL: wipe the
 * slot). */
extern int dek_store_slot(uint8_t src, uint8_t slot, const uint8_t *wrap_key);
/* New PW record with its data key slot (see openpgp.c). */
extern int pw_replace(file_t *pw, uint8_t src, uint8_t slot, const uint8_t *pin, uint16_t len,
                      uint8_t len_byte, uint8_t *session);
/* Length byte flag of a Reset Code written by this firmware. */
#define RC_MARK         0x80
/* PIN verifier records (OpenPGP PW1, Reset Code, PW3; PIV PIN, PUK): the
 * length byte and double_hash_pin() of the PIN, sealed in the namespace of
 * the application (records of earlier firmware: plaintext, sealed once the
 * firmware is confirmed). pw_rec_read() gives the record as it was written
 * (PICOKEY_WRONG_DATA for one that does not open, PICOKEY_ERR_BLOCKED while
 * the key store is locked). */
#define PW_REC_LEN      33
extern int pw_rec_read(const file_t *pw, uint8_t rec[PW_REC_LEN]);
extern int pw_rec_write(file_t *pw, const uint8_t rec[PW_REC_LEN]);
/* A new verifier record for pin with the given length byte. */
extern int pw_rec_set(file_t *pw, const uint8_t *pin, uint16_t len, uint8_t len_byte);
/* Seals a plaintext verifier of earlier firmware (once confirmed). */
extern void pw_rec_migrate(file_t *pw);
/* The key store of the profile is locked (root key held until it is bound,
 * or a HARDENED build on a chip that is not): no OpenPGP or PIV operation
 * that needs a PIN, a key or the data key may run. */
extern bool openpgp_store_locked(void);
/* Byte idx of the PW status record EF_PW_PRIV (bounds checked). */
extern int openpgp_pw_status_set(uint8_t idx, uint8_t val);
/* Seals a plaintext PIV key record of earlier firmware (once confirmed). */
extern int key_record_migrate(file_t *ef);

/* PIV algorithm identifiers (SP 800-78-4; E0 and E1 as on YubiKey 5.7). */
#define PIV_ALGO_3DES       0x03
#define PIV_ALGO_AES128     0x08
#define PIV_ALGO_AES192     0x0a
#define PIV_ALGO_AES256     0x0c
#define PIV_ALGO_RSA1024    0x06
#define PIV_ALGO_RSA2048    0x07
#define PIV_ALGO_RSA3072    0x05
#define PIV_ALGO_RSA4096    0x16
#define PIV_ALGO_ECCP256    0x11
#define PIV_ALGO_ECCP384    0x14
#define PIV_ALGO_ED25519    0xE0
#define PIV_ALGO_X25519     0xE1

/* Single-key transfer (lf_keyio_pgp.c). */
/* PW3 checked with the PIN given, as VERIFY 83 checks it: the same retry
 * counter (63Cx, 6983 once blocked) and, if right, the PW3 security status
 * and session key, which the caller ends with openpgp_logout(). */
extern int openpgp_verify_pw3(const uint8_t *pin, size_t len);
/* The key of PIV slot 9A, 9C, 9D, 9E or 82-95 and its algorithm, PIN and
 * touch policy as the card enforces them; NULL when the slot holds no key.
 * Never the management key (9B) or the attestation key (F9). */
extern file_t *piv_slot_key(uint8_t slot, uint8_t *algo, uint8_t *pin_policy, uint8_t *touch_policy);

#endif
