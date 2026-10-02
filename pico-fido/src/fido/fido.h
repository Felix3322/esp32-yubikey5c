/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
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

#ifndef _FIDO_H_
#define _FIDO_H_

#if defined(PICO_PLATFORM)
#include "pico/stdlib.h"
#endif
#ifndef ESP_PLATFORM
#include "common.h"
#else
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#endif

#include "mbedtls/ecdsa.h"
#ifdef MBEDTLS_EDDSA_C
#include "mbedtls/eddsa.h"
#endif
#include "hid/ctap_hid.h"

/* Ed25519 credentials (COSE EdDSA, -8). Through the mbedTLS EdDSA fork
 * (ENABLE_EDDSA) when the build has it; otherwise through lf_25519
 * (pico-keys-sdk), which needs no particular mbedTLS (ESP-IDF's included).
 *   FIDO_HAVE_ED25519  one of the two is in the build: EdDSA credentials
 *                      can be made and used, getInfo lists -8.
 *   FIDO_ED25519_LF    the lf_25519 one. Upstream mbedTLS has no Ed25519
 *                      group, so such a key is a seed, not an mbedTLS key
 *                      pair (see fido_cred_key_t).
 * Both derive the same key from a credential ID. */
#if defined(MBEDTLS_EDDSA_C)
#define FIDO_HAVE_ED25519   1
#elif defined(LF_HAVE_25519)
#define FIDO_HAVE_ED25519   1
#define FIDO_ED25519_LF     1
#include "crypto/lf_25519.h"
#endif

#define CTAP_PUBKEY_LEN (65)
#define KEY_PATH_LEN (32)
#define KEY_PATH_ENTRIES (KEY_PATH_LEN / sizeof(uint32_t))
#define SHA256_DIGEST_LENGTH (32)
#define KEY_HANDLE_LEN (KEY_PATH_LEN + SHA256_DIGEST_LENGTH)

extern int scan_files_fido();
extern int derive_key(const uint8_t *app_id,
                      bool new_key,
                      uint8_t *key_handle,
                      int,
                      mbedtls_ecp_keypair *key);
extern int verify_key(const uint8_t *appId, const uint8_t *keyHandle, mbedtls_ecp_keypair *);
/* Presence, true when NO presence was obtained. Everyday operations only
 * (makeCredential, getAssertion, U2F, selection): follows the per-profile
 * automatic presence policy. */
extern bool fido_wait_everyday_presence(void);
/* Destructive, copying and security-setting operations: always a physical
 * press. */
extern bool fido_wait_physical_press(void);
extern void init_fido();
extern mbedtls_ecp_group_id fido_curve_to_mbedtls(int curve);
extern int mbedtls_curve_to_fido(mbedtls_ecp_group_id id);
extern int fido_load_key(int curve, const uint8_t *cred_id, mbedtls_ecp_keypair *key);

/* The private key of a credential, for every curve a credential can have:
 * an mbedTLS key pair, or (FIDO_ED25519_LF) the Ed25519 seed and its public
 * key. fido_cred_key_free() wipes it; it may be called more than once. */
typedef struct fido_cred_key {
    int curve;                  /* FIDO2_CURVE_* */
    mbedtls_ecp_keypair ec;     /* every curve but a FIDO_ED25519_LF key */
#ifdef FIDO_ED25519_LF
    uint8_t ed_seed[LF_ED25519_SEED_LEN];
    uint8_t ed_pub[LF_ED25519_PUB_LEN];
#endif
} fido_cred_key_t;

extern void fido_cred_key_init(fido_cred_key_t *key);
extern void fido_cred_key_free(fido_cred_key_t *key);
/* The key of the credential cred_id on curve (FIDO2_CURVE_*), derived from
 * the credential ID and the device key as fido_load_key() does. */
extern int fido_cred_key_load(fido_cred_key_t *key, int curve, const uint8_t *cred_id);
/* Private key bytes of a single-key transfer: the EC scalar big endian at the
 * curve's length (P-256, P-384, P-521, secp256k1), the Ed25519 seed (lf_25519
 * builds). Import checks the length and the scalar range, and computes the
 * public key; key is wiped on failure. Export writes *len bytes of out. Other
 * curves: CTAP2_ERR_UNSUPPORTED_ALGORITHM. */
extern int fido_cred_key_import(fido_cred_key_t *key, int curve, const uint8_t *priv, size_t len);
extern int fido_cred_key_export(const fido_cred_key_t *key, uint8_t *out, size_t cap, size_t *len);
/* Signature of msg (authenticatorData || clientDataHash) with the
 * credential's algorithm: ECDSA over SHA-256/384/512 by curve (DER), or
 * pure EdDSA (no prehash; 64 bytes for Ed25519). 0 on success. */
extern int fido_cred_key_sign(fido_cred_key_t *key, const uint8_t *msg, size_t len,
                              uint8_t *sig, size_t sig_size, size_t *sig_len);
/* Device key (fido.c): load, store (sks record) and the host-sealed state
 * (ef_keydev_enc, AUT_ENABLE / restore). load_keydev returns
 * PICOKEY_ERR_BLOCKED while a sealed key is not unlocked. keydev_store
 * refuses to write while the key is sealed; keydev_store_unsealing (only
 * for AUT_DISABLE) writes it and then removes the sealed copy. */
extern int load_keydev(uint8_t key[32]);
extern bool keydev_is_sealed(void);
extern int keydev_store(const uint8_t key[32]);
extern int keydev_store_unsealing(const uint8_t key[32]);
/* Re-seals a device key of an earlier firmware format (needs the PIN
 * session for the PIN-bound formats); nothing to do otherwise. */
extern int keydev_migrate_legacy(void);
/* New FIDO records are sealed (sks) only once the firmware is confirmed, or
 * in a profile created secure; before, they keep the format earlier
 * firmware reads, as an unconfirmed update can still roll back. */
extern bool fido_seal_now(void);
/* The profile root key is in use (key store unlocked, root not held):
 * otherwise nothing derives FIDO keys, PIN verifiers or writes records. */
extern bool fido_keystore_ok(void);
extern int fido_ppaut_store(void);
extern int fido_certdev_build(const uint8_t key[32], uint8_t *cert, size_t cap, size_t *len);
/* AAGUID this profile reports in getInfo, attestation and enterprise
 * attestation CSRs: the profile's own EF_AAGUID when it set one, else the
 * build's default (ctap2_cbor.h aaguid[16]). Always succeeds. */
extern void fido_get_aaguid(uint8_t out[16]);
/* Sets the profile's AAGUID (exactly 16 bytes), or clears it back to the
 * build default when in is NULL. Requires the key store unlocked (the
 * value lives in the profile's own flash file); the caller (lf_mgmt via
 * lf_mgmt_set_aaguid_hooks) is responsible for the touch confirmation. */
extern int fido_aaguid_set(const uint8_t *in);
extern int encrypt(uint8_t protocol, const uint8_t *key, const uint8_t *in, uint16_t in_len, uint8_t *out);
extern int decrypt(uint8_t protocol, const uint8_t *key, const uint8_t *in, uint16_t in_len, uint8_t *out);
extern int ecdh(uint8_t protocol, const mbedtls_ecp_point *Q, uint8_t *sharedSecret);

#define FIDO2_ALG_ES256     -7 //ECDSA-SHA256
#define FIDO2_ALG_EDDSA     -8 //EdDSA
#define FIDO2_ALG_ESP256    -9 //ECDSA-SHA256 P256
#define FIDO2_ALG_ED25519   -19 //EDDSA Ed25519
#define FIDO2_ALG_ES384     -35 //ECDSA-SHA384
#define FIDO2_ALG_ES512     -36 //ECDSA-SHA512
#define FIDO2_ALG_ECDH_ES_HKDF_256 -25 //ECDH-ES + HKDF-256
#define FIDO2_ALG_ES256K    -47
#define FIDO2_ALG_ESP384    -51 //ECDSA-SHA384 P384
#define FIDO2_ALG_ESP512    -52 //ECDSA-SHA512 P521
#define FIDO2_ALG_ED448     -53 //EDDSA Ed448
#define FIDO2_ALG_RS256     -257
#define FIDO2_ALG_RS384     -258
#define FIDO2_ALG_RS512     -259
#define FIDO2_ALG_ESB256    -265 //ECDSA-SHA256 BP256r1
#define FIDO2_ALG_ESB384    -267 //ECDSA-SHA384 BP384r1
#define FIDO2_ALG_ESB512    -268 //ECDSA-SHA512 BP512r1

#define FIDO2_CURVE_P256        1
#define FIDO2_CURVE_P384        2
#define FIDO2_CURVE_P521        3
#define FIDO2_CURVE_X25519      4
#define FIDO2_CURVE_X448        5
#define FIDO2_CURVE_ED25519     6
#define FIDO2_CURVE_ED448       7
#define FIDO2_CURVE_P256K1      8
#define FIDO2_CURVE_BP256R1     9
#define FIDO2_CURVE_BP384R1     10
#define FIDO2_CURVE_BP512R1     11

#define FIDO2_AUT_FLAG_UP       0x1
#define FIDO2_AUT_FLAG_UV       0x4
#define FIDO2_AUT_FLAG_AT       0x40
#define FIDO2_AUT_FLAG_ED       0x80

#define FIDO2_OPT_EA            0x01 // Enterprise Attestation
#define FIDO2_OPT_AUV           0x02 // User Verification

#define MAX_PIN_RETRIES 8
extern bool getUserPresentFlagValue();
extern bool getUserVerifiedFlagValue();
extern void clearUserPresentFlag();
extern void clearUserVerifiedFlag();
extern void clearPinUvAuthTokenPermissionsExceptLbw();
extern void send_keepalive();
extern uint32_t get_sign_counter();
/* Stores and returns the next counter value (before it is signed). */
extern int fido_next_sign_counter(uint32_t *out);
/* Raises the counter to at least min, never lowers it (an imported
 * credential continues from the exporting device's counter). */
extern int fido_sign_counter_raise(uint32_t min);
extern uint8_t get_opts();
extern void set_opts(uint8_t);
#define MAX_CREDENTIAL_COUNT_IN_LIST 16
#define MAX_CRED_ID_LENGTH        1024
#define MAX_RESIDENT_CREDENTIALS  256
#define MAX_CREDBLOB_LENGTH       128
#define MAX_MSG_SIZE              1024
#define MAX_FRAGMENT_LENGTH       (MAX_MSG_SIZE - 64)
#define MAX_LARGE_BLOB_SIZE       2048


#define TRANSPORT_TIME_LIMIT (30 * 1000) //USB

bool check_user_presence();
extern int fido_up_error();
/* False once the window after power up in which the FIDO keys may be
 * destroyed (reset, device key replacement) has passed. */
extern bool fido_in_power_up_window(void);
/* The same, ignoring the board option that disables it (device key
 * protect, export and restore). */
extern bool fido_in_strict_power_up_window(void);
/* Creates the self-signed device certificate from the device key when it is
 * missing, or always with replace. */
extern int fido_certdev_generate(bool replace);

typedef struct pinUvAuthToken {
    uint8_t *data;
    size_t len;
    bool in_use;
    uint8_t permissions;
    uint8_t rp_id_hash[32];
    bool has_rp_id;
    bool user_present;
    bool user_verified;
} pinUvAuthToken_t;

typedef struct persistentPinUvAuthToken {
    uint8_t *data;
    size_t len;
    uint8_t permissions;
} persistentPinUvAuthToken_t;

extern uint32_t user_present_time_limit;

extern pinUvAuthToken_t paut;
extern persistentPinUvAuthToken_t ppaut;
extern uint8_t paut_token[32];
extern uint8_t ppaut_token[32];

extern int verify(uint8_t protocol, const uint8_t *key, const uint8_t *data, uint16_t len, const uint8_t *sign, size_t sign_len);
extern uint16_t fido_export_pin_check(const uint8_t *pin, uint16_t len);

extern uint8_t session_pin[32];

#endif //_FIDO_H
