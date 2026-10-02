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

#ifndef _CREDENTIAL_H_
#define _CREDENTIAL_H_

#include "ctap2_cbor.h"
#include "file.h"

typedef struct CredOptions {
    const bool *rk;
    const bool *up;
    const bool *uv;
    bool present;
} CredOptions;

typedef struct CredExtensions {
    const bool *hmac_secret;
    uint64_t credProtect;
    const bool *minPinLength;
    CborByteString credBlob;
    const bool *largeBlobKey;
    const bool *thirdPartyPayment;
    bool present;
} CredExtensions;

typedef struct Credential {
    CborCharString rpId;
    CborByteString userId;
    CborCharString userName;
    CborCharString userDisplayName;
    uint64_t board_creation;
    CredExtensions extensions;
    const bool *use_sign_count;
    int64_t alg;
    int64_t curve;
    CborByteString id;
    CredOptions opts;
    bool present;
    uint64_t rtc_creation;
} Credential;

#define CRED_PROT_UV_OPTIONAL               0x01
#define CRED_PROT_UV_OPTIONAL_WITH_LIST     0x02
#define CRED_PROT_UV_REQUIRED               0x03

#define CRED_PROTO_21_S                     "\xf1\xd0\x02\x01"
#define CRED_PROTO_22_S                     "\xf1\xd0\x02\x02"
#define CRED_PROTO_23_S                     "\xf1\xd0\x02\x03"
#define CRED_PROTO_24_S                     "\xf1\xd0\x02\x04"

#define CRED_PROTO                          CRED_PROTO_22_S

#define CRED_PROTO_LEN                      4
#define CRED_IV_LEN                         12
#define CRED_TAG_LEN                        16
#define CRED_SILENT_TAG_LEN                 16

#define CRED_PROTO_RESIDENT                 CRED_PROTO_23_S
#define CRED_PROTO_RESIDENT_LEN             4
#define CRED_RESIDENT_HEADER_LEN            (CRED_PROTO_RESIDENT_LEN + 6)
#define CRED_RESIDENT_LEN                   (CRED_RESIDENT_HEADER_LEN + 32)

typedef enum
{
    CRED_PROTO_21 = 0x01,
    CRED_PROTO_22 = 0x02,
} cred_proto_t;

/* Resident credential record (EF_CRED + slot):
 *
 *   rp_id_hash[32] || cred_idr[CRED_RESIDENT_LEN] || cred_id[n] [|| user trailer]
 *
 * cred_id is the sealed credential; the private key, hmac-secret and
 * largeBlobKey are derived from it, so it is never rewritten after creation.
 * updateUserInformation stores the new user name/displayName in a trailer:
 *
 *   iv[12] || ChaCha20-Poly1305(CBOR {4: name, 5: displayName}) || tag[16] || le16(len) || "LFU1"
 *
 * bound to rp_id_hash and cred_idr through the AAD. A trailer is accepted only
 * when cred_idr re-derives from the remaining cred_id, so a legacy record whose
 * last bytes happen to look like a trailer is still read correctly.
 * Records from firmware without resident IDs are rp_id_hash[32] || cred_id[n].
 *
 * Explicit-key credentials (single-key import, lf_keyio_fido.c) come from
 * another device: their key, hmac-secret key and largeBlobKey cannot be
 * derived here, and their resident ID is the one the relying party knows. The
 * record has the same layout, with cred_idr the imported ID verbatim and
 * cred_id sealed in its own format:
 *
 *   CRED_PROTO_24_S || iv[12] || ChaCha20-Poly1305(CBOR) || tag[16]
 *
 * under a key of its own, AAD rp_id_hash. (Firmware before 2.1.0 opens any ID
 * that is not CRED_PROTO_22_S with the key credential_derive_chacha_key()
 * gives for its prefix: with that key it would sign with a key derived from
 * the ID; with this one such a record stays stored there, unreadable.) The
 * CBOR map has the keys credential_create() writes (1, 3..0x0C, all but the
 * rp_id_hash) and 0x20 resident ID, 0x21 private key, 0x22 hmac-secret key
 * (optional), 0x23 largeBlobKey (optional). The resident ID cannot re-derive:
 * the sealed copy authenticates cred_idr (and a user trailer split). Such a
 * credential is only ever used through its record, never as a bare ID. */
typedef struct resident_record {
    const uint8_t *rp_id_hash;
    const uint8_t *cred_idr;    /* NULL for records without a resident ID */
    const uint8_t *cred_id;
    size_t cred_id_len;
    const uint8_t *user_sealed; /* NULL when the user entity was never updated */
    size_t user_sealed_len;
} resident_record_t;

#define CRED_USER_TRAILER_MAGIC             "LFU1"
#define CRED_USER_TRAILER_MAGIC_LEN         4
#define CRED_USER_FIELD_MAX                 64

extern int credential_verify(uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash, bool silent);
extern int credential_create(CborCharString *rpId,
                             CborByteString *userId,
                             CborCharString *userName,
                             CborCharString *userDisplayName,
                             CredOptions *opts,
                             CredExtensions *extensions,
                             bool use_sign_count,
                             int alg,
                             int curve,
                             uint8_t *cred_id,
                             uint16_t *cred_id_len);
extern void credential_free(Credential *cred);
extern int credential_store(const uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash);
extern int credential_load(const uint8_t *cred_id,
                           size_t cred_id_len,
                           const uint8_t *rp_id_hash,
                           Credential *cred);
extern int credential_derive_hmac_key(const uint8_t *cred_id, size_t cred_id_len, uint8_t *outk);
extern int credential_derive_large_blob_key(const uint8_t *cred_id,
                                            size_t cred_id_len,
                                            uint8_t *outk);
/* Legacy resident ID derivation: the ID of records stored without one. */
extern int credential_derive_resident(const uint8_t *cred_id, size_t cred_id_len, uint8_t *outk);
/* Resident ID given to a new discoverable credential (and stored with it). */
extern void credential_new_resident_id(const uint8_t *cred_id, size_t cred_id_len, uint8_t *outk);
extern bool credential_is_resident(const uint8_t *cred_id, size_t cred_id_len);
/* True if this build can derive (and so sign with) a key on the credential's
 * curve (fido_cred_key_load()). getAssertion and credential management use
 * the same rule. */
extern bool credential_curve_supported(int64_t curve);
extern int credential_load_resident(const file_t *ef, const uint8_t *rp_id_hash, Credential *cred);
/* Splits a stored resident record. The pointers alias the file data and are
 * only valid until the next flash write. */
extern int credential_resident_parse(const file_t *ef, resident_record_t *rec);
/* True if id (as sent by a platform) names this stored credential. */
extern bool credential_resident_matches(const resident_record_t *rec, const uint8_t *id, size_t id_len);
/* The ID reported for a stored credential: the stored one, or the legacy
 * derivation for records stored without one. Never re-derived, so every
 * credential keeps the ID it was created with. */
extern void credential_resident_id(const resident_record_t *rec, uint8_t *out);
/* The same, looked up by the sealed credential ID (-1 if not stored). */
extern int credential_resident_id_lookup(const uint8_t *rp_id_hash, const uint8_t *cred_id, size_t cred_id_len, uint8_t *out);
/* Replaces the stored user name/displayName without touching the credential
 * ID or its keys. Absent or empty fields are removed (CTAP 2.1, 6.8.7). */
extern int credential_update_user(file_t *ef, const CborCharString *name, const CborCharString *displayName);
/* Byte length of s cut to at most max bytes without splitting a UTF-8 sequence. */
extern size_t credential_utf8_truncate(const char *s, size_t len, size_t max);

/* ---- Explicit-key credentials ---- */

/* Longest sealed explicit-key credential: room for every credential
 * credential_create() can make (MAX_CRED_ID_LENGTH) plus the stored keys. */
#define CRED_EXPLICIT_MAX_LEN               (1024 + 192)
/* Longest rpId of an imported credential (a DNS name has at most 253). */
#define CRED_IMPORT_RP_ID_MAX               255
#define CRED_KEY_MAX                        66      /* P-521 scalar */
#define CRED_HMAC_KEY_LEN                   64
#define CRED_LARGE_BLOB_KEY_LEN             32

struct fido_cred_key;

extern bool credential_is_explicit(const uint8_t *cred_id, size_t cred_id_len);
/* credential_load() of a parsed record: the only way to load an explicit-key
 * credential (it checks the stored resident ID), and the stored user entity
 * applied. */
extern int credential_load_record(const resident_record_t *rec, const uint8_t *rp_id_hash, Credential *cred);
/* Key material of a loaded credential (rp_id_hash: the one it was loaded
 * for): derived from its ID, or the stored material of an explicit-key
 * credential. Every user of a credential key goes through these. */
extern int credential_key_load(const Credential *cred, const uint8_t *rp_id_hash, struct fido_cred_key *key);
/* The credential can answer hmac-secret: every derived one, an explicit-key
 * one only when it was imported with its hmac-secret key. */
extern bool credential_hmac_capable(const Credential *cred);
/* CredRandomWithoutUV || CredRandomWithUV (CRED_HMAC_KEY_LEN bytes). */
extern int credential_hmac_key(const Credential *cred, const uint8_t *rp_id_hash, uint8_t *outk);
/* The largeBlobKey (CRED_LARGE_BLOB_KEY_LEN bytes) of a credential made or
 * imported with one (extensions.largeBlobKey). */
extern int credential_large_blob_key(const Credential *cred, const uint8_t *rp_id_hash, uint8_t *outk);

/* A credential to import. The pointers reference the caller's (validated)
 * record and are only read by credential_import_check(). */
typedef struct credential_explicit {
    const char *rp_id;
    size_t rp_id_len;                   /* 1..CRED_IMPORT_RP_ID_MAX */
    const uint8_t *user_id;
    size_t user_id_len;
    const char *user_name;              /* NULL: none */
    size_t user_name_len;
    const char *display_name;           /* NULL: none */
    size_t display_name_len;
    int64_t alg;
    int64_t curve;
    const uint8_t *key;                 /* EC scalar big endian, Ed25519 seed */
    size_t key_len;
    uint64_t cred_protect;              /* 1..3 */
    const uint8_t *hmac_key;            /* CRED_HMAC_KEY_LEN bytes, NULL: none */
    const uint8_t *large_blob_key;      /* CRED_LARGE_BLOB_KEY_LEN bytes, NULL: none */
    const uint8_t *cred_blob;           /* NULL: none */
    size_t cred_blob_len;
    bool use_sign_count;
    uint64_t creation_time;             /* seconds, 0: unknown */
    bool third_party_payment;
    const uint8_t *resident_id;         /* CRED_RESIDENT_LEN bytes */
} credential_explicit_t;

/* An import in two steps, so that the touch comes after every check and
 * before anything is written. Holds key material in the clear until it is
 * sealed: the caller wipes it on every path. */
typedef struct credential_import {
    /* rp_id_hash || resident ID || sealed credential; the plaintext CBOR is
     * built in place of the ciphertext */
    uint8_t record[32 + CRED_RESIDENT_LEN + CRED_EXPLICIT_MAX_LEN];
    size_t pt_len;
    char rp_id[CRED_IMPORT_RP_ID_MAX];
    size_t rp_id_len;
    int slot;                           /* EF_CRED slot written */
    int drop;                           /* a second conflicting record, deleted; -1 none */
    uint8_t gone_rp[2][32];             /* RPs of the records replaced or deleted */
    uint8_t gone;
} credential_import_t;

/* Builds the credential and finds its slot. A stored credential with the same
 * resident ID, or the same rpId and user ID, is replaced when replace is set
 * (both, when they are two), else CTAP2_ERR_CREDENTIAL_EXCLUDED.
 * CTAP2_ERR_KEY_STORE_FULL: no slot or no RP entry left;
 * CTAP2_ERR_REQUEST_TOO_LARGE: it does not fit a credential. Nothing is
 * written. */
extern int credential_import_check(credential_import_t *imp, const credential_explicit_t *x, bool replace);
/* Seals and stores what credential_import_check() prepared, with its RP entry. */
extern int credential_import_store(credential_import_t *imp);

#endif // _CREDENTIAL_H_
