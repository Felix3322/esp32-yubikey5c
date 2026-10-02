/*
 * This file is part of the Pico OpenPGP distribution (https://github.com/polhenarejos/pico-openpgp).
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

/* Single-key transfer of OpenPGP and PIV private keys (lf_keyio.h): the
 * listing and the export. Imports go through the applications themselves
 * (OpenPGP PUT DATA and IMPORT DATA with PW3, PIV INS FE with the management
 * key), as on any card.
 *
 * The private key of a record (key 3 of both records) is a map of byte
 * strings, the private key in the form the card uses it:
 *   RSA      {1: e, 2: p, 3: q}, unsigned big endian without leading zero
 *            bytes. e is always 65537: the card keeps P and Q only
 *            (store_keys()) and uses them with that exponent.
 *   EC       {6: d, big endian, left-padded to the byte length of the group
 *            order (P-256 32, P-384 48, P-521 66 bytes), 7: the public key,
 *            04 || x || y}.
 *   Ed25519  {6: the 32-byte seed of RFC 8032 (what a signer hashes; the
 *            Raw private key of Python cryptography), 7: the 32-byte public
 *            key}.
 *   X25519   {6: the 32-byte scalar in the byte order of RFC 7748, little
 *            endian (the Raw private key of Python cryptography), as the
 *            card stores it: clamped if the card generated it, as given if it
 *            was imported; 7: the 32-byte public u-coordinate, little
 *            endian}. OpenPGP IMPORT DATA (92) takes the scalar as GnuPG
 *            keeps it, an MPI, that is byte-reversed; PIV INS FE (08) takes
 *            it as it is here. */

#ifdef ESP_PLATFORM
#include "esp_compat.h"
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#else
#include "common.h"
#endif
#include "openpgp.h"
#include "do.h"
#include "lf_keyio.h"
#include "lf_policy.h"
#include "profile.h"
#include "mbedtls/platform_util.h"

/* Status words of the hooks (lf_keyio.h). */
#define KIO_OK              0x9000
#define KIO_EXEC_ERROR      0x6400
#define KIO_SECRET_NEEDED   0x6982
#define KIO_NO_TOUCH        0x6985
#define KIO_NOT_ALLOWED     0x6986
#define KIO_UNSUPPORTED     0x6A81
#define KIO_NO_KEY          0x6A88

/* How the private key of a slot is kept, from its algorithm. */
enum { KT_NONE, KT_RSA, KT_EC, KT_ED25519, KT_X25519 };

/* key: x as an unsigned big-endian byte string of len bytes (0: without
 * leading zero bytes), through buf (cap bytes, wiped). */
static CborError encode_mpi(CborEncoder *map, uint8_t key, const mbedtls_mpi *x, size_t len, uint8_t *buf,
                            size_t cap) {
    if (len == 0) {
        len = mbedtls_mpi_size(x);
    }
    if (len == 0 || len > cap || mbedtls_mpi_write_binary(x, buf, len) != 0) {
        return CborErrorInternalError;
    }
    CborError e = cbor_encode_uint(map, key);
    e |= cbor_encode_byte_string(map, buf, len);
    mbedtls_platform_zeroize(buf, len);
    return e;
}

/* An EC group whose private key is a scalar of the group order, big
 * endian (short Weierstrass: NIST, Brainpool, secp256k1). Keys on Curve25519
 * are the lf_25519 records; those of the EdDSA mbedTLS (ENABLE_EDDSA) have
 * a form of that library and are not exported. */
static bool group_weierstrass(mbedtls_ecp_group_id gid) {
    return gid != MBEDTLS_ECP_DP_NONE && gid != MBEDTLS_ECP_DP_CURVE25519 && gid != MBEDTLS_ECP_DP_CURVE448
#ifdef MBEDTLS_EDDSA_C
           && gid != MBEDTLS_ECP_DP_ED25519 && gid != MBEDTLS_ECP_DP_ED448
#endif
    ;
}

/* Record key 3: the private key of ef (mode KEY_MODE_DEK: the data key must
 * be open to the session, KEY_MODE_PIV) and its public key, the key of type
 * kt (for KT_EC on group gid). */
static uint16_t encode_private(CborEncoder *rec, file_t *ef, int mode, int kt, mbedtls_ecp_group_id gid) {
    /* p or q (the record P || Q is at most 512 bytes, store_keys()), d or
     * an EC point */
    uint8_t buf[MAX(4096 / 16, MBEDTLS_ECP_MAX_PT_LEN)];
    CborEncoder m;
    CborError e = CborNoError;
    uint16_t sw = KIO_OK;
    if (kt == KT_RSA) {
        mbedtls_rsa_context rsa;
        mbedtls_rsa_init(&rsa);
        if (load_private_key_rsa(&rsa, ef, mode) != PICOKEY_OK) {
            sw = KIO_EXEC_ERROR;
        }
        else {
            e |= cbor_encode_uint(rec, 3);
            e |= cbor_encoder_create_map(rec, &m, 3);
            e |= encode_mpi(&m, 1, &rsa.E, 0, buf, sizeof(buf));
            e |= encode_mpi(&m, 2, &rsa.P, 0, buf, sizeof(buf));
            e |= encode_mpi(&m, 3, &rsa.Q, 0, buf, sizeof(buf));
            e |= cbor_encoder_close_container(rec, &m);
        }
        mbedtls_rsa_free(&rsa);
    }
    else if (kt == KT_EC) {
        mbedtls_ecp_keypair kp;
        mbedtls_ecp_keypair_init(&kp);
        if (load_private_key_ecdsa(&kp, ef, mode) != PICOKEY_OK) {
            sw = KIO_EXEC_ERROR;
        }
        else if (kp.grp.id != gid || mbedtls_ecp_get_type(&kp.grp) != MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
            sw = KIO_UNSUPPORTED;       /* not the key its algorithm announces */
        }
        else {
            size_t qlen = 0;
            e |= cbor_encode_uint(rec, 3);
            e |= cbor_encoder_create_map(rec, &m, 2);
            e |= encode_mpi(&m, 6, &kp.d, (kp.grp.nbits + 7) / 8, buf, sizeof(buf));
            if (mbedtls_ecp_point_write_binary(&kp.grp, &kp.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &qlen, buf,
                                               sizeof(buf)) != 0) {
                e |= CborErrorInternalError;
            }
            else {
                e |= cbor_encode_uint(&m, 7);
                e |= cbor_encode_byte_string(&m, buf, qlen);
            }
            e |= cbor_encoder_close_container(rec, &m);
        }
        mbedtls_ecp_keypair_free(&kp);
    }
#ifdef LF_HAVE_25519
    else if (kt == KT_ED25519 || kt == KT_X25519) {
        int curve = kt == KT_ED25519 ? LF_CURVE_ED25519 : LF_CURVE_X25519;
        uint8_t secret[32], pub[32];
        if (lf25519_load(ef, curve, secret, mode) != PICOKEY_OK || lf25519_public(curve, secret, pub) != 0) {
            sw = KIO_EXEC_ERROR;
        }
        else {
            e |= cbor_encode_uint(rec, 3);
            e |= cbor_encoder_create_map(rec, &m, 2);
            e |= cbor_encode_uint(&m, 6);
            e |= cbor_encode_byte_string(&m, secret, sizeof(secret));
            e |= cbor_encode_uint(&m, 7);
            e |= cbor_encode_byte_string(&m, pub, sizeof(pub));
            e |= cbor_encoder_close_container(rec, &m);
        }
        mbedtls_platform_zeroize(secret, sizeof(secret));
    }
#endif
    else {
        sw = KIO_UNSUPPORTED;
    }
    mbedtls_platform_zeroize(buf, sizeof(buf));
    if (sw == KIO_OK && e != CborNoError) {
        sw = KIO_EXEC_ERROR;
    }
    return sw;
}

/* ---- OpenPGP -------------------------------------------------------------
 * Key ref 1 (signature), 2 (decryption), 3 (authentication): the slots of
 * EF_PK_SIG..EF_PK_AUT, with the algorithm attributes (C1-C3), fingerprints
 * (C7-C9), generation times (CE-D0) and UIF (D6-D8) of the same order. The
 * keys are encrypted with the data key (DEK), which only a verified PW
 * opens: the export verifies PW3 itself. */

#define PGP_KEYS        3
/* Longest algorithm attributes PUT DATA takes (algo_attr_valid()). */
#define PGP_ATTR_MAX    16
/* Worst case of a list entry with attributes of n bytes: the map, key ref,
 * attributes, fingerprint, generation time. */
#define PGP_ENTRY_MAX(n) (1 + 3 + 4 + (n) + 22 + 6)

/* The algorithm attributes of key ref (the DO C1-C3 value; RSA 2048 when
 * never set, as GET DATA answers). */
static void pgp_attr(uint8_t ref, const uint8_t **attr, uint16_t *len) {
    file_t *ef = search_by_fid(EF_ALGO_PRIV1 + ref - 1, NULL, SPECIFY_EF);
    if (file_has_data(ef)) {
        *attr = file_get_data(ef);
        *len = file_get_size(ef);
    }
    else {
        *attr = algorithm_attr_rsa2k + 1;
        *len = algorithm_attr_rsa2k[0];
    }
}

/* The key type the attributes give the slot, as the card's own commands
 * read them (cmd_pso.c). */
static int pgp_key_type(const uint8_t *attr, uint16_t len, mbedtls_ecp_group_id *gid) {
    *gid = MBEDTLS_ECP_DP_NONE;
    if (len < 1) {
        return KT_NONE;
    }
    if (attr[0] == ALGO_RSA) {
        return KT_RSA;
    }
#ifdef OPGP_LF_25519
    int curve = lf25519_attr_curve(attr, len);
    if (curve == LF_CURVE_ED25519) {
        return KT_ED25519;
    }
    if (curve == LF_CURVE_X25519) {
        return KT_X25519;
    }
#endif
    if (len >= 2 && (attr[0] == ALGO_ECDSA || attr[0] == ALGO_ECDH || attr[0] == ALGO_EDDSA)) {
        *gid = get_ec_group_id_from_attr(attr + 1, len - 1);
        if (group_weierstrass(*gid)) {
            return KT_EC;
        }
    }
    return KT_NONE;
}

/* The private key of key ref (1-3), NULL if the slot has none. */
static file_t *pgp_key_file(uint8_t ref) {
    file_t *ef = search_by_fid(EF_PK_SIG + ref - 1, NULL, SPECIFY_EF);
    return file_has_data(ef) ? ef : NULL;
}

/* key: the fingerprint of key ref (C7-C9, 20 bytes; zeros if none was set,
 * as GET DATA C5 answers). */
static CborError encode_fp(CborEncoder *map, uint8_t key, uint8_t ref) {
    static const uint8_t none[20] = { 0 };
    file_t *ef = search_by_fid(EF_FP_SIG + ref - 1, NULL, SPECIFY_EF);
    const uint8_t *fp = file_get_size(ef) == sizeof(none) ? file_get_data(ef) : none;
    CborError e = cbor_encode_uint(map, key);
    e |= cbor_encode_byte_string(map, fp, sizeof(none));
    return e;
}

/* key: its generation time (CE-D0, seconds, big endian; 0 if none). */
static CborError encode_ts(CborEncoder *map, uint8_t key, uint8_t ref) {
    file_t *ef = search_by_fid(EF_TS_SIG + ref - 1, NULL, SPECIFY_EF);
    uint32_t t = 0;
    if (file_get_size(ef) == 4) {
        const uint8_t *p = file_get_data(ef);
        t = ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) | p[3];
    }
    CborError e = cbor_encode_uint(map, key);
    e |= cbor_encode_uint(map, t);
    return e;
}

static uint16_t pgp_list(uint32_t *cursor, bool pin_verified, CborEncoder *arr) {
    (void) pin_verified;        /* GET DATA: given to any host */
    CborError e = CborNoError;
    size_t used = 0;
    uint32_t i = *cursor;
    for (; i < PGP_KEYS; i++) {
        uint8_t ref = (uint8_t) (i + 1);
        const uint8_t *attr = NULL;
        uint16_t attr_len = 0;
        CborEncoder m;
        if (!pgp_key_file(ref)) {
            continue;
        }
        pgp_attr(ref, &attr, &attr_len);
        if (used && used + PGP_ENTRY_MAX(attr_len) > LF_KEYIO_PAGE_BUDGET) {
            break;
        }
        used += PGP_ENTRY_MAX(attr_len);
        e |= cbor_encoder_create_map(arr, &m, 4);
        e |= cbor_encode_uint(&m, 1);
        e |= cbor_encode_byte_string(&m, &ref, 1);
        e |= cbor_encode_uint(&m, 2);
        e |= cbor_encode_byte_string(&m, attr, attr_len);
        e |= encode_fp(&m, 3, ref);
        e |= encode_ts(&m, 4, ref);
        e |= cbor_encoder_close_container(arr, &m);
    }
    *cursor = i < PGP_KEYS ? i : LF_KEYIO_END;
    return e == CborNoError ? KIO_OK : KIO_EXEC_ERROR;
}

/* secret: the Admin PIN (PW3). It is verified here, with the retry counter
 * of PW3 as VERIFY 83 counts it, and the data key opened with it alone: a
 * PW1 verified in an OpenPGP session never serves an export. Whatever
 * happens, the OpenPGP session ends with no PW verified and no data key in
 * memory. */
static uint16_t pgp_export(const uint8_t *id, size_t id_len, const uint8_t *secret, size_t secret_len,
                           lf_keyio_confirm_t confirm, CborEncoder *enc) {
    uint8_t attr[PGP_ATTR_MAX];
    const uint8_t *a = NULL;
    uint16_t attr_len = 0;
    mbedtls_ecp_group_id gid = MBEDTLS_ECP_DP_NONE;
    if (!LF_ALLOW_SECRET_EXPORT) {
        return KIO_NOT_ALLOWED;     /* HARDENED: never, whoever asks */
    }
    if (id_len != 1 || id[0] < 1 || id[0] > PGP_KEYS) {
        return KIO_NO_KEY;
    }
    uint8_t ref = id[0];
    file_t *ef = pgp_key_file(ref);
    if (!ef) {
        return KIO_NO_KEY;
    }
    /* a copy: the PIN check below writes to the flash */
    pgp_attr(ref, &a, &attr_len);
    if (attr_len > sizeof(attr)) {
        return KIO_UNSUPPORTED;
    }
    memcpy(attr, a, attr_len);
    int kt = pgp_key_type(attr, attr_len, &gid);
    if (kt == KT_NONE) {
        return KIO_UNSUPPORTED;
    }
    if (!secret || secret_len == 0) {
        return KIO_SECRET_NEEDED;
    }
    openpgp_logout();
    uint16_t sw = (uint16_t) openpgp_verify_pw3(secret, secret_len);
    if (sw != KIO_OK) {
        openpgp_logout();
        /* no PW3 on the card: nothing that "no such key" would describe */
        return sw == KIO_NO_KEY ? KIO_NO_TOUCH : sw;
    }
    if (!confirm()) {
        openpgp_logout();
        return KIO_NO_TOUCH;
    }
    uint8_t uif[2];
    file_t *ef_uif = search_by_fid(EF_UIF_SIG + ref - 1, NULL, SPECIFY_EF);
    bool has_uif = file_get_size(ef_uif) == sizeof(uif);
    if (has_uif) {
        memcpy(uif, file_get_data(ef_uif), sizeof(uif));
    }
    CborEncoder rec;
    CborError e = cbor_encoder_create_map(enc, &rec, has_uif ? 6 : 5);
    e |= cbor_encode_uint(&rec, 1);
    e |= cbor_encode_uint(&rec, ref);
    e |= cbor_encode_uint(&rec, 2);
    e |= cbor_encode_byte_string(&rec, attr, attr_len);
    sw = e == CborNoError ? encode_private(&rec, ef, KEY_MODE_DEK, kt, gid) : KIO_EXEC_ERROR;
    openpgp_logout();
    if (sw == KIO_OK) {
        e |= encode_fp(&rec, 4, ref);
        e |= encode_ts(&rec, 5, ref);
        if (has_uif) {
            e |= cbor_encode_uint(&rec, 6);
            e |= cbor_encode_byte_string(&rec, uif, sizeof(uif));
        }
        e |= cbor_encoder_close_container(enc, &rec);
        if (e != CborNoError) {
            sw = KIO_EXEC_ERROR;
        }
    }
    return sw;
}

/* ---- PIV -----------------------------------------------------------------
 * The keys of slots 9A, 9C, 9D, 9E and 82-95, sealed in the PIV namespace of
 * the secure key store (KEY_MODE_PIV): no PIV PIN or management key opens
 * them. The management key (9B) is a secret of the card and the attestation
 * key (F9) its identity: neither is ever listed or exported. */

static const uint8_t piv_slots[] = {
    0x9A, 0x9C, 0x9D, 0x9E,
    0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B,
    0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
};
#define PIV_SLOTS       (sizeof(piv_slots) / sizeof(piv_slots[0]))
/* Worst case of a list entry: the map, slot, algorithm and the policies. */
#define PIV_ENTRY_MAX   16

static int piv_key_type(uint8_t algo, mbedtls_ecp_group_id *gid) {
    *gid = MBEDTLS_ECP_DP_NONE;
    switch (algo) {
        case PIV_ALGO_RSA1024: case PIV_ALGO_RSA2048: case PIV_ALGO_RSA3072: case PIV_ALGO_RSA4096:
            return KT_RSA;
        case PIV_ALGO_ECCP256:
            *gid = MBEDTLS_ECP_DP_SECP256R1;
            return KT_EC;
        case PIV_ALGO_ECCP384:
            *gid = MBEDTLS_ECP_DP_SECP384R1;
            return KT_EC;
#ifdef LF_HAVE_25519
        case PIV_ALGO_ED25519:
            return KT_ED25519;
        case PIV_ALGO_X25519:
            return KT_X25519;
#endif
    }
    return KT_NONE;
}

static uint16_t piv_list(uint32_t *cursor, bool pin_verified, CborEncoder *arr) {
    (void) pin_verified;        /* GET METADATA: given to any host */
    CborError e = CborNoError;
    size_t used = 0;
    uint32_t i = *cursor;
    for (; i < PIV_SLOTS; i++) {
        uint8_t slot = piv_slots[i], algo = 0, pin = 0, touch = 0;
        CborEncoder m;
        if (!piv_slot_key(slot, &algo, &pin, &touch)) {
            continue;
        }
        if (used && used + PIV_ENTRY_MAX > LF_KEYIO_PAGE_BUDGET) {
            break;
        }
        used += PIV_ENTRY_MAX;
        e |= cbor_encoder_create_map(arr, &m, 4);
        e |= cbor_encode_uint(&m, 1);
        e |= cbor_encode_byte_string(&m, &slot, 1);
        e |= cbor_encode_uint(&m, 2);
        e |= cbor_encode_uint(&m, algo);
        e |= cbor_encode_uint(&m, 3);
        e |= cbor_encode_uint(&m, pin);
        e |= cbor_encode_uint(&m, 4);
        e |= cbor_encode_uint(&m, touch);
        e |= cbor_encoder_close_container(arr, &m);
    }
    *cursor = i < PIV_SLOTS ? i : LF_KEYIO_END;
    return e == CborNoError ? KIO_OK : KIO_EXEC_ERROR;
}

/* No application secret: the PIV keys are not behind the PIV PIN at rest,
 * and the export is guarded by the profile's FIDO PIN and the touch. */
static uint16_t piv_export(const uint8_t *id, size_t id_len, const uint8_t *secret, size_t secret_len,
                           lf_keyio_confirm_t confirm, CborEncoder *enc) {
    uint8_t algo = 0, pin = 0, touch = 0;
    mbedtls_ecp_group_id gid = MBEDTLS_ECP_DP_NONE;
    (void) secret;
    (void) secret_len;
    if (!LF_ALLOW_SECRET_EXPORT) {
        return KIO_NOT_ALLOWED;
    }
    file_t *ef = id_len == 1 ? piv_slot_key(id[0], &algo, &pin, &touch) : NULL;
    if (!ef) {
        return KIO_NO_KEY;
    }
    int kt = piv_key_type(algo, &gid);
    if (kt == KT_NONE) {
        return KIO_UNSUPPORTED;
    }
    if (!confirm()) {
        return KIO_NO_TOUCH;
    }
    CborEncoder rec;
    CborError e = cbor_encoder_create_map(enc, &rec, 5);
    e |= cbor_encode_uint(&rec, 1);
    e |= cbor_encode_uint(&rec, id[0]);
    e |= cbor_encode_uint(&rec, 2);
    e |= cbor_encode_uint(&rec, algo);
    uint16_t sw = e == CborNoError ? encode_private(&rec, ef, KEY_MODE_PIV, kt, gid) : KIO_EXEC_ERROR;
    if (sw == KIO_OK) {
        e |= cbor_encode_uint(&rec, 4);
        e |= cbor_encode_uint(&rec, pin);
        e |= cbor_encode_uint(&rec, 5);
        e |= cbor_encode_uint(&rec, touch);
        e |= cbor_encoder_close_container(enc, &rec);
        if (e != CborNoError) {
            sw = KIO_EXEC_ERROR;
        }
    }
    return sw;
}

/* No list_protected: algorithm attributes, fingerprints and generation times
 * are data objects GET DATA answers without a PIN (6E, C1..C3, C5, CD), and
 * so are the algorithm and policies of a PIV slot (GET METADATA). */
static const lf_keyio_ops_t pgp_ops = {
    .list = pgp_list,
    .export_key = pgp_export,
    .import_key = NULL,
};

static const lf_keyio_ops_t piv_ops = {
    .list = piv_list,
    .export_key = piv_export,
    .import_key = NULL,
};

void lf_keyio_openpgp_piv_register(void) {
    lf_keyio_register(LF_APP_OPENPGP, &pgp_ops);
    lf_keyio_register(LF_APP_PIV, &piv_ops);
}
