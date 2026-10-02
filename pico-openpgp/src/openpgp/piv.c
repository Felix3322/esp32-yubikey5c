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

#ifdef ESP_PLATFORM
#include "esp_compat.h"
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#else
#include "common.h"
#endif
#include "files.h"
#include "apdu.h"
#include "pico_keys.h"
#include "random.h"
#include "eac.h"
#include "crypto_utils.h"
#include "version.h"
#include "asn1.h"
#include "mbedtls/aes.h"
#include "mbedtls/des.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "openpgp.h"
#include "usb.h"
#include "sks.h"
#include "security.h"
#include "lf_policy.h"
#include "low_flash.h"

#define PINPOLICY_DEFAULT 0
#define PINPOLICY_NEVER 1
#define PINPOLICY_ONCE 2
#define PINPOLICY_ALWAYS 3

#define TOUCHPOLICY_DEFAULT 0
#define TOUCHPOLICY_NEVER 1
#define TOUCHPOLICY_ALWAYS 2
#define TOUCHPOLICY_CACHED 3
#define TOUCHPOLICY_AUTO 0xFF

#define ORIGIN_GENERATED 0x01
#define ORIGIN_IMPORTED 0x02

#define IS_RETIRED(x) ((x) >= EF_PIV_KEY_RETIRED1 && (x) <= EF_PIV_KEY_RETIRED20)
#define IS_ACTIVE(x) ((x) >= EF_PIV_KEY_AUTHENTICATION && (x) <= EF_PIV_KEY_CARDAUTH)
#define IS_KEY(x) ((IS_ACTIVE((x))) || (IS_RETIRED((x))))

uint8_t piv_aid[] = {
    5,
    0xA0, 0x00, 0x00, 0x03, 0x8,
};
uint8_t yk_aid[] = {
    8,
    0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x1, 0x1
};

bool has_pwpiv = false;
bool has_mgm = false;
bool has_challenge = false;
uint8_t challenge[16];
/* A PIN-always key needs the PIN verified by the command right before:
 * a successful VERIFY arms pin_always_armed for the next command, which
 * sees it as pin_always_ok; every command disarms it, and a key operation
 * uses it up. */
static bool pin_always_armed = false;
static bool pin_always_ok = false;
/* Time of the last touch collected for a key (touch policy CACHED). */
static uint32_t piv_touch_ms = 0;
#define PIV_TOUCH_CACHE_MS 15000

/* Metadata record of a key (EF_META): algorithm, PIN policy, touch policy,
 * origin, then PIV_META_V1. Records of earlier firmware have no version
 * byte: their touch policy was stored but never enforced. */
#define PIV_META_V1 0x01
typedef struct {
    uint8_t algo, pin, touch, origin;
    bool v1;
} piv_meta_t;

int piv_process_apdu();

static void piv_logout_pin(void) {
    has_pwpiv = false;
    pin_always_armed = pin_always_ok = false;
}

/* Default PIN policy of a slot, as on YubiKey: always for 9C, never for
 * 9E, once for the others. */
static uint8_t piv_default_pinpol(uint16_t key_ref) {
    if (key_ref == EF_PIV_KEY_SIGNATURE) {
        return PINPOLICY_ALWAYS;
    }
    if (key_ref == EF_PIV_KEY_CARDAUTH) {
        return PINPOLICY_NEVER;
    }
    return PINPOLICY_ONCE;
}

/* The metadata of a key as the card enforces it. Records of earlier
 * firmware: touch NEVER (what that firmware did, whatever it stored), and
 * a stored DEFAULT PIN policy resolved as that firmware resolved it. */
static bool piv_meta_get(uint16_t key_ref, piv_meta_t *m) {
    uint8_t *p = NULL;
    uint16_t n = meta_find(key_ref, &p);
    if (n < 3 || !p) {
        return false;
    }
    m->algo = p[0];
    m->pin = p[1];
    m->touch = p[2];
    m->origin = n >= 4 ? p[3] : 0;
    m->v1 = n >= 5 && p[4] == PIV_META_V1;
    if (m->pin == PINPOLICY_DEFAULT) {
        m->pin = m->v1 ? piv_default_pinpol(key_ref) :
                 (key_ref == EF_PIV_KEY_SIGNATURE ? PINPOLICY_ALWAYS : PINPOLICY_ONCE);
    }
    if (!m->v1 || m->touch == TOUCHPOLICY_DEFAULT) {
        m->touch = TOUCHPOLICY_NEVER;
    }
    return true;
}

static int piv_meta_put(uint16_t key_ref, uint8_t algo, uint8_t pin, uint8_t touch, uint8_t origin) {
    uint8_t m[5] = { algo, pin, touch, origin, PIV_META_V1 };
    return meta_add(key_ref, m, sizeof(m));
}

/* Collects presence if the touch policy of a key asks for it: a press, or
 * automatic presence if the user switched it on for PIV in this profile
 * ("my device is safe"). Any value but NEVER, DEFAULT (NEVER, as on
 * YubiKey) and CACHED within its 15 s counts as ALWAYS. */
static bool piv_touch(uint8_t policy) {
    if (policy == TOUCHPOLICY_NEVER || policy == TOUCHPOLICY_DEFAULT) {
        return true;
    }
    if (policy == TOUCHPOLICY_CACHED && piv_touch_ms != 0 &&
        board_millis() - piv_touch_ms < PIV_TOUCH_CACHE_MS) {
        return true;
    }
    if (lf_wait_presence(LF_APP_PIV) == true) {        /* true: no presence */
        return false;
    }
    uint32_t now = board_millis();
    piv_touch_ms = now ? now : 1;
    return true;
}

/* The touch policy of the management key (9B, NEVER or ALWAYS): it guards
 * what the card administrator does (replacing, moving and deleting keys,
 * security settings), so only a physical press satisfies it. Automatic
 * presence does not, nor does the cache a key operation armed, and this
 * press does not arm it either. */
static bool piv_touch_admin(uint8_t policy) {
    if (policy == TOUCHPOLICY_NEVER || policy == TOUCHPOLICY_DEFAULT) {
        return true;
    }
    return wait_button() == false;
}

static int get_serial() {
    uint32_t serial = (pico_serial.id[0] & 0x7F) << 24 | pico_serial.id[1] << 16 | pico_serial.id[2] << 8 | pico_serial.id[3];
    return serial;
}

static int x509_create_cert(void *pk_ctx, uint8_t algo, uint8_t slot, bool attestation, uint8_t *buffer, size_t buffer_size) {
    mbedtls_x509write_cert ctx;
    mbedtls_x509write_crt_init(&ctx);
    mbedtls_x509write_crt_set_version(&ctx, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_validity(&ctx, "20240325000000", "20741231235959");
    uint8_t serial[20];
    random_gen(NULL, serial, sizeof(serial));
    mbedtls_x509write_crt_set_serial_raw(&ctx, serial, sizeof(serial));
    /* The pk contexts own copies of the keys (pointing them at the caller's
     * context leaked what mbedtls_pk_setup() allocated, per certificate). */
    mbedtls_pk_context skey, ikey;
    mbedtls_pk_init(&skey);
    mbedtls_pk_init(&ikey);
    int ret = -1;
    if (algo == PIV_ALGO_RSA1024 || algo == PIV_ALGO_RSA2048 || algo == PIV_ALGO_RSA3072 || algo == PIV_ALGO_RSA4096) {
        if (mbedtls_pk_setup(&skey, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0 ||
            mbedtls_rsa_copy(mbedtls_pk_rsa(skey), (const mbedtls_rsa_context *) pk_ctx) != 0) {
            goto end;
        }
    }
    else if (algo == PIV_ALGO_ECCP256 || algo == PIV_ALGO_ECCP384) {
        const mbedtls_ecp_keypair *src = (const mbedtls_ecp_keypair *) pk_ctx;
        if (mbedtls_pk_setup(&skey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0 ||
            mbedtls_ecp_group_load(&mbedtls_pk_ec(skey)->grp, src->grp.id) != 0 ||
            mbedtls_ecp_copy(&mbedtls_pk_ec(skey)->Q, &src->Q) != 0 ||
            mbedtls_mpi_copy(&mbedtls_pk_ec(skey)->d, &src->d) != 0) {
            goto end;
        }
    }
    else {
        goto end;
    }
    mbedtls_x509write_crt_set_subject_key(&ctx, &skey);
    char buf_sname[256];
    if (attestation) {
        sprintf(buf_sname, "C=ES,O=Pico Keys,CN=Pico OpenPGP PIV Attestation %X", slot);
        mbedtls_x509write_crt_set_subject_name(&ctx, buf_sname);
        mbedtls_x509write_crt_set_issuer_name(&ctx, "C=ES,O=Pico Keys,CN=Pico OpenPGP PIV Slot F9");
        file_t *ef_key = search_by_fid(EF_PIV_KEY_ATTESTATION, NULL, SPECIFY_EF);
        if (!ef_key || mbedtls_pk_setup(&ikey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0 ||
            load_private_key_ecdsa(mbedtls_pk_ec(ikey), ef_key, KEY_MODE_PIV) != PICOKEY_OK) {
            goto end;
        }
        mbedtls_x509write_crt_set_issuer_key(&ctx, &ikey);
        uint8_t ver[] = {PIV_VERSION_MAJOR, PIV_VERSION_MINOR, 0};
        mbedtls_x509write_crt_set_extension(&ctx, "\x2B\x06\x01\x04\x01\x82\xC4\x0A\x03\x03", 10, 0, ver, sizeof(ver));
        uint32_t dev_serial = get_serial();
        mbedtls_x509write_crt_set_extension(&ctx, "\x2B\x06\x01\x04\x01\x82\xC4\x0A\x03\x07", 10, 0, (const uint8_t *)&dev_serial, sizeof(dev_serial));
        piv_meta_t m;
        if (piv_meta_get(slot, &m)) {
            /* the policies the card enforces */
            uint8_t pol[2] = { m.pin, m.touch };
            mbedtls_x509write_crt_set_extension(&ctx, "\x2B\x06\x01\x04\x01\x82\xC4\x0A\x03\x08", 10, 0, pol, sizeof(pol));
        }
        uint8_t v = 1;
        mbedtls_x509write_crt_set_extension(&ctx, "\x2B\x06\x01\x04\x01\x82\xC4\x0A\x03\x09", 10, 0, &v, sizeof(v));
    }
    else {
        uint8_t wslot = slot;
        if (slot == EF_PIV_KEY_ATTESTATION) {
            wslot = 0xF9;
        }
        else if (slot == EF_PIV_KEY_RETIRED18) {
            wslot = 0x93;
        }
        sprintf(buf_sname, "C=ES,O=Pico Keys,CN=Pico OpenPGP PIV Slot %X", wslot);
        mbedtls_x509write_crt_set_issuer_name(&ctx, buf_sname);
        mbedtls_x509write_crt_set_subject_name(&ctx, buf_sname);
        mbedtls_x509write_crt_set_issuer_key(&ctx, &skey);
    }
    if (algo == PIV_ALGO_ECCP384) {
        mbedtls_x509write_crt_set_md_alg(&ctx, MBEDTLS_MD_SHA384);
    }
    else {
        mbedtls_x509write_crt_set_md_alg(&ctx, MBEDTLS_MD_SHA256);
    }
    if (slot == EF_PIV_KEY_ATTESTATION) {
        mbedtls_x509write_crt_set_basic_constraints(&ctx, 1, 1);
    }
    else {
        mbedtls_x509write_crt_set_basic_constraints(&ctx, 0, 0);
    }
    mbedtls_x509write_crt_set_subject_key_identifier(&ctx);
    mbedtls_x509write_crt_set_authority_key_identifier(&ctx);
    mbedtls_x509write_crt_set_key_usage(&ctx,
                                        MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
                                        MBEDTLS_X509_KU_KEY_CERT_SIGN);
    ret = mbedtls_x509write_crt_der(&ctx, buffer, buffer_size, random_gen, NULL);
end:
    mbedtls_pk_free(&skey);
    mbedtls_pk_free(&ikey);
    mbedtls_x509write_crt_free(&ctx);
    return ret;
}

#ifdef LF_HAVE_25519
/* Ed25519 (E0) and X25519 (E1) keys, as on YubiKey 5.7, kept by lf_25519. */
static int piv_curve(uint8_t algo) {
    return algo == PIV_ALGO_ED25519 ? LF_CURVE_ED25519 : (algo == PIV_ALGO_X25519 ? LF_CURVE_X25519 : 0);
}

/* How mbedTLS writes a distinguished name (library/x509_internal.h, which
 * is not installed): the names match those of the certificates above. */
extern int mbedtls_x509_write_names(unsigned char **p, unsigned char *start, mbedtls_asn1_named_data *first);

#define X509_CHK(f) do { if ((ret = (f)) < 0) goto end; len += (size_t) ret; } while (0)

static int x509_write_name(uint8_t **p, uint8_t *start, const char *name) {
    mbedtls_asn1_named_data *n = NULL;
    int ret = mbedtls_x509_string_to_names(&n, name);
    if (ret == 0) {
        ret = mbedtls_x509_write_names(p, start, n);
    }
    mbedtls_asn1_free_named_data_list(&n);
    return ret;
}

/* AlgorithmIdentifier without parameters (RFC 8410, RFC 5758). */
static int x509_write_alg(uint8_t **p, uint8_t *start, const char *oid, size_t oid_len) {
    int ret;
    size_t len = 0;
    X509_CHK(mbedtls_asn1_write_oid(p, start, oid, oid_len));
    X509_CHK(mbedtls_asn1_write_len(p, start, len));
    X509_CHK(mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    ret = (int) len;
end:
    return ret;
}

static int x509_write_ext(uint8_t **p, uint8_t *start, const char *oid, size_t oid_len, bool critical,
                          const uint8_t *val, size_t val_len) {
    int ret;
    size_t len = 0;
    X509_CHK(mbedtls_asn1_write_octet_string(p, start, val, val_len));
    if (critical) {
        X509_CHK(mbedtls_asn1_write_bool(p, start, 1));
    }
    X509_CHK(mbedtls_asn1_write_oid(p, start, oid, oid_len));
    X509_CHK(mbedtls_asn1_write_len(p, start, len));
    X509_CHK(mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    ret = (int) len;
end:
    return ret;
}

#define OID_ED25519         "\x2B\x65\x70"      /* 1.3.101.112 */
#define OID_X25519          "\x2B\x65\x6E"      /* 1.3.101.110 */
#define OID_YK(n)           "\x2B\x06\x01\x04\x01\x82\xC4\x0A\x03" n

/* Certificate of a Curve25519 key (public key info of RFC 8410), with the
 * contents x509_create_cert() gives the other keys: signed by the
 * attestation key F9 (ECDSA with SHA-256) with the attestation extensions,
 * or, for an Ed25519 key (seed) not attested, self-signed. mbedTLS has no
 * such keys, so the DER is written here. Like mbedTLS, it is written at the
 * end of buffer; returns its length or a negative error. */
static int x509_create_cert_25519(uint8_t algo, uint8_t slot, const uint8_t pub[32], const uint8_t *seed,
                                  bool attestation, uint8_t *buffer, size_t size) {
    bool ed = piv_curve(algo) == LF_CURVE_ED25519;
    uint8_t *start = buffer, *p = buffer + size, ski[20], aki[20], ext[24], sig[MBEDTLS_ECDSA_MAX_LEN];
    uint8_t serial[20], hash[32];
    char name[64];
    size_t len = 0, mark, sig_len = 0;
    int ret = -1;
    mbedtls_ecdsa_context ikey;
    mbedtls_ecdsa_init(&ikey);
    if (!piv_curve(algo) || (!attestation && (!ed || !seed))) {
        goto end;                       /* X25519 keys cannot sign */
    }
    if (mbedtls_sha1(pub, 32, ski) != 0) {
        goto end;
    }
    memcpy(aki, ski, sizeof(aki));
    if (attestation) {
        uint8_t pt[MBEDTLS_ECP_MAX_PT_LEN];
        size_t plen = 0;
        file_t *ef_key = search_by_fid(EF_PIV_KEY_ATTESTATION, NULL, SPECIFY_EF);
        if (!ef_key || load_private_key_ecdsa(&ikey, ef_key, KEY_MODE_PIV) != PICOKEY_OK ||
            mbedtls_ecp_point_write_binary(&ikey.grp, &ikey.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &plen, pt,
                                           sizeof(pt)) != 0 ||
            mbedtls_sha1(pt, plen, aki) != 0) {
            ret = -1;
            goto end;
        }
    }

    /* [3] { extensions }, the last one first */
    mark = len;
    if (!ed) {
        X509_CHK(x509_write_ext(&p, start, MBEDTLS_OID_KEY_USAGE, MBEDTLS_OID_SIZE(MBEDTLS_OID_KEY_USAGE), true,
                                (const uint8_t *) "\x03\x02\x03\x08", 4));      /* keyAgreement */
    }
    else if (attestation) {
        X509_CHK(x509_write_ext(&p, start, MBEDTLS_OID_KEY_USAGE, MBEDTLS_OID_SIZE(MBEDTLS_OID_KEY_USAGE), true,
                                (const uint8_t *) "\x03\x02\x07\x80", 4));      /* digitalSignature */
    }
    else {
        X509_CHK(x509_write_ext(&p, start, MBEDTLS_OID_KEY_USAGE, MBEDTLS_OID_SIZE(MBEDTLS_OID_KEY_USAGE), true,
                                (const uint8_t *) "\x03\x02\x02\x84", 4));      /* + keyCertSign */
    }
    memcpy(ext, "\x30\x16\x80\x14", 4);
    memcpy(ext + 4, aki, 20);
    X509_CHK(x509_write_ext(&p, start, MBEDTLS_OID_AUTHORITY_KEY_IDENTIFIER,
                            MBEDTLS_OID_SIZE(MBEDTLS_OID_AUTHORITY_KEY_IDENTIFIER), false, ext, 24));
    memcpy(ext, "\x04\x14", 2);
    memcpy(ext + 2, ski, 20);
    X509_CHK(x509_write_ext(&p, start, MBEDTLS_OID_SUBJECT_KEY_IDENTIFIER,
                            MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_KEY_IDENTIFIER), false, ext, 22));
    X509_CHK(x509_write_ext(&p, start, MBEDTLS_OID_BASIC_CONSTRAINTS, MBEDTLS_OID_SIZE(MBEDTLS_OID_BASIC_CONSTRAINTS),
                            false, (const uint8_t *) "\x30\x00", 2));
    if (attestation) {
        /* as in x509_create_cert(): form factor, policies, serial, version */
        uint8_t v = 1, ver[] = { PIV_VERSION_MAJOR, PIV_VERSION_MINOR, 0 };
        uint32_t dev_serial = get_serial();
        piv_meta_t m;
        X509_CHK(x509_write_ext(&p, start, OID_YK("\x09"), 10, false, &v, 1));
        if (piv_meta_get(slot, &m)) {
            uint8_t pol[2] = { m.pin, m.touch };
            X509_CHK(x509_write_ext(&p, start, OID_YK("\x08"), 10, false, pol, sizeof(pol)));
        }
        X509_CHK(x509_write_ext(&p, start, OID_YK("\x07"), 10, false, (const uint8_t *) &dev_serial,
                                sizeof(dev_serial)));
        X509_CHK(x509_write_ext(&p, start, OID_YK("\x03"), 10, false, ver, sizeof(ver)));
    }
    X509_CHK(mbedtls_asn1_write_len(&p, start, len - mark));
    X509_CHK(mbedtls_asn1_write_tag(&p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    X509_CHK(mbedtls_asn1_write_len(&p, start, len - mark));
    X509_CHK(mbedtls_asn1_write_tag(&p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 3));
    /* subjectPublicKeyInfo */
    mark = len;
    X509_CHK(mbedtls_asn1_write_bitstring(&p, start, pub, 32 * 8));
    X509_CHK(x509_write_alg(&p, start, ed ? OID_ED25519 : OID_X25519, 3));
    X509_CHK(mbedtls_asn1_write_len(&p, start, len - mark));
    X509_CHK(mbedtls_asn1_write_tag(&p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    /* subject */
    snprintf(name, sizeof(name), attestation ? "C=ES,O=Pico Keys,CN=Pico OpenPGP PIV Attestation %X"
                                             : "C=ES,O=Pico Keys,CN=Pico OpenPGP PIV Slot %X", slot);
    X509_CHK(x509_write_name(&p, start, name));
    /* validity: 2024-03-25 (UTCTime) to 2074-12-31 (GeneralizedTime) */
    mark = len;
    X509_CHK(mbedtls_asn1_write_raw_buffer(&p, start, (const uint8_t *) "20741231235959Z", 15));
    X509_CHK(mbedtls_asn1_write_len(&p, start, 15));
    X509_CHK(mbedtls_asn1_write_tag(&p, start, MBEDTLS_ASN1_GENERALIZED_TIME));
    X509_CHK(mbedtls_asn1_write_raw_buffer(&p, start, (const uint8_t *) "240325000000Z", 13));
    X509_CHK(mbedtls_asn1_write_len(&p, start, 13));
    X509_CHK(mbedtls_asn1_write_tag(&p, start, MBEDTLS_ASN1_UTC_TIME));
    X509_CHK(mbedtls_asn1_write_len(&p, start, len - mark));
    X509_CHK(mbedtls_asn1_write_tag(&p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    /* issuer */
    X509_CHK(x509_write_name(&p, start, attestation ? "C=ES,O=Pico Keys,CN=Pico OpenPGP PIV Slot F9" : name));
    /* signature algorithm */
    if (attestation) {
        X509_CHK(x509_write_alg(&p, start, MBEDTLS_OID_ECDSA_SHA256, MBEDTLS_OID_SIZE(MBEDTLS_OID_ECDSA_SHA256)));
    }
    else {
        X509_CHK(x509_write_alg(&p, start, OID_ED25519, 3));
    }
    /* serial number: 20 random bytes, positive */
    random_gen(NULL, serial, sizeof(serial));
    serial[0] = (serial[0] & 0x7F) | 0x40;
    X509_CHK(mbedtls_asn1_write_raw_buffer(&p, start, serial, sizeof(serial)));
    X509_CHK(mbedtls_asn1_write_len(&p, start, sizeof(serial)));
    X509_CHK(mbedtls_asn1_write_tag(&p, start, MBEDTLS_ASN1_INTEGER));
    /* version: v3 */
    mark = len;
    X509_CHK(mbedtls_asn1_write_int(&p, start, 2));
    X509_CHK(mbedtls_asn1_write_len(&p, start, len - mark));
    X509_CHK(mbedtls_asn1_write_tag(&p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0));
    X509_CHK(mbedtls_asn1_write_len(&p, start, len));
    X509_CHK(mbedtls_asn1_write_tag(&p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    /* the signature of the TBSCertificate [p, p + len) */
    if (attestation) {
        ret = mbedtls_sha256(p, len, hash, 0);
        if (ret == 0) {
            ret = mbedtls_ecdsa_write_signature(&ikey, MBEDTLS_MD_SHA256, hash, sizeof(hash), sig, sizeof(sig),
                                                &sig_len, random_gen, NULL);
        }
    }
    else {
        ret = lf_ed25519_sign(sig, p, len, seed, NULL);
        sig_len = LF_ED25519_SIG_LEN;
    }
    if (ret != 0) {
        ret = -1;
        goto end;
    }
    /* [TBS][algorithm][signature] in a SEQUENCE, as mbedTLS lays it out: the
     * TBS to the front, the signature parts at the end, the TBS before them */
    size_t tbs_len = len;
    memmove(buffer, p, tbs_len);
    start = buffer + tbs_len;
    p = buffer + size;
    len = 0;
    X509_CHK(mbedtls_asn1_write_bitstring(&p, start, sig, sig_len * 8));
    if (attestation) {
        X509_CHK(x509_write_alg(&p, start, MBEDTLS_OID_ECDSA_SHA256, MBEDTLS_OID_SIZE(MBEDTLS_OID_ECDSA_SHA256)));
    }
    else {
        X509_CHK(x509_write_alg(&p, start, OID_ED25519, 3));
    }
    p -= tbs_len;
    memmove(p, buffer, tbs_len);
    len += tbs_len;
    start = buffer;
    X509_CHK(mbedtls_asn1_write_len(&p, start, len));
    X509_CHK(mbedtls_asn1_write_tag(&p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    ret = (int) len;
end:
    mbedtls_ecdsa_free(&ikey);
    mbedtls_platform_zeroize(hash, sizeof(hash));
    return ret;
}
#endif

static const uint8_t piv_default_mgm[24] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};
/* Default PIN (padded to 8 bytes) and PUK. */
static const uint8_t piv_default_pin[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF };
static const uint8_t piv_default_puk[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };

static uint16_t piv_key_fid(uint8_t key_ref);

/* Key records and the PIN and PUK verifiers written in plaintext by earlier
 * firmware are sealed when the application is selected, once the running
 * firmware is confirmed (until then they are used as they are: a rollback
 * must find them readable). Each record is one rewrite; a record that
 * fails stays as it was and is tried again at the next selection. */
static void piv_seal_legacy_keys(void) {
    static const uint8_t active[] = { 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0xF9 };
    if (!lf_migrate_ok() || !security_keystore_unlocked()) {
        return;
    }
    for (size_t i = 0; i < 20 + sizeof(active); i++) {
        uint8_t ref = i < 20 ? (uint8_t) (0x82 + i) : active[i - 20];
        file_t *ef = search_by_fid(piv_key_fid(ref), NULL, SPECIFY_EF);
        if (key_record_migrate(ef) != PICOKEY_OK) {
            printf("PIV key %02X could not be sealed\r\n", ref);
        }
    }
    pw_rec_migrate(search_by_fid(EF_PIV_PIN, NULL, SPECIFY_EF));
    pw_rec_migrate(search_by_fid(EF_PIV_PUK, NULL, SPECIFY_EF));
}

static void scan_files_piv() {
    scan_flash();
    file_t *ef = NULL;
    /* A locked key store (root key held until it is bound): nothing is
     * provisioned or migrated; the application refuses what needs its PINs
     * or keys (piv_process_apdu()). */
    if (openpgp_store_locked()) {
        return;
    }
    if ((ef = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_ANY))) {
        if (file_get_size(ef) == 0) {
            printf("PW status is empty. Initializing to default\r\n");
            /* no OpenPGP Reset Code until one is set */
            const uint8_t def[] = { 0x1, 127, 127, 127, 3, 0, 3, 3, 3 };
            file_put_data(ef, def, sizeof(def));
        }
        else if (file_get_size(ef) == 7) {
            printf("PW status is older. Initializing to default\r\n");
            uint8_t def[9] = { 0 };
            memcpy(def, file_get_data(ef), 7);
            def[7] = def[8] = 3; // PIV retries
            file_put_data(ef, def, sizeof(def));
        }
    }
    if ((ef = search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_ANY))) {
        if (file_get_size(ef) == 0) {
            printf("PW retries is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x1, 3, 3, 3, 3, 3 };
            file_put_data(ef, def, sizeof(def));
        }
        else if (file_get_size(ef) == 4) {
            printf("PW retries is older. Initializing to default\r\n");
            uint8_t def[6] = { 0 };
            memcpy(def, file_get_data(ef), 4);
            def[4] = def[5] = 3; // PIV retries
            file_put_data(ef, def, sizeof(def));
        }
    }
    bool reset_dek = false;
    /* The fourth slot of EF_DEK holds no key of use (PIV keys are sealed by
     * the secure key store): it marks the PIV application as provisioned,
     * and PIV RESET drops it to provision it again. The OpenPGP part must
     * be complete first (PIV selected before OpenPGP ever was): slots that
     * PW1 and PW3 did not open to the same key would make OpenPGP keys
     * depend on which PW was verified. */
    if (dek_file_len() == 0) {
        scan_files_openpgp();
    }
    if (dek_file_len() == IV_SIZE + 32 * 3) {
        printf("DEK is empty or older\r\n");
        uint8_t def[DEK_FILE_MAX];
        uint16_t dlen = 0;
        if (dek_file_read(def, &dlen) == PICOKEY_OK && dlen == IV_SIZE + 32 * 3) {
            random_gen(NULL, def + IV_SIZE + 32 * 3, 32);
            reset_dek = dek_file_write(def, IV_SIZE + 32 * 4) == PICOKEY_OK;
        }
        mbedtls_platform_zeroize(def, sizeof(def));
    }
    /* The default management key (as on YubiKey: 3DES, no touch), also
     * whenever it went missing (a PIV RESET cut short): without it no
     * administration is possible. 3DES keeps clients that know no other
     * (yubico-piv-tool 2.2) working; GENERAL AUTHENTICATE only accepts a
     * key with its own algorithm. */
    if ((ef = search_by_fid(EF_PIV_KEY_CARDMGM, NULL, SPECIFY_ANY))) {
        uint8_t key[32];
        int klen = 0;
        piv_meta_t m;
        if (reset_dek || !file_has_data(ef)) {
            memcpy(key, piv_default_mgm, sizeof(piv_default_mgm));
            key_record_write(ef, KEY_MODE_PIV, key, sizeof(piv_default_mgm));
            piv_meta_put(EF_PIV_KEY_CARDMGM, PIV_ALGO_3DES, PINPOLICY_NEVER, TOUCHPOLICY_NEVER, 0);
        }
        /* Earlier firmware tagged the default key AES-192 (and took it as
         * 3DES too); switched once the firmware is confirmed. */
        else if (lf_migrate_ok() && piv_meta_get(EF_PIV_KEY_CARDMGM, &m) && !m.v1 && m.algo == PIV_ALGO_AES192 &&
                 key_record_read(ef, KEY_MODE_PIV, key, sizeof(key), &klen) == PICOKEY_OK &&
                 klen == sizeof(piv_default_mgm) &&
                 mbedtls_ct_memcmp(key, piv_default_mgm, sizeof(piv_default_mgm)) == 0) {
            piv_meta_put(EF_PIV_KEY_CARDMGM, PIV_ALGO_3DES, PINPOLICY_NEVER, TOUCHPOLICY_NEVER, 0);
        }
        mbedtls_platform_zeroize(key, sizeof(key));
    }
    if ((ef = search_by_fid(EF_PIV_PIN, NULL, SPECIFY_ANY))) {
        if (!ef->data || reset_dek) {
            printf("PIV PIN is empty. Initializing with default password\r\n");
            pw_rec_set(ef, piv_default_pin, sizeof(piv_default_pin), sizeof(piv_default_pin));
        }
    }
    if ((ef = search_by_fid(EF_PIV_PUK, NULL, SPECIFY_ANY))) {
        if (!ef->data || reset_dek) {
            printf("PIV PUK is empty. Initializing with default password\r\n");
            pw_rec_set(ef, piv_default_puk, sizeof(piv_default_puk), sizeof(piv_default_puk));
        }
    }
    if ((ef = search_by_fid(EF_PIV_KEY_ATTESTATION, NULL, SPECIFY_ANY))) {
        bool make = !file_has_data(ef);
        /* A sealed record that no longer opens (a PIV RESET cut between
         * its new epoch and the re-seal) is replaced; a locked key store
         * is not a reason to. */
        if (!make && security_keystore_unlocked() &&
            sks_is_sealed(SKS_NS_PIV, file_get_data(ef), file_get_size(ef))) {
            uint8_t k[67];
            size_t n = 0;
            bool legacy = false;
            make = sks_file_get(SKS_NS_PIV, ef, k, sizeof(k), &n, &legacy) == PICOKEY_WRONG_DATA;
            mbedtls_platform_zeroize(k, sizeof(k));
        }
        if (make) {
            printf("ATTESTATION key is empty. Initializing with random one\r\n");
            mbedtls_ecdsa_context ecdsa;
            mbedtls_ecdsa_init(&ecdsa);
            int r = mbedtls_ecdsa_genkey(&ecdsa, MBEDTLS_ECP_DP_SECP384R1, random_gen, NULL);
            if (r == 0) {
                r = store_keys(&ecdsa, ALGO_ECDSA, EF_PIV_KEY_ATTESTATION, KEY_MODE_PIV);
            }
            if (r == 0) {
                uint8_t cert[2048];
                r = x509_create_cert(&ecdsa, PIV_ALGO_ECCP384, EF_PIV_KEY_ATTESTATION, false, cert, sizeof(cert));
                if (r > 0) {
                    file_put_data(search_by_fid(EF_PIV_ATTESTATION, NULL, SPECIFY_ANY), cert + sizeof(cert) - r, r);
                }
            }
            mbedtls_ecdsa_free(&ecdsa);
        }
    }
    piv_seal_legacy_keys();
    dek_file_migrate();
    low_flash_available();
}

/* Management key authentication: witness of the mutual (80 then 80 + 81)
 * flow, and the challenge of the external (81 then 82) flow. */
static uint8_t mgm_witness[16];
static bool has_witness = false;

/* All authentication and session state of the application. */
static void piv_logout(void) {
    piv_logout_pin();
    isUserAuthenticated = false;
    has_mgm = false;
    has_challenge = has_witness = false;
    mbedtls_platform_zeroize(challenge, sizeof(challenge));
    mbedtls_platform_zeroize(mgm_witness, sizeof(mgm_witness));
    piv_touch_ms = 0;
}

/* Authentication state (PIN, management key, pending challenge) belongs to
 * one selection of the applet: it never survives a switch to another
 * application, another client, or a reset. */
void init_piv() {
    scan_files_piv();
    piv_logout();
}

int piv_unload() {
    piv_logout();
    return PICOKEY_OK;
}

/* Application property template (SP 800-73-4 part 2, 3.1.1): the PIX with
 * the version, the coexistent tag allocation authority, the label and the
 * algorithms of this card. */
void select_piv_aid() {
    static const uint8_t algos[] = {
        PIV_ALGO_3DES, PIV_ALGO_RSA1024, PIV_ALGO_RSA2048, PIV_ALGO_AES128,
        PIV_ALGO_AES192, PIV_ALGO_AES256, PIV_ALGO_ECCP256, PIV_ALGO_ECCP384,
#ifdef LF_HAVE_25519
        PIV_ALGO_ED25519, PIV_ALGO_X25519,
#endif
    };
    const char *app_label = "LibreFido PIV";
    uint8_t *p = res_APDU;
    *p++ = 0x61;
    uint8_t *len61 = p++;
    memcpy(p, "\x4F\x06\x00\x00\x10\x00\x01\x00", 8);
    p += 8;
    memcpy(p, "\x79\x07\x4F\x05\xA0\x00\x00\x03\x08", 9);
    p += 9;
    *p++ = 0x50;
    *p++ = (uint8_t) strlen(app_label);
    memcpy(p, app_label, strlen(app_label));
    p += strlen(app_label);
    *p++ = 0xAC;
    *p++ = sizeof(algos) * 3 + 2;
    for (size_t i = 0; i < sizeof(algos); i++) {
        *p++ = 0x80;
        *p++ = 1;
        *p++ = algos[i];
    }
    *p++ = 0x06;
    *p++ = 0x00;
    *len61 = (uint8_t) (p - len61 - 1);
    res_APDU_size = (uint16_t) (p - res_APDU);
}

int piv_select_aid(app_t *a, uint8_t force) {
    (void) force;
    a->process_apdu = piv_process_apdu;
    a->unload = piv_unload;
    init_piv();
    select_piv_aid();
    if (apdu.ne == 0) {             /* no Le: the template directly */
        apdu.ne = res_APDU_size;
    }
    return PICOKEY_OK;
}

INITIALIZER( piv_ctor ) {
    register_app(piv_select_aid, piv_aid);
    register_app(piv_select_aid, yk_aid);
}

static int cmd_version() {
    res_APDU[res_APDU_size++] = PIV_VERSION_MAJOR;
    res_APDU[res_APDU_size++] = PIV_VERSION_MINOR;
    res_APDU[res_APDU_size++] = 0x0;
    return SW_OK();
}

static int cmd_select() {
    if (P2(apdu) != 0x1) {
        return SW_WRONG_P1P2();
    }
    if (apdu.nc >= piv_aid[0] && memcmp(apdu.data, piv_aid + 1, piv_aid[0]) == 0) {
        select_piv_aid();
    }
    return SW_OK();
}

int piv_parse_discovery(const file_t *ef) {
    memcpy(res_APDU, "\x7E\x12\x4F\x0B\xA0\x00\x00\x03\x08\x00\x00\x10\x00\x01\x00\x5F\x2F\x02\x40\x10", 20);
    res_APDU_size = 20;
    return res_APDU_size;
}

static int cmd_get_serial() {
    uint32_t serial = get_serial();
    res_APDU[res_APDU_size++] = serial >> 24;
    res_APDU[res_APDU_size++] = serial >> 16;
    res_APDU[res_APDU_size++] = serial >> 8;
    res_APDU[res_APDU_size++] = serial & 0xFF;
    return SW_OK();
}

extern int check_pin(const file_t *pin, const uint8_t *data, size_t len);
static int cmd_verify() {
    uint8_t key_ref = P2(apdu);
    if (P1(apdu) != 0x00 && P1(apdu) != 0xFF) {
        return SW_INCORRECT_P1P2();
    }
    if (key_ref != 0x80) {
        return SW_REFERENCE_NOT_FOUND();
    }
    /* SP 800-73-4: P1 FF (no data) resets the security status of the PIN */
    if (P1(apdu) == 0xFF) {
        if (apdu.nc != 0) {
            return SW_WRONG_LENGTH();
        }
        piv_logout_pin();
        return SW_OK();
    }
    file_t *pw, *pw_status;
    uint16_t fid = EF_PIV_PIN;
    if (!(pw = search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!(pw_status = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!file_has_data(pw)) { //not initialized
        return SW_REFERENCE_NOT_FOUND();
    }
    if (apdu.nc > 0) {
        uint16_t ret = check_pin(pw, apdu.data, apdu.nc);
        if (ret == 0x9000) {
            has_pwpiv = true;
            pin_always_armed = true;    /* for the next command */
        }
        else {
            piv_logout_pin();
        }
        return ret; //SW already set
    }
    /* a status query right after VERIFY keeps it for the command after */
    if (has_pwpiv && pin_always_ok) {
        pin_always_armed = true;
    }
    if (3 + (fid & 0xf) >= file_get_size(pw_status)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    uint8_t retries = *(file_get_data(pw_status) + 3 + (fid & 0xf));
    if (retries == 0) {
        return SW_PIN_BLOCKED();
    }
    if ((key_ref == 0x80 && has_pwpiv)) {
        return SW_OK();
    }
    return set_res_sw(0x63, 0xc0 | MIN(retries, 15));
}

static int cmd_get_data() {
    if (P1(apdu) != 0x3F || P2(apdu) != 0xFF) {
        return SW_INCORRECT_P1P2();
    }
    if (apdu.nc < 3 || apdu.data[0] != 0x5C || (apdu.data[1] & 0x80) || apdu.data[1] >= 4 ||
        apdu.data[1] == 0 || apdu.nc < 2u + apdu.data[1]) {
        return SW_WRONG_DATA();
    }
    uint32_t fid = apdu.data[2];
    for (uint8_t lt = 1; lt < apdu.data[1]; lt++) {
        fid <<= 8;
        fid |= apdu.data[2 + lt];
    }
    if ((fid & 0xFFFF00) != 0x5FC100 && (fid & 0xFFFF) != EF_PIV_BITGT && (fid & 0xFFFF) != EF_PIV_DISCOVERY && (fid & 0xFFFF) != EF_PIV_ATTESTATION) {
        return SW_FILE_NOT_FOUND();
    }
    /* SP 800-73-4 part 1, table 3: these containers need the PIN */
    uint16_t f16 = (uint16_t) (fid & 0xFFFF);
    if ((f16 == EF_PIV_FINGERPRINTS || f16 == EF_PIV_FACIAL || f16 == EF_PIV_PRINTED ||
         f16 == EF_PIV_IRIS || f16 == EF_PIV_PC_REF_DATA) && (fid & 0xFFFF00) == 0x5FC100 && !has_pwpiv) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    file_t *ef = NULL;
    if ((ef = search_by_fid((uint16_t)(fid & 0xFFFF), NULL, SPECIFY_EF))) {
        uint16_t data_len = 0;
        res_APDU_size = 2; // Minimum: TAG+LEN
        if ((ef->type & FILE_DATA_FUNC) == FILE_DATA_FUNC) {
            data_len = ((int (*)(const file_t *))(ef->data))((const file_t *) ef);
        }
        else {
            if (ef->data) {
                data_len = file_get_size(ef);
                const uint8_t *d = file_get_data(ef);
                bool cert_obj = (fid & 0xFFFF00) == 0x5FC100 ?
                                (f16 == EF_PIV_AUTHENTICATION || f16 == EF_PIV_SIGNATURE ||
                                 f16 == EF_PIV_KEY_MANAGEMENT || f16 == EF_PIV_CARD_AUTH ||
                                 (f16 >= EF_PIV_RETIRED1 && f16 <= EF_PIV_RETIRED20)) :
                                fid == 0x5FFF01;
                if (cert_obj && data_len > 0 && d[0] == 0x30 && data_len <= 2048) {
                    /* A certificate this firmware keeps as bare DER (those
                     * of generated keys, the attestation certificate F9):
                     * given as SP 800-73-4 certificate objects are, 70
                     * certificate and 71 CertInfo (not compressed), as
                     * clients (yubikit, yubico-piv-tool, OpenSC) read them. */
                    uint8_t *o = res_APDU + res_APDU_size;
                    uint16_t h = 1 + format_tlv_len(data_len, NULL);
                    memmove(o + h, d, data_len);
                    o[0] = 0x70;
                    format_tlv_len(data_len, o + 1);
                    data_len += h;
                    o[data_len++] = 0x71;
                    o[data_len++] = 0x01;
                    o[data_len++] = 0x00;
                }
                else {
                    memcpy(res_APDU + res_APDU_size, d, data_len);
                }
            }
        }
        if (data_len == 0) {
            return SW_FILE_NOT_FOUND();
        }
        if (data_len > 255) {
            memmove(res_APDU + res_APDU_size + 2, res_APDU + res_APDU_size, data_len);
        }
        else if (data_len > 127) {
            memmove(res_APDU + res_APDU_size + 1, res_APDU + res_APDU_size, data_len);
        }
        res_APDU[0] = 0x53;
        res_APDU_size = 1 + format_tlv_len(data_len, res_APDU + 1) + data_len;
    }
    else {
        return SW_FILE_NOT_FOUND();
    }
    return SW_OK();
}

/* File of a PIV key reference (SP 800-73-4 9A-9E and the retired keys
 * 82-95, the attestation key F9), 0 for anything else. The files share one
 * namespace with the OpenPGP DOs of the same card, so 93 (OpenPGP signature
 * counter) and F9 (KDF-DO) live elsewhere: every key access goes through
 * here, or a PIV command could read or overwrite OpenPGP data. */
static uint16_t piv_key_fid(uint8_t key_ref) {
    if (key_ref == 0x93) {
        return EF_PIV_KEY_RETIRED18;
    }
    if (key_ref == 0xF9) {
        return EF_PIV_KEY_ATTESTATION;
    }
    if ((key_ref >= 0x9A && key_ref <= 0x9E) || (key_ref >= 0x82 && key_ref <= 0x95)) {
        return key_ref;
    }
    return 0;
}

static file_t *piv_key_file(uint8_t key_ref) {
    uint16_t fid = piv_key_fid(key_ref);
    return fid ? search_by_fid(fid, NULL, SPECIFY_EF) : NULL;
}

/* A key is a record and its metadata: no command uses a record without
 * metadata (left by a MOVE KEY or a generation cut short). */
file_t *piv_slot_key(uint8_t slot, uint8_t *algo, uint8_t *pin_policy, uint8_t *touch_policy) {
    piv_meta_t m;
    if (slot == EF_PIV_KEY_CARDMGM || !IS_KEY(slot)) {
        return NULL;
    }
    file_t *ef = piv_key_file(slot);
    if (!file_has_data(ef) || !piv_meta_get(slot, &m)) {
        return NULL;
    }
    *algo = m.algo;
    *pin_policy = m.pin;
    *touch_policy = m.touch;
    return ef;
}

static int cmd_get_metadata() {
    if (P1(apdu) != 0x00) {
        return SW_INCORRECT_P1P2();
    }
    /* key_ref names the key (and its metadata record), fid its file */
    uint16_t key_ref = P2(apdu), fid = 0;
    if (key_ref == 0x80) {
        key_ref = fid = EF_PIV_PIN;
    }
    else if (key_ref == 0x81) {
        key_ref = fid = EF_PIV_PUK;
    }
    else if ((fid = piv_key_fid(P2(apdu))) == 0) {
        return SW_REFERENCE_NOT_FOUND();
    }
    file_t *ef_key = search_by_fid(fid, NULL, SPECIFY_EF);
    if (!file_has_data(ef_key)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (key_ref != EF_PIV_PIN && key_ref != EF_PIV_PUK) {
        /* the policies as the card enforces them */
        piv_meta_t m;
        if (!piv_meta_get(key_ref, &m)) {
            return SW_REFERENCE_NOT_FOUND();
        }
        res_APDU[res_APDU_size++] = 0x1;
        res_APDU[res_APDU_size++] = 1;
        res_APDU[res_APDU_size++] = m.algo;
        res_APDU[res_APDU_size++] = 0x2;
        res_APDU[res_APDU_size++] = 2;
        res_APDU[res_APDU_size++] = m.pin;
        res_APDU[res_APDU_size++] = m.touch;
        if (key_ref != EF_PIV_KEY_CARDMGM) {
            res_APDU[res_APDU_size++] = 0x3;
            res_APDU[res_APDU_size++] = 1;
            res_APDU[res_APDU_size++] = m.origin;
            bool has_pk = m.algo == PIV_ALGO_RSA1024 || m.algo == PIV_ALGO_RSA2048 || m.algo == PIV_ALGO_RSA3072 || m.algo == PIV_ALGO_RSA4096 || m.algo == PIV_ALGO_ECCP256 || m.algo == PIV_ALGO_ECCP384;
#ifdef LF_HAVE_25519
            has_pk = has_pk || piv_curve(m.algo) != 0;
#endif
            if (has_pk) {
                res_APDU[res_APDU_size++] = 0x4;
                res_APDU[res_APDU_size++] = 0; // Filled later
                uint8_t *pk = &res_APDU[res_APDU_size];
                if (m.algo == PIV_ALGO_RSA1024 || m.algo == PIV_ALGO_RSA2048 || m.algo == PIV_ALGO_RSA3072 || m.algo == PIV_ALGO_RSA4096) {
                    mbedtls_rsa_context ctx;
                    mbedtls_rsa_init(&ctx);
                    int r = load_private_key_rsa(&ctx, ef_key, KEY_MODE_PIV);
                    if (r != PICOKEY_OK) {
                        mbedtls_rsa_free(&ctx);
                        return SW_EXEC_ERROR();
                    }
                    res_APDU[res_APDU_size++] = 0x81;
                    res_APDU[res_APDU_size++] = 0x82;
                    put_uint16_t_be(mbedtls_mpi_size(&ctx.N), res_APDU + res_APDU_size); res_APDU_size += 2;
                    mbedtls_mpi_write_binary(&ctx.N, res_APDU + res_APDU_size, mbedtls_mpi_size(&ctx.N));
                    res_APDU_size += mbedtls_mpi_size(&ctx.N);
                    res_APDU[res_APDU_size++] = 0x82;
                    res_APDU[res_APDU_size++] = mbedtls_mpi_size(&ctx.E) & 0xff;
                    mbedtls_mpi_write_binary(&ctx.E, res_APDU + res_APDU_size, mbedtls_mpi_size(&ctx.E));
                    res_APDU_size += mbedtls_mpi_size(&ctx.E);
                    mbedtls_rsa_free(&ctx);
                }
#ifdef LF_HAVE_25519
                else if (piv_curve(m.algo)) {
                    /* 86: the 32-byte public key */
                    uint8_t secret[32], pub[32];
                    int curve = piv_curve(m.algo);
                    if (lf25519_load(ef_key, curve, secret, KEY_MODE_PIV) != PICOKEY_OK) {
                        return SW_EXEC_ERROR();
                    }
                    int r = lf25519_public(curve, secret, pub);
                    mbedtls_platform_zeroize(secret, sizeof(secret));
                    if (r != 0) {
                        return SW_EXEC_ERROR();
                    }
                    res_APDU[res_APDU_size++] = 0x86;
                    res_APDU[res_APDU_size++] = sizeof(pub);
                    memcpy(res_APDU + res_APDU_size, pub, sizeof(pub));
                    res_APDU_size += sizeof(pub);
                }
#endif
                else {
                    mbedtls_ecdsa_context ctx;
                    mbedtls_ecdsa_init(&ctx);
                    int r = load_private_key_ecdsa(&ctx, ef_key, KEY_MODE_PIV);
                    if (r != PICOKEY_OK) {
                        mbedtls_ecdsa_free(&ctx);
                        return SW_EXEC_ERROR();
                    }
                    uint8_t pt[MBEDTLS_ECP_MAX_PT_LEN];
                    size_t plen = 0;
                    mbedtls_ecp_point_write_binary(&ctx.grp, &ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &plen, pt, sizeof(pt));
                    mbedtls_ecdsa_free(&ctx);
                    res_APDU[res_APDU_size++] = 0x86;
                    if (plen >= 128) {
                        res_APDU[res_APDU_size++] = 0x81;
                    }
                    res_APDU[res_APDU_size++] = plen;
                    memcpy(res_APDU + res_APDU_size, pt, plen);
                    res_APDU_size += plen;
                }
                uint16_t pk_len = res_APDU_size - (pk - res_APDU);
                if (pk_len > 255) {
                    memmove(pk + 2, pk, pk_len);
                    pk[-1] = 0x82;
                    pk[0] = pk_len >> 8;
                    pk[1] = pk_len & 0xff;
                    res_APDU_size += 2;
                }
                else if (pk_len > 127) {
                    memmove(pk + 1, pk, pk_len);
                    pk[-1] = 0x81;
                    pk[0] = pk_len;
                    res_APDU_size += 1;
                }
                else {
                    pk[-1] = pk_len;
                }
            }
        }
    }
    if (key_ref == EF_PIV_PIN || key_ref == EF_PIV_PUK || key_ref == EF_PIV_KEY_CARDMGM) {
        bool is_default = false;
        if (key_ref == EF_PIV_PIN || key_ref == EF_PIV_PUK) {
            uint8_t dhash[32], rec[PW_REC_LEN];
            if (key_ref == EF_PIV_PIN) {
                double_hash_pin(piv_default_pin, sizeof(piv_default_pin), dhash);
            }
            else {
                double_hash_pin(piv_default_puk, sizeof(piv_default_puk), dhash);
            }
            is_default = pw_rec_read(ef_key, rec) == PICOKEY_OK &&
                         mbedtls_ct_memcmp(dhash, rec + 1, sizeof(dhash)) == 0;
            mbedtls_platform_zeroize(rec, sizeof(rec));
            mbedtls_platform_zeroize(dhash, sizeof(dhash));
        }
        else {
            uint8_t key[32];
            int klen = 0;
            if (key_record_read(ef_key, KEY_MODE_PIV, key, sizeof(key), &klen) == PICOKEY_OK) {
                is_default = klen == sizeof(piv_default_mgm) &&
                             mbedtls_ct_memcmp(key, piv_default_mgm, sizeof(piv_default_mgm)) == 0;
            }
            mbedtls_platform_zeroize(key, sizeof(key));
        }
        res_APDU[res_APDU_size++] = 0x5;
        res_APDU[res_APDU_size++] = 1;
        res_APDU[res_APDU_size++] = is_default;
        if (key_ref == EF_PIV_PIN || key_ref == EF_PIV_PUK) {
            file_t *pw_status, *pw_retries;
            if (!(pw_status = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF)) ||
                !(pw_retries = search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_EF)) ||
                3 + (key_ref & 0xf) >= file_get_size(pw_status) || (key_ref & 0xf) >= file_get_size(pw_retries)) {
                return SW_REFERENCE_NOT_FOUND();
            }
            uint8_t retries = *(file_get_data(pw_status) + 3 + (key_ref & 0xf));
            uint8_t total = *(file_get_data(pw_retries) + (key_ref & 0xf));
            res_APDU[res_APDU_size++] = 0x6;
            res_APDU[res_APDU_size++] = 2;
            res_APDU[res_APDU_size++] = total;
            res_APDU[res_APDU_size++] = retries;
        }
    }
    return SW_OK();
}
/* One block with the management key. */
static int mgm_crypt(uint8_t algo, bool encrypt, const uint8_t *key, uint16_t key_len, const uint8_t *in, uint8_t *out) {
    int r = 0;
    if (algo == PIV_ALGO_3DES) {
        mbedtls_des3_context ctx;
        mbedtls_des3_init(&ctx);
        r = encrypt ? mbedtls_des3_set3key_enc(&ctx, key) : mbedtls_des3_set3key_dec(&ctx, key);
        if (r == 0) {
            r = mbedtls_des3_crypt_ecb(&ctx, in, out);
        }
        mbedtls_des3_free(&ctx);
    }
    else {
        mbedtls_aes_context ctx;
        mbedtls_aes_init(&ctx);
        r = encrypt ? mbedtls_aes_setkey_enc(&ctx, key, key_len * 8) : mbedtls_aes_setkey_dec(&ctx, key, key_len * 8);
        if (r == 0) {
            r = mbedtls_aes_crypt_ecb(&ctx, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, in, out);
        }
        mbedtls_aes_free(&ctx);
    }
    return r;
}

/* Dynamic authentication template 7C { tag <len bytes at res_APDU + 8> }. */
static void dyn_auth_response(uint8_t tag, size_t len) {
    uint8_t hdr[8];
    size_t h = 0;
    hdr[h++] = 0x7C;
    h += format_tlv_len((uint16_t) (1 + format_tlv_len((uint16_t) len, NULL) + len), hdr + h);
    hdr[h++] = tag;
    h += format_tlv_len((uint16_t) len, hdr + h);
    memmove(res_APDU + h, res_APDU + 8, len);
    memcpy(res_APDU, hdr, h);
    res_APDU_size = (uint16_t) (h + len);
}

/* Card administrator (9B), SP 800-73-4 part 2, appendix A.
 * Mutual: 80 (empty) -> 80 E(witness); 80 witness + 81 challenge ->
 * 82 E(challenge). External: 81 (empty) -> 81 challenge; 82 E(challenge).
 * Witness and challenge serve one attempt, passed or failed, and are
 * compared over their full length in constant time. The key encrypts host
 * data only inside a mutual authentication whose witness was right. */
static int mgm_authenticate(uint8_t algo, uint8_t touch, const asn1_ctx_t *a80, const asn1_ctx_t *a81,
                            const asn1_ctx_t *a82) {
    if (algo != PIV_ALGO_AES128 && algo != PIV_ALGO_AES192 && algo != PIV_ALGO_AES256 && algo != PIV_ALGO_3DES) {
        return SW_INCORRECT_P1P2();
    }
    int need = (algo == PIV_ALGO_AES128 ? 16 : (algo == PIV_ALGO_AES256 ? 32 : 24));
    uint8_t blk = (algo == PIV_ALGO_3DES ? 8 : 16);
    uint8_t key[32];
    int key_len = 0, ret = 0;
    file_t *ef_mgm = search_by_fid(EF_PIV_KEY_CARDMGM, NULL, SPECIFY_EF);
    if (!file_has_data(ef_mgm) || key_record_read(ef_mgm, KEY_MODE_PIV, key, sizeof(key), &key_len) != PICOKEY_OK) {
        mbedtls_platform_zeroize(key, sizeof(key));
        return SW_MEMORY_FAILURE();
    }
    bool has80 = a80->data != NULL, has81 = a81->data != NULL, has82 = a82->data != NULL;
    /* a new attempt ends the administrator session */
    has_mgm = false;
    if (key_len != need) {
        ret = SW_INCORRECT_P1P2();
    }
    else if (has80 && a80->len == 0 && !has81) {
        has_challenge = false;
        random_gen(NULL, mgm_witness, blk);
        if (mgm_crypt(algo, true, key, (uint16_t) key_len, mgm_witness, res_APDU + 8) != 0) {
            ret = SW_EXEC_ERROR();
        }
        else {
            has_witness = true;
            dyn_auth_response(0x80, blk);
            ret = SW_OK();
        }
    }
    else if (has80 && a80->len > 0 && has81 && a81->len > 0) {
        bool ok = has_witness && a80->len == blk && a81->len == blk &&
                  mbedtls_ct_memcmp(a80->data, mgm_witness, blk) == 0;
        has_witness = false;
        mbedtls_platform_zeroize(mgm_witness, sizeof(mgm_witness));
        if (!ok) {
            ret = SW_SECURITY_STATUS_NOT_SATISFIED();
        }
        else if (!piv_touch_admin(touch)) {
            ret = SW_CONDITIONS_NOT_SATISFIED();
        }
        else if (mgm_crypt(algo, true, key, (uint16_t) key_len, a81->data, res_APDU + 8) != 0) {
            ret = SW_EXEC_ERROR();
        }
        else {
            dyn_auth_response(0x82, blk);
            has_mgm = true;
            ret = SW_OK();
        }
    }
    else if (has81 && a81->len == 0 && !has80) {
        has_witness = false;
        random_gen(NULL, challenge, blk);
        memcpy(res_APDU + 8, challenge, blk);
        has_challenge = true;
        dyn_auth_response(0x81, blk);
        ret = SW_OK();
    }
    else if (has82 && a82->len > 0 && !has80 && !has81) {
        uint8_t plain[16];
        bool ok = has_challenge && a82->len == blk &&
                  mgm_crypt(algo, false, key, (uint16_t) key_len, a82->data, plain) == 0 &&
                  mbedtls_ct_memcmp(plain, challenge, blk) == 0;
        mbedtls_platform_zeroize(plain, sizeof(plain));
        has_challenge = false;
        mbedtls_platform_zeroize(challenge, sizeof(challenge));
        if (!ok) {
            ret = SW_SECURITY_STATUS_NOT_SATISFIED();
        }
        else if (!piv_touch_admin(touch)) {
            ret = SW_CONDITIONS_NOT_SATISFIED();
        }
        else {
            has_mgm = true;
            ret = SW_OK();
        }
    }
    else {
        ret = SW_WRONG_DATA();
    }
    mbedtls_platform_zeroize(key, sizeof(key));
    return ret;
}

/* Sign / decrypt (81) or key agreement (85) with an asymmetric key, under
 * its PIN and touch policies. One private key operation per command. */
static int key_authenticate(uint8_t algo, uint8_t key_ref, uint8_t pinpol, uint8_t touchpol,
                            const asn1_ctx_t *a81, const asn1_ctx_t *a82, const asn1_ctx_t *a85) {
    bool is_rsa = (algo == PIV_ALGO_RSA1024 || algo == PIV_ALGO_RSA2048 || algo == PIV_ALGO_RSA3072 || algo == PIV_ALGO_RSA4096);
    bool is_ec = (algo == PIV_ALGO_ECCP256 || algo == PIV_ALGO_ECCP384);
    int curve = 0;
#ifdef LF_HAVE_25519
    curve = piv_curve(algo);
#endif
    if (!is_rsa && !is_ec && !curve) {
        return SW_INCORRECT_P1P2();
    }
    /* Ed25519 signs (81, the data as given), X25519 agrees (85) */
    bool sign = a81->data && a81->len > 0, ecdh = a85->data != NULL;
    bool can_sign = is_rsa || is_ec || curve == LF_CURVE_ED25519, can_ecdh = is_ec || curve == LF_CURVE_X25519;
    if (sign == ecdh || (ecdh && !can_ecdh) || (sign && !can_sign) || (a82->data && a82->len > 0)) {
        return SW_WRONG_DATA();
    }
    file_t *ef_key = piv_key_file(key_ref);
    if (!file_has_data(ef_key)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    /* pinpol is resolved (piv_meta_get); an unknown value counts as always */
    if (pinpol != PINPOLICY_NEVER && pinpol != PINPOLICY_ONCE) {
        pinpol = PINPOLICY_ALWAYS;
    }
    /* any key operation uses up a PIN-always grant */
    bool always_ok = pin_always_ok;
    pin_always_ok = false;
    if (pinpol != PINPOLICY_NEVER) {
        /* PIN-always: verified by the command right before this one */
        if (!has_pwpiv || (pinpol == PINPOLICY_ALWAYS && !always_ok)) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
    }
    if (!piv_touch(touchpol)) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    int r = 0;
    size_t olen = 0;
    if (is_rsa) {
        mbedtls_rsa_context ctx;
        mbedtls_rsa_init(&ctx);
        if (load_private_key_rsa(&ctx, ef_key, KEY_MODE_PIV) != PICOKEY_OK) {
            mbedtls_rsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        olen = mbedtls_rsa_get_len(&ctx);
        /* a whole block: a shorter one would be completed from the buffer */
        if (a81->len != olen) {
            mbedtls_rsa_free(&ctx);
            return SW_WRONG_LENGTH();
        }
        r = mbedtls_rsa_private(&ctx, random_gen, NULL, a81->data, res_APDU + 8);
        mbedtls_rsa_free(&ctx);
    }
#ifdef LF_HAVE_25519
    else if (curve) {
        uint8_t secret[32];
        if (ecdh && a85->len != LF_X25519_LEN) {       /* 85: the other party's u */
            return SW_WRONG_DATA();
        }
        if (lf25519_load(ef_key, curve, secret, KEY_MODE_PIV) != PICOKEY_OK) {
            return SW_EXEC_ERROR();
        }
        if (sign) {
            /* the public key is derived from the seed, never taken from
             * elsewhere: a wrong one would give the private key away */
            r = lf_ed25519_sign(res_APDU + 8, a81->data, a81->len, secret, NULL);
            olen = LF_ED25519_SIG_LEN;
        }
        else {
            r = lf_x25519(res_APDU + 8, secret, a85->data);
            olen = LF_X25519_LEN;
        }
        mbedtls_platform_zeroize(secret, sizeof(secret));
        if (r != 0 && ecdh) {
            return SW_DATA_INVALID();                   /* a point of small order */
        }
    }
#endif
    else if (sign) {
        mbedtls_ecdsa_context ctx;
        mbedtls_ecdsa_init(&ctx);
        if (load_private_key_ecdsa(&ctx, ef_key, KEY_MODE_PIV) != PICOKEY_OK) {
            mbedtls_ecdsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        r = mbedtls_ecdsa_write_signature(&ctx, algo == PIV_ALGO_ECCP256 ? MBEDTLS_MD_SHA256 : MBEDTLS_MD_SHA384, a81->data, a81->len, res_APDU + 8, MBEDTLS_ECDSA_MAX_LEN, &olen, random_gen, NULL);
        mbedtls_ecdsa_free(&ctx);
    }
    else {
        /* 85: the other party's point, uncompressed */
        if (a85->len == 0 || a85->len > MBEDTLS_ECP_MAX_PT_LEN) {
            return SW_WRONG_DATA();
        }
        mbedtls_ecdsa_context ecdsa_ctx;
        mbedtls_ecdsa_init(&ecdsa_ctx);
        if (load_private_key_ecdsa(&ecdsa_ctx, ef_key, KEY_MODE_PIV) != PICOKEY_OK) {
            mbedtls_ecdsa_free(&ecdsa_ctx);
            return SW_EXEC_ERROR();
        }
        mbedtls_ecdh_context ecdh_ctx;
        mbedtls_ecdh_init(&ecdh_ctx);
        r = mbedtls_ecdh_setup(&ecdh_ctx, ecdsa_ctx.grp.id);
        if (r == 0) {
            r = mbedtls_mpi_copy(&ecdh_ctx.ctx.mbed_ecdh.d, &ecdsa_ctx.d);
        }
        mbedtls_ecdsa_free(&ecdsa_ctx);
        if (r != 0) {
            mbedtls_ecdh_free(&ecdh_ctx);
            return SW_EXEC_ERROR();
        }
        // mbedtls_ecdh_read_public expects TLS format: [length][point_data]
        uint8_t pub_buf[1 + MBEDTLS_ECP_MAX_PT_LEN];
        pub_buf[0] = (uint8_t) a85->len;
        memcpy(pub_buf + 1, a85->data, a85->len);
        r = mbedtls_ecdh_read_public(&ecdh_ctx, pub_buf, a85->len + 1);
        if (r != 0) {
            mbedtls_ecdh_free(&ecdh_ctx);
            return SW_DATA_INVALID();
        }
        uint8_t shared_secret[MBEDTLS_ECP_MAX_BYTES];
        r = mbedtls_ecdh_calc_secret(&ecdh_ctx, &olen, shared_secret, sizeof(shared_secret), random_gen, NULL);
        mbedtls_ecdh_free(&ecdh_ctx);
        if (r == 0) {
            memcpy(res_APDU + 8, shared_secret, olen);
        }
        mbedtls_platform_zeroize(shared_secret, sizeof(shared_secret));
    }
    if (r != 0) {
        return SW_EXEC_ERROR();
    }
    dyn_auth_response(0x82, olen);
    return SW_OK();
}

static int cmd_authenticate() {
    uint8_t algo = P1(apdu), key_ref = P2(apdu);
    if (apdu.nc == 0) {
        return SW_WRONG_LENGTH();
    }
    if (apdu.data[0] != 0x7C) {
        return SW_WRONG_DATA();
    }
    asn1_ctx_t ctxi, a7c = { 0 };
    asn1_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
    if (!asn1_find_tag(&ctxi, 0x7C, &a7c) || asn1_len(&a7c) == 0) {
        return SW_WRONG_DATA();
    }
    asn1_ctx_t a80 = { 0 }, a81 = { 0 }, a82 = { 0 }, a85 = { 0 };
    asn1_find_tag(&a7c, 0x80, &a80);
    asn1_find_tag(&a7c, 0x81, &a81);
    asn1_find_tag(&a7c, 0x82, &a82);
    asn1_find_tag(&a7c, 0x85, &a85);
    /* The algorithm is the key's own (its metadata), never the host's
     * choice: P1 must name it. */
    piv_meta_t m;
    if ((key_ref != EF_PIV_KEY_CARDMGM && piv_key_fid(key_ref) == 0) || !piv_meta_get(key_ref, &m)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (algo != m.algo) {
        return SW_INCORRECT_P1P2();
    }
    if (key_ref == EF_PIV_KEY_CARDMGM) {
        return mgm_authenticate(algo, m.touch, &a80, &a81, &a82);
    }
    return key_authenticate(algo, key_ref, m.pin, m.touch, &a81, &a82, &a85);
}

/* PIN (AA) and touch (AB) policy of a new key into meta[1] and meta[2].
 * Absent or DEFAULT: as on YubiKey, PIN once (always for 9C, never for 9E)
 * and no touch. Anything but NEVER / ONCE / ALWAYS (PIN) or NEVER / ALWAYS
 * / CACHED (touch) is refused: an unknown value would read as no policy at
 * all. */
static int piv_policies(uint8_t key_ref, asn1_ctx_t *aaa, asn1_ctx_t *aab, uint8_t *meta) {
    uint8_t pin = asn1_len(aaa) ? aaa->data[0] : PINPOLICY_DEFAULT;
    uint8_t touch = asn1_len(aab) ? aab->data[0] : TOUCHPOLICY_DEFAULT;
    if (pin == PINPOLICY_DEFAULT) {
        pin = piv_default_pinpol(key_ref);
    }
    if (touch == TOUCHPOLICY_DEFAULT) {
        touch = TOUCHPOLICY_NEVER;
    }
    if (pin > PINPOLICY_ALWAYS || touch > TOUCHPOLICY_CACHED) {
        return -1;
    }
    meta[1] = pin;
    meta[2] = touch;
    return 0;
}

static int cmd_asym_keygen() {
    uint8_t key_ref = P2(apdu);
    if (apdu.nc == 0) {
        return SW_WRONG_LENGTH();
    }
    if (apdu.data[0] != 0xAC) {
        return SW_WRONG_DATA();
    }
    if (P1(apdu) != 0x0) {
        return SW_INCORRECT_P1P2();
    }
    if (!has_mgm) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (key_ref != EF_PIV_KEY_AUTHENTICATION && key_ref != EF_PIV_KEY_SIGNATURE && key_ref != EF_PIV_KEY_KEYMGM && key_ref != EF_PIV_KEY_CARDAUTH && !(key_ref >= EF_PIV_KEY_RETIRED1 && key_ref <= EF_PIV_KEY_RETIRED20)) {
        return SW_INCORRECT_P1P2();
    }
    asn1_ctx_t ctxi, aac = {0};
    asn1_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
    if (!asn1_find_tag(&ctxi, 0xAC, &aac) || asn1_len(&aac) == 0) {
        return SW_WRONG_DATA();
    }
    asn1_ctx_t a80 = {0}, aaa = {0}, aab = {0};
    asn1_find_tag(&aac, 0x80, &a80);
    asn1_find_tag(&aac, 0xAA, &aaa);
    asn1_find_tag(&aac, 0xAB, &aab);
    if (asn1_len(&a80) == 0) {
        return SW_WRONG_DATA();
    }
    uint16_t key_cert = 0;
    if (key_ref == EF_PIV_KEY_AUTHENTICATION) {
        key_cert = EF_PIV_AUTHENTICATION;
    }
    else if (key_ref == EF_PIV_KEY_SIGNATURE) {
        key_cert = EF_PIV_SIGNATURE;
    }
    else if (key_ref == EF_PIV_KEY_KEYMGM) {
        key_cert = EF_PIV_KEY_MANAGEMENT;
    }
    else if (key_ref == EF_PIV_KEY_CARDAUTH) {
        key_cert = EF_PIV_CARD_AUTH;
    }
    else {
        key_cert = key_ref + 0xC08B;
    }
    uint8_t meta[] = { a80.data[0], 0, 0, ORIGIN_GENERATED };
    if (piv_policies(key_ref, &aaa, &aab, meta) != 0) {
        return SW_WRONG_DATA();
    }
    /* key first, then its certificate and metadata */
    int r = 0;
    bool no_cert = false;
    uint8_t cert[2048];
    if (a80.data[0] == PIV_ALGO_RSA1024 || a80.data[0] == PIV_ALGO_RSA2048) {
        printf("KEYPAIR RSA\r\n");
        asn1_ctx_t a81 = {0};
        asn1_find_tag(&aac, 0x81, &a81);
        /* the key record keeps P and Q only: it is used with e = 65537 */
        if (asn1_len(&a81) && (asn1_len(&a81) > 4 || asn1_get_uint(&a81) != 65537)) {
            return SW_WRONG_DATA();
        }
        mbedtls_rsa_context rsa;
        mbedtls_rsa_init(&rsa);
        int nlen = (a80.data[0] == PIV_ALGO_RSA1024 ? 1024 : 2048);
        r = mbedtls_rsa_gen_key(&rsa, random_gen, NULL, nlen, 65537);
        if (r == 0) {
            r = store_keys(&rsa, ALGO_RSA, piv_key_fid(key_ref), KEY_MODE_PIV);
        }
        if (r == 0) {
            make_rsa_response(&rsa);
            r = x509_create_cert(&rsa, a80.data[0], key_ref, false, cert, sizeof(cert));
        }
        mbedtls_rsa_free(&rsa);
    }
    else if (a80.data[0] == PIV_ALGO_ECCP256 || a80.data[0] == PIV_ALGO_ECCP384) {
        printf("KEYPAIR ECDSA\r\n");
        mbedtls_ecp_group_id gid = a80.data[0] == PIV_ALGO_ECCP256 ? MBEDTLS_ECP_DP_SECP256R1 : MBEDTLS_ECP_DP_SECP384R1;
        mbedtls_ecdsa_context ecdsa;
        mbedtls_ecdsa_init(&ecdsa);
        r = mbedtls_ecdsa_genkey(&ecdsa, gid, random_gen, NULL);
        if (r == 0) {
            r = store_keys(&ecdsa, ALGO_ECDSA, piv_key_fid(key_ref), KEY_MODE_PIV);
        }
        if (r == 0) {
            make_ecdsa_response(&ecdsa);
            r = x509_create_cert(&ecdsa, a80.data[0], key_ref, false, cert, sizeof(cert));
        }
        mbedtls_ecdsa_free(&ecdsa);
    }
#ifdef LF_HAVE_25519
    else if (piv_curve(a80.data[0])) {
        /* answer 7F49 { 86 <32 bytes> }; an Ed25519 key gets a self-signed
         * certificate as the other keys, an X25519 key (it cannot sign) none:
         * the certificate of the key it replaces goes */
        int curve = piv_curve(a80.data[0]);
        uint8_t secret[32], pub[32];
        printf("KEYPAIR %s\r\n", curve == LF_CURVE_ED25519 ? "ED25519" : "X25519");
        lf25519_generate(curve, secret);
        r = lf25519_public(curve, secret, pub) == 0 ? lf25519_store(piv_key_fid(key_ref), curve, secret, KEY_MODE_PIV)
                                                    : PICOKEY_EXEC_ERROR;
        if (r == PICOKEY_OK) {
            make_25519_response(pub);
            if (curve == LF_CURVE_ED25519) {
                r = x509_create_cert_25519(a80.data[0], key_ref, pub, secret, false, cert, sizeof(cert));
            }
            else {
                no_cert = true;
            }
        }
        else {
            r = -1;
        }
        mbedtls_platform_zeroize(secret, sizeof(secret));
    }
#endif
    else {
        return SW_FUNC_NOT_SUPPORTED();
    }
    if (r < 0 || (r == 0 && !no_cert)) {
        return SW_EXEC_ERROR();
    }
    file_t *ef_cert = search_by_fid(key_cert, NULL, SPECIFY_ANY);
    int w = PICOKEY_OK;
    if (!no_cert) {
        w = file_put_data(ef_cert, cert + sizeof(cert) - r, r);
    }
    else if (file_has_data(ef_cert)) {
        w = flash_clear_file(ef_cert);
    }
    if (w != PICOKEY_OK || piv_meta_put(key_ref, meta[0], meta[1], meta[2], meta[3]) != PICOKEY_OK) {
        return SW_MEMORY_FAILURE();
    }
    low_flash_available();
    return SW_OK();
}

static int cmd_put_data() {
    if (P1(apdu) != 0x3F || P2(apdu) != 0xFF) {
        return SW_INCORRECT_P1P2();
    }
    if (!has_mgm) {             /* SP 800-73-4: PUT DATA needs the card admin */
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (apdu.nc == 0) {
        return SW_WRONG_LENGTH();
    }
    asn1_ctx_t ctxi, a5c = {0}, a53 = {0};
    asn1_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
    if (apdu.data[0] != 0x7E && apdu.data[0] != 0x7F && (!asn1_find_tag(&ctxi, 0x5C, &a5c) || !asn1_find_tag(&ctxi, 0x53, &a53))) {
        return SW_WRONG_DATA();
    }
    if (a5c.data && a53.data) {
        if (a5c.len != 3 || a5c.data[0] != 0x5F || a5c.data[1] != 0xC1) {
            return SW_WRONG_DATA();
        }
        uint16_t fid = (a5c.data[1] << 8 | a5c.data[2]);
        file_t *ef = search_by_fid(fid, NULL, SPECIFY_EF);
        if (!ef || !(ef->type & FILE_DATA_FLASH)) {
            return SW_FILE_NOT_FOUND();
        }
        int r = PICOKEY_OK;
        if (a53.len > 0) {
            r = file_put_data(ef, a53.data, a53.len);
        }
        else if (file_has_data(ef)) {
            r = flash_clear_file(ef);
        }
        if (r != PICOKEY_OK) {
            return SW_MEMORY_FAILURE();
        }
        low_flash_available();
    }
    return SW_OK();
}

static int cmd_set_mgmkey() {
    if (P1(apdu) != 0xFF) {
        return SW_INCORRECT_P1P2();
    }
    if (apdu.nc < 3) {
        return SW_WRONG_LENGTH();
    }
    if (!has_mgm) {             /* only the holder of the current key replaces it */
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    uint8_t touch = P2(apdu);
    if (touch != 0xFF && touch != 0xFE) {
        return SW_INCORRECT_P1P2();
    }
    if (touch == 0xFF) {
        touch = TOUCHPOLICY_NEVER;
    }
    else if (touch == 0xFE) {
        touch = TOUCHPOLICY_ALWAYS;
    }
    uint8_t algo = apdu.data[0], key_ref = apdu.data[1], pinlen = apdu.data[2];
    if ((key_ref != EF_PIV_KEY_CARDMGM) || (!(algo == PIV_ALGO_AES128 && pinlen == 16) && !(algo == PIV_ALGO_AES192 && pinlen == 24) && !(algo == PIV_ALGO_AES256 && pinlen == 32) && !(algo == PIV_ALGO_3DES && pinlen == 24))) {
        return SW_WRONG_DATA();
    }
    /* exactly the key: bytes beyond the command would come from old buffers */
    if (apdu.nc != 3u + pinlen) {
        return SW_WRONG_LENGTH();
    }
    piv_meta_t m;
    if (!piv_meta_get(key_ref, &m)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    file_t *ef = search_by_fid(key_ref, NULL, SPECIFY_EF);
    if (!ef) {
        return SW_REFERENCE_NOT_FOUND();
    }
    uint8_t key[32];
    memcpy(key, apdu.data + 3, pinlen);
    int r = key_record_write(ef, KEY_MODE_PIV, key, pinlen);
    mbedtls_platform_zeroize(key, sizeof(key));
    /* this touch policy is enforced (a record of this firmware) */
    if (r != PICOKEY_OK || piv_meta_put(key_ref, algo, PINPOLICY_NEVER, touch, m.origin) != PICOKEY_OK) {
        return SW_MEMORY_FAILURE();
    }
    low_flash_available();
    return SW_OK();
}

/* MOVE KEY (P1 destination or FF to delete, P2 source): the key goes with
 * its metadata (algorithm, PIN and touch policy, origin), so a slot never
 * lends its policy or "generated" origin to another key. The management
 * key (9B) and the attestation key cannot be moved. */
static int cmd_move_key() {
    if (apdu.nc != 0) {
        return SW_WRONG_LENGTH();
    }
    uint8_t to = P1(apdu), from = P2(apdu);
    if (from == to || from == EF_PIV_KEY_CARDMGM || to == EF_PIV_KEY_CARDMGM ||
        (!IS_KEY(to) && to != 0xFF) || !IS_KEY(from)) {
        return SW_INCORRECT_P1P2();
    }
    if (!has_mgm) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    file_t *efs, *efd = NULL;
    if (!(efs = piv_key_file(from)) || (to != 0xFF && !(efd = piv_key_file(to)))) {
        return SW_FILE_NOT_FOUND();
    }
    /* the metadata record is rewritten below: copy it first */
    uint8_t *m = NULL, mbuf[8];
    uint16_t ml = meta_find(from, &m);
    if (!file_has_data(efs) || ml < 4 || ml > sizeof(mbuf)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    memcpy(mbuf, m, ml);
    int r = PICOKEY_OK;
    if (to != 0xFF) {
        /* destination first: a power cut leaves a copy, never no key. The
         * sealed record is bound to its file, so it is opened and sealed
         * again for the destination; a sealed key never lands in plaintext
         * (one of earlier firmware keeps its format while an update is
         * unconfirmed). */
        uint8_t kdata[4096 / 8];
        int klen = 0;
        int mode = sks_is_sealed(SKS_NS_PIV, file_get_data(efs), file_get_size(efs)) ? KEY_MODE_PIV_SEALED :
                   KEY_MODE_PIV;
        r = key_record_read(efs, KEY_MODE_PIV, kdata, sizeof(kdata), &klen);
        if (r == PICOKEY_OK) {
            r = key_record_write(efd, mode, kdata, (uint16_t) klen);
        }
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        if (r == PICOKEY_OK) {
            r = meta_add(to, mbuf, ml);
        }
    }
    if (r == PICOKEY_OK) {
        r = meta_delete(from);
    }
    if (r == PICOKEY_OK) {
        r = flash_clear_file(efs);
    }
    if (r != PICOKEY_OK) {
        return SW_MEMORY_FAILURE();
    }
    low_flash_available();
    return SW_OK();
}

/* New PIN or PUK: 8 bytes, at least 6 characters, then 0xFF padding. */
static bool piv_new_pin_ok(const uint8_t *p, size_t len) {
    if (len != 8) {
        return false;
    }
    size_t n = 0;
    while (n < len && p[n] != 0xFF) {
        n++;
    }
    for (size_t i = n; i < len; i++) {
        if (p[i] != 0xFF) {
            return false;
        }
    }
    return n >= 6;
}

static int cmd_change_pin() {
    uint8_t pin_ref = P2(apdu);
    if (P1(apdu) != 0x0 || (pin_ref != 0x80 && pin_ref != 0x81)) {
        return SW_INCORRECT_P1P2();
    }
    file_t *ef = search_by_fid(pin_ref == 0x80 ? EF_PIV_PIN : EF_PIV_PUK, NULL, SPECIFY_ANY);
    if (!file_has_data(ef)) {
        return SW_MEMORY_FAILURE();
    }
    /* old || new, the old one as long as when it was set (a record that
     * does not open matches nothing, but the attempt counts: 8 bytes) */
    uint8_t rec[PW_REC_LEN];
    size_t old_len = pw_rec_read(ef, rec) == PICOKEY_OK ? rec[0] : 8;
    mbedtls_platform_zeroize(rec, sizeof(rec));
    if (old_len == 0 || apdu.nc <= old_len || !piv_new_pin_ok(apdu.data + old_len, apdu.nc - old_len)) {
        return SW_WRONG_LENGTH();
    }
    uint16_t ret = check_pin(ef, apdu.data, old_len);
    if (ret != 0x9000) {
        if (pin_ref == 0x80) {
            piv_logout_pin();
        }
        return ret;
    }
    uint8_t new_len = (uint8_t) (apdu.nc - old_len);
    int r = pw_rec_set(ef, apdu.data + old_len, new_len, new_len);
    if (r != PICOKEY_OK) {
        return SW_MEMORY_FAILURE();
    }
    low_flash_available();
    return SW_OK();
}

static int cmd_reset_retry() {
    if (P1(apdu) != 0x0 || P2(apdu) != 0x80) {
        return SW_INCORRECT_P1P2();
    }
    file_t *ef = search_by_fid(EF_PIV_PUK, NULL, SPECIFY_ANY);
    if (!file_has_data(ef)) {
        return SW_MEMORY_FAILURE();
    }
    /* PUK || new PIN (a PUK record that does not open matches nothing,
     * but the attempt counts, so the PUK can still be blocked for RESET) */
    uint8_t rec[PW_REC_LEN];
    size_t puk_len = pw_rec_read(ef, rec) == PICOKEY_OK ? rec[0] : 8;
    mbedtls_platform_zeroize(rec, sizeof(rec));
    if (puk_len == 0 || apdu.nc <= puk_len || !piv_new_pin_ok(apdu.data + puk_len, apdu.nc - puk_len)) {
        return SW_WRONG_LENGTH();
    }
    uint16_t ret = check_pin(ef, apdu.data, puk_len);
    if (ret != 0x9000) {
        return ret;
    }
    uint8_t new_len = (uint8_t) (apdu.nc - puk_len);
    ef = search_by_fid(EF_PIV_PIN, NULL, SPECIFY_ANY);
    int r = ef ? pw_rec_set(ef, apdu.data + puk_len, new_len, new_len) : PICOKEY_ERR_FILE_NOT_FOUND;
    if (r == PICOKEY_OK) {
        r = pin_reset_retries(ef, true);
    }
    if (r != PICOKEY_OK) {
        return SW_MEMORY_FAILURE();
    }
    piv_logout_pin();
    low_flash_available();
    return SW_OK();
}

static int cmd_set_retries() {
    /* Resets PIN and PUK to their defaults: the card admin, with the PIN
     * verified in this session (as on other PIV cards). */
    if (!has_mgm || !has_pwpiv) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (P1(apdu) == 0 || P2(apdu) == 0) {     /* 0 tries would block at once */
        return SW_INCORRECT_P1P2();
    }
    file_t *ef = search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_ANY);
    uint8_t tmp[16];
    uint16_t n = file_get_size(ef);
    if (!ef || n < 6 || n > sizeof(tmp)) {
        return SW_MEMORY_FAILURE();
    }
    memcpy(tmp, file_get_data(ef), n);
    tmp[4] = P1(apdu);
    tmp[5] = P2(apdu);
    file_put_data(ef, tmp, n);

    ef = search_by_fid(EF_PIV_PIN, NULL, SPECIFY_ANY);
    pw_rec_set(ef, piv_default_pin, sizeof(piv_default_pin), sizeof(piv_default_pin));
    pin_reset_retries(ef, true);

    ef = search_by_fid(EF_PIV_PUK, NULL, SPECIFY_ANY);
    pw_rec_set(ef, piv_default_puk, sizeof(piv_default_puk), sizeof(piv_default_puk));
    pin_reset_retries(ef, true);

    low_flash_available();
    return SW_OK();
}

/* Files of the PIV application. The attestation key (F9) and its
 * certificate survive a reset, as on other PIV cards; 0x93 is the OpenPGP
 * signature counter (retired key 18 is stored in 0x96). */
static bool piv_owned(uint16_t fid) {
    switch (fid) {
        case EF_PIV_PIN: case EF_PIV_PUK: case EF_PIV_ADMIN_DATA:
        case EF_PIV_DISCOVERY: case EF_PIV_BITGT: case EF_PIV_KEY_RETIRED18:
            return true;
    }
    return (fid >= EF_PIV_KEY_RETIRED1 && fid <= EF_PIV_KEY_RETIRED20 && fid != EF_SIG_COUNT) ||
           (fid >= EF_PIV_KEY_AUTHENTICATION && fid <= EF_PIV_KEY_CARDAUTH) ||
           (fid >= EF_PIV_CARD_AUTH && fid <= EF_PIV_PC_REF_DATA) ||
           (fid >= EF_PIV_MSCMAP && fid <= EF_PIV_MSROOTS5);
}

/* Factory state of the PIV application only (formerly the whole key store:
 * FIDO, OpenPGP and OATH went with it). */
static int piv_reset(void) {
    piv_logout();
    /* Writes become durable in this order (a large reset commits in
     * several batches). First drop the PIV mark of the DEK, so that from
     * any cut-short state scan_files_piv() provisions the default PIN,
     * PUK and management key again; the OpenPGP part and the IV stay. */
    file_t *ef;
    if (dek_file_len() > IV_SIZE + 32 * 3) {
        uint8_t d[DEK_FILE_MAX];
        uint16_t dlen = 0;
        if (dek_file_read(d, &dlen) == PICOKEY_OK) {
            dek_file_write(d, IV_SIZE + 32 * 3);
        }
        mbedtls_platform_zeroize(d, sizeof(d));
    }
    int r = file_wipe_matching(piv_owned);
    for (uint16_t ref = EF_PIV_KEY_RETIRED1; ref <= EF_PIV_KEY_CARDAUTH; ref++) {
        if (ref <= EF_PIV_KEY_RETIRED20 || ref >= EF_PIV_KEY_AUTHENTICATION) {
            meta_delete(ref);
        }
    }
    /* A new epoch for the PIV namespace: copies of the old key records
     * left in the store can no longer be opened. The attestation key stays,
     * sealed again under the new epoch (a plaintext one of earlier firmware
     * needs nothing). The epoch and the re-seal must become durable
     * together: the writes so far are committed first, so that the two
     * start from an empty write cache and land in one commit. */
    if (r == PICOKEY_OK && security_keystore_unlocked() &&
        (ef = search_by_fid(EF_PIV_KEY_ATTESTATION, NULL, SPECIFY_ANY))) {
        uint8_t kdata[67];
        int klen = 0;
        bool sealed = file_has_data(ef) && sks_is_sealed(SKS_NS_PIV, file_get_data(ef), file_get_size(ef));
        bool keep = sealed && key_record_read(ef, KEY_MODE_PIV, kdata, sizeof(kdata), &klen) == PICOKEY_OK;
        r = low_flash_commit();
        if (r == PICOKEY_OK) {
            r = sks_rotate(SKS_NS_PIV);
        }
        if (r == PICOKEY_OK && sealed) {
            if (keep) {
                r = key_record_write(ef, KEY_MODE_PIV_SEALED, kdata, (uint16_t) klen);
            }
            else {
                flash_clear_file(ef);       /* unreadable: a new one is made */
            }
        }
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
    }
    /* Shared with OpenPGP: only the PIV fields. Last, so that PIN and PUK
     * stay blocked (RESET possible again) until the rest is durable. */
    if ((ef = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_ANY)) && file_get_size(ef) >= 9) {
        uint8_t st[16];
        uint16_t n = MIN(file_get_size(ef), (uint16_t) sizeof(st));
        memcpy(st, file_get_data(ef), n);
        st[3 + (EF_PIV_PIN & 0xf)] = st[3 + (EF_PIV_PUK & 0xf)] = 3;
        file_put_data(ef, st, n);
    }
    if ((ef = search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_ANY)) && file_get_size(ef) >= 6) {
        uint8_t rt[16];
        uint16_t n = MIN(file_get_size(ef), (uint16_t) sizeof(rt));
        memcpy(rt, file_get_data(ef), n);
        rt[EF_PIV_PIN & 0xf] = rt[EF_PIV_PUK & 0xf] = 3;
        file_put_data(ef, rt, n);
    }
    low_flash_available();
    init_piv();
    return r;
}

static int cmd_reset() {
    if (P1(apdu) != 0x0 || P2(apdu) != 0x0) {
        return SW_INCORRECT_P1P2();
    }
    file_t *pw_status;
    if (!(pw_status = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF)) ||
        file_get_size(pw_status) <= 3 + (EF_PIV_PUK & 0xf)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    uint8_t retPIN = *(file_get_data(pw_status) + 3 + (EF_PIV_PIN & 0xf)), retPUK = *(file_get_data(pw_status) + 3 + (EF_PIV_PUK & 0xf));
    if (retPIN != 0 || retPUK != 0) {
        return SW_INCORRECT_PARAMS();
    }
    /* A reset destroys the keys: a physical press, whatever presence
     * policy the profile has for PIV. */
    if (wait_button() == true) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    return piv_reset() == PICOKEY_OK ? SW_OK() : SW_MEMORY_FAILURE();
}

static int cmd_attestation() {
    uint8_t key_ref = P1(apdu);
    if (P2(apdu) != 0x00) {
        return SW_INCORRECT_P1P2();
    }
    if (!IS_KEY(key_ref)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    file_t *ef_key = NULL;
    piv_meta_t m;
    if (!(ef_key = piv_key_file(key_ref)) || !file_has_data(ef_key)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!piv_meta_get(key_ref, &m)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (m.origin != ORIGIN_GENERATED) {
        return SW_INCORRECT_PARAMS();
    }
    int r = 0;
    uint8_t m_algo = m.algo;
    if (m_algo == PIV_ALGO_RSA1024 || m_algo == PIV_ALGO_RSA2048) {
        mbedtls_rsa_context ctx;
        mbedtls_rsa_init(&ctx);
        r = load_private_key_rsa(&ctx, ef_key, KEY_MODE_PIV);
        if (r != PICOKEY_OK) {
            mbedtls_rsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        r = x509_create_cert(&ctx, m_algo, key_ref, true, res_APDU, 2048);
        mbedtls_rsa_free(&ctx);
    }
    else if (m_algo == PIV_ALGO_ECCP256 || m_algo == PIV_ALGO_ECCP384) {
        mbedtls_ecdsa_context ctx;
        mbedtls_ecdsa_init(&ctx);
        r = load_private_key_ecdsa(&ctx, ef_key, KEY_MODE_PIV);
        if (r != PICOKEY_OK) {
            mbedtls_ecdsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        r = x509_create_cert(&ctx, m_algo, key_ref, true, res_APDU, 2048);
        mbedtls_ecdsa_free(&ctx);
    }
#ifdef LF_HAVE_25519
    else if (piv_curve(m_algo)) {
        uint8_t secret[32], pub[32];
        int curve = piv_curve(m_algo);
        if (lf25519_load(ef_key, curve, secret, KEY_MODE_PIV) != PICOKEY_OK) {
            return SW_EXEC_ERROR();
        }
        r = lf25519_public(curve, secret, pub);
        mbedtls_platform_zeroize(secret, sizeof(secret));
        if (r != 0) {
            return SW_EXEC_ERROR();
        }
        r = x509_create_cert_25519(m_algo, key_ref, pub, NULL, true, res_APDU, 2048);
    }
#endif
    else {
        return SW_WRONG_DATA();
    }
    if (r <= 0) {
        return SW_EXEC_ERROR();
    }
    memmove(res_APDU, res_APDU + 2048 - r, r);
    res_APDU_size = r;
    return SW_OK();
}

static int cmd_import_asym() {
    uint8_t algo = P1(apdu), key_ref = P2(apdu);
    if (key_ref != EF_PIV_KEY_AUTHENTICATION && key_ref != EF_PIV_KEY_SIGNATURE && key_ref != EF_PIV_KEY_KEYMGM && key_ref != EF_PIV_KEY_CARDAUTH && !(key_ref >= EF_PIV_KEY_RETIRED1 && key_ref <= EF_PIV_KEY_RETIRED20)) {
        return SW_INCORRECT_P1P2();
    }
    if (!has_mgm) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    asn1_ctx_t ctxi, aaa = {0}, aab = {0};
    asn1_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
    asn1_find_tag(&ctxi, 0xAA, &aaa);
    asn1_find_tag(&ctxi, 0xAB, &aab);
    uint8_t meta[] = { algo, 0, 0, ORIGIN_IMPORTED };
    if (piv_policies(key_ref, &aaa, &aab, meta) != 0) {
        return SW_WRONG_DATA();
    }
    if (algo == PIV_ALGO_RSA1024 || algo == PIV_ALGO_RSA2048 || algo == PIV_ALGO_RSA3072 || algo == PIV_ALGO_RSA4096) {
        asn1_ctx_t a1 = { 0 }, a2 = { 0 };
        asn1_find_tag(&ctxi, 0x01, &a1);
        asn1_find_tag(&ctxi, 0x02, &a2);
        if (asn1_len(&a1) <= 0 || asn1_len(&a2) <= 0 || a1.len > 256 || a2.len > 256) {
            return SW_WRONG_DATA();
        }
        size_t nbits = (algo == PIV_ALGO_RSA1024 ? 1024 : (algo == PIV_ALGO_RSA2048 ? 2048 : (algo == PIV_ALGO_RSA3072 ? 3072 : 4096)));
        mbedtls_rsa_context rsa;
        mbedtls_rsa_init(&rsa);
        int r = mbedtls_mpi_read_binary(&rsa.P, a1.data, a1.len);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_WRONG_DATA();
        }
        r = mbedtls_mpi_read_binary(&rsa.Q, a2.data, a2.len);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_WRONG_DATA();
        }
        int exponent = 65537;
        mbedtls_mpi_lset(&rsa.E, exponent);
        r = mbedtls_rsa_import(&rsa, NULL, &rsa.P, &rsa.Q, NULL, &rsa.E);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        r = mbedtls_rsa_complete(&rsa);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        r = mbedtls_rsa_check_privkey(&rsa);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        /* the size P1 announces */
        if (mbedtls_mpi_bitlen(&rsa.N) != nbits) {
            mbedtls_rsa_free(&rsa);
            return SW_WRONG_DATA();
        }
        r = store_keys(&rsa, ALGO_RSA, piv_key_fid(key_ref), KEY_MODE_PIV);
        mbedtls_rsa_free(&rsa);
        if (r != 0) {
            return SW_EXEC_ERROR();
        }
    }
    else if (algo == PIV_ALGO_ECCP256 || algo == PIV_ALGO_ECCP384) {
        asn1_ctx_t a6 = {0};
        asn1_find_tag(&ctxi, 0x06, &a6);
        if (asn1_len(&a6) != (algo == PIV_ALGO_ECCP256 ? 32 : 48)) {
            return SW_WRONG_DATA();
        }
        mbedtls_ecp_group_id gid = algo == PIV_ALGO_ECCP256 ? MBEDTLS_ECP_DP_SECP256R1 : MBEDTLS_ECP_DP_SECP384R1;
        mbedtls_ecdsa_context ecdsa;
        mbedtls_ecdsa_init(&ecdsa);
        int r = mbedtls_ecp_read_key(gid, &ecdsa, a6.data, a6.len);
        if (r != 0) {
            mbedtls_ecdsa_free(&ecdsa);
            return SW_EXEC_ERROR();
        }
        r = mbedtls_ecp_mul(&ecdsa.grp, &ecdsa.Q, &ecdsa.d, &ecdsa.grp.G, random_gen, NULL);
        if (r != 0) {
            mbedtls_ecdsa_free(&ecdsa);
            return SW_EXEC_ERROR();
        }
        r = mbedtls_ecp_check_pub_priv(&ecdsa, &ecdsa, random_gen, NULL);
        if (r != 0) {
            mbedtls_ecdsa_free(&ecdsa);
            return SW_EXEC_ERROR();
        }
        r = store_keys(&ecdsa, ALGO_ECDSA, piv_key_fid(key_ref), KEY_MODE_PIV);
        mbedtls_ecdsa_free(&ecdsa);
        if (r != 0) {
            return SW_EXEC_ERROR();
        }
    }
#ifdef LF_HAVE_25519
    else if (piv_curve(algo)) {
        /* 07: the Ed25519 seed, 08: the X25519 scalar, 32 bytes each (as
         * yubikit sends them) */
        int curve = piv_curve(algo);
        asn1_ctx_t ak = { 0 };
        asn1_find_tag(&ctxi, curve == LF_CURVE_ED25519 ? 0x07 : 0x08, &ak);
        if (asn1_len(&ak) != 32) {
            return SW_WRONG_DATA();
        }
        if (lf25519_store(piv_key_fid(key_ref), curve, ak.data, KEY_MODE_PIV) != PICOKEY_OK) {
            return SW_EXEC_ERROR();
        }
    }
#endif
    else {
        return SW_WRONG_DATA();
    }
    if (piv_meta_put(key_ref, meta[0], meta[1], meta[2], meta[3]) != PICOKEY_OK) {
        return SW_MEMORY_FAILURE();
    }
    low_flash_available();
    return SW_OK();
}

#define INS_VERIFY          0x20
#define INS_VERSION         0xFD
#define INS_SELECT          0xA4
#define INS_YK_SERIAL       0xF8
#define INS_VERIFY          0x20
#define INS_GET_DATA        0xCB
#define INS_GET_METADATA    0xF7
#define INS_AUTHENTICATE    0x87
#define INS_ASYM_KEYGEN     0x47
#define INS_PUT_DATA        0xDB
#define INS_SET_MGMKEY      0xFF
#define INS_MOVE_KEY        0xF6
#define INS_CHANGE_PIN      0x24
#define INS_RESET_RETRY     0x2C
#define INS_SET_RETRIES     0xFA
#define INS_RESET           0xFB
#define INS_ATTESTATION     0xF9
#define INS_IMPORT_ASYM     0xFE

static const cmd_t cmds[] = {
    { INS_VERSION, cmd_version },
    { INS_SELECT, cmd_select },
    { INS_YK_SERIAL, cmd_get_serial },
    { INS_VERIFY, cmd_verify },
    { INS_GET_DATA, cmd_get_data },
    { INS_GET_METADATA, cmd_get_metadata },
    { INS_AUTHENTICATE, cmd_authenticate },
    { INS_ASYM_KEYGEN, cmd_asym_keygen },
    { INS_PUT_DATA, cmd_put_data },
    { INS_SET_MGMKEY, cmd_set_mgmkey },
    { INS_MOVE_KEY, cmd_move_key },
    { INS_CHANGE_PIN, cmd_change_pin },
    { INS_RESET_RETRY, cmd_reset_retry },
    { INS_SET_RETRIES, cmd_set_retries },
    { INS_RESET, cmd_reset },
    { INS_ATTESTATION, cmd_attestation },
    { INS_IMPORT_ASYM, cmd_import_asym },
    { 0x00, 0x0 }
};

/* What runs while the key store is locked (root key held until it is
 * bound): reading the card, nothing that needs the PIN, the PUK, the
 * management key or a private key, and nothing that writes. */
static bool piv_ins_without_store(uint8_t ins) {
    return ins == INS_SELECT || ins == INS_VERSION || ins == INS_YK_SERIAL || ins == INS_GET_DATA ||
           ins == INS_GET_METADATA;
}

int piv_process_apdu() {
    if (sm_unwrap() != PICOKEY_OK) {
        /* Secure messaging requested but not established or not valid:
         * the command must not run on unverified data. */
        pin_always_ok = pin_always_armed = false;
        return set_res_sw(0x68, 0x82);
    }
    /* A PIN-always grant lasts exactly the command after the VERIFY that
     * armed it (command chains and GET RESPONSE are put together by the
     * SDK before they get here). */
    pin_always_ok = pin_always_armed;
    pin_always_armed = false;
    for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
        if (cmd->ins == INS(apdu)) {
            int r = openpgp_store_locked() && !piv_ins_without_store(cmd->ins) ?
                    SW_CONDITIONS_NOT_SATISFIED() : cmd->cmd_handler();
            sm_wrap();
            /* PIV clients (libykpiv's GENERAL AUTHENTICATE, for one) send
             * commands without Le and read the answer directly, as PIV
             * cards give it: up to 256 bytes, the rest with 61xx. */
            if (apdu.ne == 0) {
                apdu.ne = MIN(res_APDU_size, 256);
            }
            return r;
        }
    }
    return SW_INS_NOT_SUPPORTED();
}
