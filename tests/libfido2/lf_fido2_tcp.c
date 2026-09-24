/*
 * libfido2 interoperability client for the LibreFido emulator.
 *
 * libfido2 (Yubico's C library, used by OpenSSH, systemd, pam-u2f) talks
 * CTAPHID over custom I/O functions to the emulator's TCP HID port, so its
 * own CTAP2 implementation is exercised without a kernel HID device.
 *
 *   lf_fido2_tcp PORT          the ES256 flow, then the EdDSA one
 *   lf_fido2_tcp PORT eddsa    the EdDSA (COSE_EDDSA, Ed25519) flow only
 *
 * The EdDSA flow prints "SKIP eddsa" when getInfo does not list EdDSA.
 *
 * Prints one "OK <step>" line per step; any failure prints "FAIL <step>: <err>"
 * and exits 1.
 */

#include <arpa/inet.h>
#include <fido.h>
#include <fido/credman.h>
#include <fido/eddsa.h>
#include <fido/es256.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int port;

struct conn {
    int fd;
};

static void *tcp_open(const char *path) {
    (void) path;
    struct conn *c = calloc(1, sizeof(*c));
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons((uint16_t) port) };
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (!c || (c->fd = socket(AF_INET, SOCK_STREAM, 0)) < 0 || connect(c->fd, (struct sockaddr *) &a, sizeof(a)) != 0) {
        free(c);
        return NULL;
    }
    return c;
}

static void tcp_close(void *h) {
    struct conn *c = h;
    close(c->fd);
    free(c);
}

static int recv_exact(int fd, unsigned char *p, size_t n, int ms) {
    size_t got = 0;
    while (got < n) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, ms < 0 ? -1 : ms) <= 0) {
            return -1;
        }
        ssize_t r = recv(fd, p + got, n - got, 0);
        if (r <= 0) {
            return -1;
        }
        got += (size_t) r;
    }
    return 0;
}

/* The emulator frames every 64-byte report with a 2-byte big-endian length. */
static int tcp_read(void *h, unsigned char *buf, size_t len, int ms) {
    struct conn *c = h;
    unsigned char hdr[2], rep[64];
    if (recv_exact(c->fd, hdr, 2, ms) != 0) {
        return -1;
    }
    size_t n = ((size_t) hdr[0] << 8) | hdr[1];
    if (n > sizeof(rep) || recv_exact(c->fd, rep, n, ms) != 0) {
        return -1;
    }
    if (n > len) {
        n = len;
    }
    memcpy(buf, rep, n);
    return (int) n;
}

static int tcp_write(void *h, const unsigned char *buf, size_t len) {
    struct conn *c = h;
    /* libfido2 prepends the report ID (0) */
    const unsigned char *rep = buf + 1;
    size_t n = len - 1;
    unsigned char out[2 + 64];
    if (n > 64) {
        return -1;
    }
    out[0] = (unsigned char) (n >> 8);
    out[1] = (unsigned char) n;
    memcpy(out + 2, rep, n);
    return send(c->fd, out, n + 2, 0) == (ssize_t) (n + 2) ? (int) len : -1;
}

static const fido_dev_io_t io = { tcp_open, tcp_close, tcp_read, tcp_write };

#define CHECK(step, expr) do { int _r = (expr); if (_r != FIDO_OK) { \
    printf("FAIL %s: %s (%d)\n", step, fido_strerr(_r), _r); exit(1); } } while (0)
#define OK(step) do { printf("OK %s\n", step); fflush(stdout); } while (0)

static fido_dev_t *open_dev(void) {
    fido_dev_t *d = fido_dev_new();
    CHECK("io", fido_dev_set_io_functions(d, &io));
    CHECK("open", fido_dev_open(d, "tcp"));
    return d;
}

static void fail(const char *step, const char *why) {
    printf("FAIL %s: %s\n", step, why);
    exit(1);
}

static void eddsa_assert(fido_dev_t *dev, const fido_cred_t *cred, const eddsa_pk_t *pk, const char *pin,
                         bool allow, const unsigned char *salt, unsigned char secret[32]) {
    unsigned char cdh[32];
    for (size_t i = 0; i < sizeof(cdh); i++) {
        cdh[i] = (unsigned char) (0x3C ^ (i * 11));
    }
    fido_assert_t *a = fido_assert_new();
    CHECK("ed-ga-cdh", fido_assert_set_clientdata_hash(a, cdh, sizeof(cdh)));
    CHECK("ed-ga-rp", fido_assert_set_rp(a, "eddsa.example"));
    if (allow) {
        CHECK("ed-ga-allow", fido_assert_allow_cred(a, fido_cred_id_ptr(cred), fido_cred_id_len(cred)));
    }
    if (salt) {
        CHECK("ed-ga-ext", fido_assert_set_extensions(a, FIDO_EXT_HMAC_SECRET));
        CHECK("ed-ga-salt", fido_assert_set_hmac_salt(a, salt, 32));
    }
    CHECK("ed-get-assertion", fido_dev_get_assert(dev, a, pin));
    if (fido_assert_count(a) != 1) {
        fail("ed-get-assertion", "not one assertion");
    }
    CHECK("ed-assertion-signature", fido_assert_verify(a, 0, COSE_EDDSA, pk));
    if (fido_assert_sig_len(a, 0) != 64) {
        fail("ed-assertion-signature", "not a 64-byte Ed25519 signature");
    }
    if (salt) {
        if (fido_assert_hmac_secret_len(a, 0) != 32) {
            fail("ed-hmac-secret", "no secret");
        }
        memcpy(secret, fido_assert_hmac_secret_ptr(a, 0), 32);
    }
    fido_assert_free(&a);
}

/* EdDSA: discoverable credential with hmac-secret, self attestation,
 * assertions with and without an allow list, credential management
 * (the listed OKP public key), exclude list, delete, reset. */
static int eddsa_flow(fido_dev_t *dev, fido_cbor_info_t *ci) {
    const char *pin = "4815162342";
    bool listed = false;
    for (size_t i = 0; i < fido_cbor_info_algorithm_count(ci); i++) {
        if (fido_cbor_info_algorithm_cose(ci, i) == COSE_EDDSA) {
            listed = true;
        }
    }
    if (!listed) {
        printf("SKIP eddsa: getInfo does not list EdDSA (-8)\n");
        return 0;
    }
    unsigned char cdh[32], uid[16], salt[32], s1[32], s2[32];
    for (size_t i = 0; i < 32; i++) {
        cdh[i] = (unsigned char) (i * 5 + 1);
        salt[i] = (unsigned char) (0x5A ^ i);
    }
    memset(uid, 0x17, sizeof(uid));
    CHECK("ed-set-pin", fido_dev_set_pin(dev, pin, NULL));

    fido_cred_t *cred = fido_cred_new();
    CHECK("ed-mc-type", fido_cred_set_type(cred, COSE_EDDSA));
    CHECK("ed-mc-cdh", fido_cred_set_clientdata_hash(cred, cdh, sizeof(cdh)));
    CHECK("ed-mc-rp", fido_cred_set_rp(cred, "eddsa.example", "EdDSA"));
    CHECK("ed-mc-user", fido_cred_set_user(cred, uid, sizeof(uid), "bob", "Bob", NULL));
    CHECK("ed-mc-rk", fido_cred_set_rk(cred, FIDO_OPT_TRUE));
    CHECK("ed-mc-ext", fido_cred_set_extensions(cred, FIDO_EXT_HMAC_SECRET));
    CHECK("ed-make-credential", fido_dev_make_cred(dev, cred, pin));
    if (fido_cred_type(cred) != COSE_EDDSA || fido_cred_pubkey_len(cred) != 32) {
        fail("ed-make-credential", "not an Ed25519 key");
    }
    CHECK("ed-self-attestation", fido_cred_verify_self(cred));
    OK("eddsa-make-credential");

    eddsa_pk_t *pk = eddsa_pk_new();
    CHECK("ed-pubkey", eddsa_pk_from_ptr(pk, fido_cred_pubkey_ptr(cred), fido_cred_pubkey_len(cred)));
    eddsa_assert(dev, cred, pk, pin, true, salt, s1);
    eddsa_assert(dev, cred, pk, pin, true, salt, s2);
    if (memcmp(s1, s2, sizeof(s1)) != 0) {
        fail("ed-hmac-secret", "not stable");
    }
    eddsa_assert(dev, cred, pk, pin, false, NULL, NULL);    /* discoverable */
    OK("eddsa-get-assertion");
    OK("eddsa-hmac-secret");

    fido_credman_rk_t *rk = fido_credman_rk_new();
    CHECK("ed-credman-rk", fido_credman_get_dev_rk(dev, "eddsa.example", rk, pin));
    if (fido_credman_rk_count(rk) != 1) {
        fail("ed-credman-rk", "not one credential");
    }
    const fido_cred_t *listed_cred = fido_credman_rk(rk, 0);
    if (fido_cred_type(listed_cred) != COSE_EDDSA || fido_cred_pubkey_len(listed_cred) != 32 ||
        memcmp(fido_cred_pubkey_ptr(listed_cred), fido_cred_pubkey_ptr(cred), 32) != 0) {
        fail("ed-credman-rk", "listed public key differs");
    }
    OK("eddsa-credential-management");

    fido_cred_t *again = fido_cred_new();
    CHECK("ed-ex-type", fido_cred_set_type(again, COSE_EDDSA));
    CHECK("ed-ex-cdh", fido_cred_set_clientdata_hash(again, cdh, sizeof(cdh)));
    CHECK("ed-ex-rp", fido_cred_set_rp(again, "eddsa.example", "EdDSA"));
    CHECK("ed-ex-user", fido_cred_set_user(again, uid, sizeof(uid), "bob", "Bob", NULL));
    CHECK("ed-ex-exclude", fido_cred_exclude(again, fido_cred_id_ptr(cred), fido_cred_id_len(cred)));
    int r = fido_dev_make_cred(dev, again, pin);
    if (r != FIDO_ERR_CREDENTIAL_EXCLUDED) {
        printf("FAIL ed-exclude-list: %s (%d)\n", fido_strerr(r), r);
        return 1;
    }
    OK("eddsa-exclude-list");

    CHECK("ed-credman-delete", fido_credman_del_dev_rk(dev, fido_cred_id_ptr(cred), fido_cred_id_len(cred), pin));
    fido_credman_metadata_t *meta = fido_credman_metadata_new();
    CHECK("ed-credman-metadata", fido_credman_get_dev_metadata(dev, meta, pin));
    if (fido_credman_rk_existing(meta) != 0) {
        fail("ed-credman-delete", "still stored");
    }
    fido_credman_metadata_free(&meta);
    OK("eddsa-credential-delete");
    CHECK("ed-reset", fido_dev_reset(dev));
    OK("eddsa-reset");

    fido_cred_free(&again);
    fido_credman_rk_free(&rk);
    eddsa_pk_free(&pk);
    fido_cred_free(&cred);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s PORT [eddsa]\n", argv[0]);
        return 2;
    }
    port = atoi(argv[1]);
    fido_init(0);
    if (argc > 2 && strcmp(argv[2], "eddsa") == 0) {
        fido_dev_t *dev = open_dev();
        fido_cbor_info_t *ci = fido_cbor_info_new();
        CHECK("info", fido_dev_get_cbor_info(dev, ci));
        OK("info");
        int ret = eddsa_flow(dev, ci);
        fido_cbor_info_free(&ci);
        fido_dev_close(dev);
        fido_dev_free(&dev);
        return ret;
    }
    const char *pin = "4815162342";
    unsigned char cdh[32], uid[16], salt[32];
    for (size_t i = 0; i < 32; i++) {
        cdh[i] = (unsigned char) (i * 7);
        salt[i] = (unsigned char) (0xA5 ^ i);
    }
    memset(uid, 0x42, sizeof(uid));

    fido_dev_t *dev = open_dev();
    if (!fido_dev_is_fido2(dev)) {
        printf("FAIL info: not a FIDO2 device\n");
        return 1;
    }
    fido_cbor_info_t *ci = fido_cbor_info_new();
    CHECK("info", fido_dev_get_cbor_info(dev, ci));
    OK("info");

    CHECK("set-pin", fido_dev_set_pin(dev, pin, NULL));
    int retries = -1;
    CHECK("pin-retries", fido_dev_get_retry_count(dev, &retries));
    if (retries != 8) {
        printf("FAIL pin-retries: %d\n", retries);
        return 1;
    }
    OK("set-pin");

    /* discoverable credential with hmac-secret, credProtect and largeBlobKey */
    fido_cred_t *cred = fido_cred_new();
    CHECK("mc-type", fido_cred_set_type(cred, COSE_ES256));
    CHECK("mc-cdh", fido_cred_set_clientdata_hash(cred, cdh, sizeof(cdh)));
    CHECK("mc-rp", fido_cred_set_rp(cred, "libfido2.example", "libfido2"));
    CHECK("mc-user", fido_cred_set_user(cred, uid, sizeof(uid), "alice", "Alice", NULL));
    CHECK("mc-rk", fido_cred_set_rk(cred, FIDO_OPT_TRUE));
    CHECK("mc-ext", fido_cred_set_extensions(cred, FIDO_EXT_HMAC_SECRET | FIDO_EXT_CRED_PROTECT | FIDO_EXT_LARGEBLOB_KEY));
    CHECK("mc-prot", fido_cred_set_prot(cred, FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID));
    CHECK("make-credential", fido_dev_make_cred(dev, cred, pin));
    CHECK("self-attestation", fido_cred_verify_self(cred));
    if (fido_cred_prot(cred) != FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID || fido_cred_largeblob_key_len(cred) != 32) {
        printf("FAIL make-credential: extensions not honoured\n");
        return 1;
    }
    OK("make-credential");

    es256_pk_t *pk = es256_pk_new();
    CHECK("pubkey", es256_pk_from_ptr(pk, fido_cred_pubkey_ptr(cred), fido_cred_pubkey_len(cred)));

    unsigned char secret1[32];
    for (int round = 0; round < 2; round++) {
        fido_assert_t *a = fido_assert_new();
        CHECK("ga-cdh", fido_assert_set_clientdata_hash(a, cdh, sizeof(cdh)));
        CHECK("ga-rp", fido_assert_set_rp(a, "libfido2.example"));
        CHECK("ga-allow", fido_assert_allow_cred(a, fido_cred_id_ptr(cred), fido_cred_id_len(cred)));
        CHECK("ga-ext", fido_assert_set_extensions(a, FIDO_EXT_HMAC_SECRET));
        CHECK("ga-salt", fido_assert_set_hmac_salt(a, salt, sizeof(salt)));
        CHECK("get-assertion", fido_dev_get_assert(dev, a, pin));
        CHECK("assertion-signature", fido_assert_verify(a, 0, COSE_ES256, pk));
        if (fido_assert_hmac_secret_len(a, 0) != 32) {
            printf("FAIL hmac-secret: no secret\n");
            return 1;
        }
        if (round == 0) {
            memcpy(secret1, fido_assert_hmac_secret_ptr(a, 0), 32);
        }
        else if (memcmp(secret1, fido_assert_hmac_secret_ptr(a, 0), 32) != 0) {
            printf("FAIL hmac-secret: not stable\n");
            return 1;
        }
        fido_assert_free(&a);
    }
    OK("get-assertion");
    OK("hmac-secret");

    /* credential management */
    fido_credman_metadata_t *meta = fido_credman_metadata_new();
    CHECK("credman-metadata", fido_credman_get_dev_metadata(dev, meta, pin));
    if (fido_credman_rk_existing(meta) != 1) {
        printf("FAIL credman-metadata: %llu resident credentials\n", (unsigned long long) fido_credman_rk_existing(meta));
        return 1;
    }
    fido_credman_rp_t *rp = fido_credman_rp_new();
    CHECK("credman-rp", fido_credman_get_dev_rp(dev, rp, pin));
    if (fido_credman_rp_count(rp) != 1 || strcmp(fido_credman_rp_id(rp, 0), "libfido2.example") != 0) {
        printf("FAIL credman-rp\n");
        return 1;
    }
    fido_credman_rk_t *rk = fido_credman_rk_new();
    CHECK("credman-rk", fido_credman_get_dev_rk(dev, "libfido2.example", rk, pin));
    if (fido_credman_rk_count(rk) != 1) {
        printf("FAIL credman-rk\n");
        return 1;
    }
    OK("credential-management");

    /* large blobs, keyed by the credential's largeBlobKey */
    const unsigned char blob[] = "a large blob written through libfido2";
    CHECK("largeblob-set", fido_dev_largeblob_set(dev, fido_cred_largeblob_key_ptr(cred), 32, blob, sizeof(blob), pin));
    unsigned char *got = NULL;
    size_t got_len = 0;
    CHECK("largeblob-get", fido_dev_largeblob_get(dev, fido_cred_largeblob_key_ptr(cred), 32, &got, &got_len));
    if (got_len != sizeof(blob) || memcmp(got, blob, got_len) != 0) {
        printf("FAIL largeblob: content differs\n");
        return 1;
    }
    free(got);
    OK("large-blobs");

    /* delete the credential, then reset */
    CHECK("credman-delete", fido_credman_del_dev_rk(dev, fido_cred_id_ptr(cred), fido_cred_id_len(cred), pin));
    CHECK("credman-metadata2", fido_credman_get_dev_metadata(dev, meta, pin));
    if (fido_credman_rk_existing(meta) != 0) {
        printf("FAIL credman-delete\n");
        return 1;
    }
    OK("credential-delete");
    CHECK("reset", fido_dev_reset(dev));
    fido_dev_close(dev);
    fido_dev_free(&dev);
    dev = open_dev();
    fido_cbor_info_free(&ci);
    ci = fido_cbor_info_new();
    CHECK("info-after-reset", fido_dev_get_cbor_info(dev, ci));
    int pin_set = 1;
    char * const *names = fido_cbor_info_options_name_ptr(ci);
    const bool *vals = fido_cbor_info_options_value_ptr(ci);
    for (size_t i = 0; i < fido_cbor_info_options_len(ci); i++) {
        if (strcmp(names[i], "clientPin") == 0) {
            pin_set = vals[i];
        }
    }
    if (pin_set) {
        printf("FAIL reset: PIN still set\n");
        return 1;
    }
    OK("reset");

    /* the same with an EdDSA credential, when the device offers it */
    if (eddsa_flow(dev, ci) != 0) {
        return 1;
    }

    es256_pk_free(&pk);
    fido_cred_free(&cred);
    fido_credman_metadata_free(&meta);
    fido_credman_rp_free(&rp);
    fido_credman_rk_free(&rk);
    fido_cbor_info_free(&ci);
    fido_dev_close(dev);
    fido_dev_free(&dev);
    return 0;
}
