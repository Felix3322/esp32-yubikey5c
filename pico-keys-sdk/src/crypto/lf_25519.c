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
 * Ed25519 (RFC 8032) and X25519 (RFC 7748), portable C99.
 *
 * The structure follows the public domain TweetNaCl (Bernstein, van Gastel,
 * Janssen, Lange, Schwabe, Smetsers): GF(2^255-19) elements are 16 signed
 * limbs of radix 2^16, X25519 is the Montgomery ladder, Ed25519 uses
 * extended twisted Edwards coordinates with the complete addition formula
 * (and, unlike TweetNaCl, the complete doubling formula instead of adding a
 * point to itself) and a double-and-add over all 256 scalar bits with
 * constant-time swaps (no tables), scalars are reduced modulo L with the
 * TweetNaCl modL. Squarings have their own function (136 products, not 256).
 *
 * Constant time: no branch and no memory index depends on a secret (seed,
 * scalar, nonce, intermediate values). Branches below depend only on loop
 * counters or on public data (verification, the all-zero X25519 result that
 * is reported to the caller anyway).
 *
 * Unlike TweetNaCl the limbs, the product accumulators and the modL digits
 * are 32-bit: a 32-bit core without a carry flag (Xtensa) compiles every
 * 64-bit addition to a branch on the carry, which would make the timing
 * depend on the data. Here the only 64-bit values are the 32 x 32 -> 64
 * bit limb products (MULL/MULSH on Xtensa); their low 16 bits and the rest
 * (a constant shift) are added to two neighbouring 32-bit accumulators.
 * Bounds: a limb is a carried value (0 <= limb < 2^16, limb 0 in
 * [-38, 2^16 + 38)) or the sum or difference of at most three of them, so
 * |limb| < 2^18, |product| < 2^36, an accumulator stays below 2^25 and
 * t[i] + 38 t[i + 16] below 2^31.
 *
 * Memory: the points, temporaries and hashes of one operation live in a
 * heap workspace (lf_ws, 1984 bytes on the ESP32-S3) that is wiped before it
 * is freed, so the stack use stays small (about 1.2 KB with the burn buffer,
 * see tests/unit/test_25519.py); what the field arithmetic leaves on the
 * stack is overwritten by lf_burn_stack() before a secret operation returns.
 */

#include <string.h>
#include "mbedtls/sha512.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "lf_25519.h"

/* The ESP32 firmware is built with -Og (ESP-IDF's default); at -O2 the
 * field multiplication uses MULL/MULSH and zero-overhead loops and the
 * operations take about half the time. */
#if defined(ESP_PLATFORM) && defined(__GNUC__) && !defined(__clang__)
#pragma GCC optimize("O2")
#endif

/* The arithmetic relies on >> of a negative value being an arithmetic shift
 * (floor division), as with every compiler we build with. */
typedef char lf_25519_asr_check[((-(int32_t) 1 >> 1) == -(int32_t) 1 &&
                                 (-(int64_t) 1 >> 1) == -(int64_t) 1) ? 1 : -1];

typedef int32_t gf[16];

static const gf gf0 = { 0 };
static const gf gf1 = { 1 };
static const gf c121665 = { 0xDB41, 1 };
/* d = -121665/121666 */
static const gf D = { 0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
                      0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203 };
/* 2d */
static const gf D2 = { 0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
                       0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406 };
/* base point B = (X, Y = 4/5) */
static const gf X = { 0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
                      0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169 };
static const gf Y = { 0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
                      0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666 };
/* sqrt(-1) = 2^((p-1)/4) */
static const gf I = { 0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
                      0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83 };
/* L = 2^252 + 27742317777372353535851937790883648493, little endian */
static const int32_t L[32] = { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
                               0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0x10 };

/* Workspace of one operation (heap, wiped before free). */
typedef struct {
    gf p[4], q[4], u[4];            /* points (X, Y, Z, T) */
    gf a, b, c, d, e, f, t;         /* field temporaries */
    int32_t x[64];                  /* scalar arithmetic mod L */
    uint8_t az[64];                 /* SHA-512(seed): clamped scalar || prefix */
    uint8_t r[64];                  /* nonce */
    uint8_t h[64];                  /* challenge */
    uint8_t pub[32];
    uint8_t out[64];
    mbedtls_sha512_context sha;
} lf_ws;

/* Covers the stack the field and point functions below a public one use
 * (at most 0.6 KB on Xtensa, -fstack-usage); SHA-512 wipes its own. */
#ifndef LF_25519_BURN_BYTES
#define LF_25519_BURN_BYTES 1024
#endif

#if defined(__GNUC__)
#define LF_NOINLINE __attribute__((noinline))
#else
#define LF_NOINLINE
#endif

static LF_NOINLINE void lf_burn_stack(void) {
    uint8_t burn[LF_25519_BURN_BYTES];
    mbedtls_platform_zeroize(burn, sizeof(burn));
}

static lf_ws *ws_new(void) {
    lf_ws *w = (lf_ws *) mbedtls_calloc(1, sizeof(lf_ws));
    if (w) {
        mbedtls_sha512_init(&w->sha);
    }
    return w;
}

static void ws_free(lf_ws *w) {
    if (w) {
        mbedtls_sha512_free(&w->sha);
        mbedtls_platform_zeroize(w, sizeof(*w));
        mbedtls_free(w);
    }
}

/* ---------------------------------------------------------------------------
 * GF(2^255 - 19)
 */

static void gf_set(gf r, const gf a) {
    for (int i = 0; i < 16; i++) {
        r[i] = a[i];
    }
}

/* Carries every limb into [0, 2^16); the carry out of limb 15 (2^256 = 38)
 * goes back to limb 0. */
static void gf_carry(gf o) {
    int32_t c;
    for (int i = 0; i < 15; i++) {
        c = o[i] >> 16;
        o[i + 1] += c;
        o[i] &= 0xffff;
    }
    c = o[15] >> 16;
    o[15] &= 0xffff;
    o[0] += 38 * c;
}

/* Swaps p and q when b = 1, leaves them when b = 0, in constant time. */
static void gf_cswap(gf p, gf q, int32_t b) {
    int32_t t, m = -b;
    for (int i = 0; i < 16; i++) {
        t = m & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

/* Canonical little-endian encoding (value mod p). */
static void gf_pack(uint8_t o[32], const gf n) {
    int32_t b;
    gf m, t;
    gf_set(t, n);
    gf_carry(t);
    gf_carry(t);
    gf_carry(t);
    for (int j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        gf_cswap(t, m, 1 - b);
    }
    for (int i = 0; i < 16; i++) {
        o[2 * i] = (uint8_t) (t[i] & 0xff);
        o[2 * i + 1] = (uint8_t) ((t[i] >> 8) & 0xff);
    }
    mbedtls_platform_zeroize(m, sizeof(m));
    mbedtls_platform_zeroize(t, sizeof(t));
}

/* Ignores bit 255, as RFC 7748 and RFC 8032 require. */
static void gf_unpack(gf o, const uint8_t n[32]) {
    for (int i = 0; i < 16; i++) {
        o[i] = n[2 * i] | ((int32_t) n[2 * i + 1] << 8);
    }
    o[15] &= 0x7fff;
}

/* Public data only (point decoding). */
static int gf_neq(const gf a, const gf b) {
    uint8_t c[32], d[32], r = 0;
    gf_pack(c, a);
    gf_pack(d, b);
    for (int i = 0; i < 32; i++) {
        r |= c[i] ^ d[i];
    }
    return r != 0;
}

static int gf_parity(const gf a) {
    uint8_t d[32];
    gf_pack(d, a);
    return d[0] & 1;
}

static int gf_iszero(const gf a) {
    uint8_t d[32], r = 0;
    gf_pack(d, a);
    for (int i = 0; i < 32; i++) {
        r |= d[i];
    }
    return r == 0;
}

static void gf_add(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; i++) {
        o[i] = a[i] + b[i];
    }
}

static void gf_sub(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; i++) {
        o[i] = a[i] - b[i];
    }
}

/* o = a * b (o may alias a or b), product scanning by columns: the low
 * 16 bits of each product go to column k, the rest to column k + 1. */
static void gf_mul(gf o, const gf a, const gf b) {
    int32_t t[32], hi = 0;
    for (int k = 0; k < 31; k++) {
        int32_t lo = 0, nhi = 0;
        const int i0 = k < 16 ? 0 : k - 15, i1 = k < 16 ? k : 15;
        for (int i = i0; i <= i1; i++) {
            const int64_t p = (int64_t) a[i] * b[k - i];
            lo += (int32_t) (p & 0xffff);
            nhi += (int32_t) (p >> 16);
        }
        t[k] = lo + hi;
        hi = nhi;
    }
    t[31] = hi;
    for (int i = 0; i < 16; i++) {
        o[i] = t[i] + 38 * t[i + 16];
    }
    gf_carry(o);
    gf_carry(o);
}

/* o = a^2: the products a[i] a[j], i < j, once and doubled, then the
 * squares (136 products instead of 256; same bounds as gf_mul). */
static void gf_sqr(gf o, const gf a) {
    int32_t t[32], hi = 0;
    for (int k = 0; k < 31; k++) {
        int32_t lo = 0, nhi = 0;
        /* i < k - i: i from i0 to ceil(k / 2) - 1 */
        const int i0 = k < 16 ? 0 : k - 15, n = ((k + 1) >> 1) - i0;
        for (int c = 0; c < n; c++) {
            const int i = i0 + c;
            const int64_t p = (int64_t) a[i] * a[k - i];
            lo += (int32_t) (p & 0xffff);
            nhi += (int32_t) (p >> 16);
        }
        lo *= 2;
        nhi *= 2;
        if ((k & 1) == 0) {
            const int64_t p = (int64_t) a[k >> 1] * a[k >> 1];
            lo += (int32_t) (p & 0xffff);
            nhi += (int32_t) (p >> 16);
        }
        t[k] = lo + hi;
        hi = nhi;
    }
    t[31] = hi;
    for (int i = 0; i < 16; i++) {
        o[i] = t[i] + 38 * t[i + 16];
    }
    gf_carry(o);
    gf_carry(o);
}

/* o = i^(p-2) */
static void gf_inv(gf o, const gf i) {
    gf c;
    gf_set(c, i);
    for (int a = 253; a >= 0; a--) {
        gf_sqr(c, c);
        if (a != 2 && a != 4) {
            gf_mul(c, c, i);
        }
    }
    gf_set(o, c);
}

/* o = i^((p-5)/8) */
static void gf_pow2523(gf o, const gf i) {
    gf c;
    gf_set(c, i);
    for (int a = 250; a >= 0; a--) {
        gf_sqr(c, c);
        if (a != 1) {
            gf_mul(c, c, i);
        }
    }
    gf_set(o, c);
}

/* ---------------------------------------------------------------------------
 * Edwards points: extended coordinates (X, Y, Z, T), x = X/Z, y = Y/Z,
 * xy = T/Z, on -x^2 + y^2 = 1 + d x^2 y^2. Points are passed as gf * (4
 * elements).
 */

/* p = p + q with the complete unified formula (also for p == q). */
static void pt_add(lf_ws *w, gf *p, gf *q) {
    gf_sub(w->a, p[1], p[0]);
    gf_sub(w->t, q[1], q[0]);
    gf_mul(w->a, w->a, w->t);           /* A = (Y1 - X1)(Y2 - X2) */
    gf_add(w->b, p[0], p[1]);
    gf_add(w->t, q[0], q[1]);
    gf_mul(w->b, w->b, w->t);           /* B = (Y1 + X1)(Y2 + X2) */
    gf_mul(w->c, p[3], q[3]);
    gf_mul(w->c, w->c, D2);             /* C = 2d T1 T2 */
    gf_mul(w->d, p[2], q[2]);
    gf_add(w->d, w->d, w->d);           /* D = 2 Z1 Z2 */
    gf_sub(w->t, w->b, w->a);           /* E = B - A */
    gf_add(w->b, w->b, w->a);           /* H = B + A */
    gf_sub(w->a, w->d, w->c);           /* F = D - C */
    gf_add(w->d, w->d, w->c);           /* G = D + C */
    gf_mul(p[0], w->t, w->a);           /* X3 = E F */
    gf_mul(p[1], w->b, w->d);           /* Y3 = H G */
    gf_mul(p[2], w->d, w->a);           /* Z3 = G F */
    gf_mul(p[3], w->t, w->b);           /* T3 = E H */
}

/* p = 2 p (dbl-2008-hwcd for a = -1, as ref10 computes it: complete, no
 * use of T; 4 squarings and 4 multiplications instead of the 9
 * multiplications of pt_add(p, p)). */
static void pt_double(lf_ws *w, gf *p) {
    gf_sqr(w->a, p[0]);                 /* XX */
    gf_sqr(w->b, p[1]);                 /* YY */
    gf_sqr(w->c, p[2]);
    gf_add(w->c, w->c, w->c);           /* 2 ZZ */
    gf_add(w->d, p[0], p[1]);
    gf_sqr(w->d, w->d);                 /* (X + Y)^2 */
    gf_add(w->t, w->b, w->a);           /* YY + XX */
    gf_sub(w->b, w->b, w->a);           /* YY - XX */
    gf_sub(w->a, w->d, w->t);           /* 2 XY */
    gf_sub(w->c, w->c, w->b);           /* 2 ZZ - YY + XX */
    gf_mul(p[0], w->a, w->c);
    gf_mul(p[1], w->t, w->b);
    gf_mul(p[2], w->b, w->c);
    gf_mul(p[3], w->a, w->t);
}

static void pt_cswap(gf *p, gf *q, int32_t b) {
    for (int i = 0; i < 4; i++) {
        gf_cswap(p[i], q[i], b);
    }
}

static void pt_pack(lf_ws *w, uint8_t r[32], gf *p) {
    gf_inv(w->a, p[2]);
    gf_mul(w->b, p[0], w->a);
    gf_mul(w->c, p[1], w->a);
    gf_pack(r, w->c);
    r[31] ^= (uint8_t) (gf_parity(w->b) << 7);
}

/* p = [s] q for a 256-bit little-endian s; q is clobbered. */
static void pt_scalarmult(lf_ws *w, gf *p, gf *q, const uint8_t s[32]) {
    gf_set(p[0], gf0);
    gf_set(p[1], gf1);
    gf_set(p[2], gf1);
    gf_set(p[3], gf0);
    for (int i = 255; i >= 0; i--) {
        int32_t b = (s[i >> 3] >> (i & 7)) & 1;
        pt_cswap(p, q, b);
        pt_add(w, q, p);
        pt_double(w, p);
        pt_cswap(p, q, b);
    }
}

/* p = [s] B (uses w->u) */
static void pt_scalarbase(lf_ws *w, gf *p, const uint8_t s[32]) {
    gf_set(w->u[0], X);
    gf_set(w->u[1], Y);
    gf_set(w->u[2], gf1);
    gf_mul(w->u[3], X, Y);
    pt_scalarmult(w, p, w->u, s);
}

/* RFC 8032 5.1.3 step 1: the y coordinate (bit 255 cleared) must be < p. */
static int y_is_canonical(const uint8_t s[32]) {
    if ((s[31] & 0x7f) != 0x7f) {
        return 1;
    }
    for (int i = 30; i > 0; i--) {
        if (s[i] != 0xff) {
            return 1;
        }
    }
    return s[0] < 0xed;
}

/* r = -A for the encoding s of A (public data: variable time). */
static int pt_unpackneg(lf_ws *w, gf *r, const uint8_t s[32]) {
    gf *num = &w->a, *den = &w->b, *den2 = &w->c, *den4 = &w->d, *den6 = &w->e;
    gf *chk = &w->f, *t = &w->t;
    int sign = s[31] >> 7;

    if (!y_is_canonical(s)) {
        return -1;
    }
    gf_set(r[2], gf1);
    gf_unpack(r[1], s);
    gf_sqr(*num, r[1]);
    gf_mul(*den, *num, D);
    gf_sub(*num, *num, r[2]);           /* u = y^2 - 1 */
    gf_add(*den, r[2], *den);           /* v = d y^2 + 1 */

    gf_sqr(*den2, *den);
    gf_sqr(*den4, *den2);
    gf_mul(*den6, *den4, *den2);
    gf_mul(*t, *den6, *num);
    gf_mul(*t, *t, *den);               /* u v^7 */

    gf_pow2523(*t, *t);
    gf_mul(*t, *t, *num);
    gf_mul(*t, *t, *den);
    gf_mul(*t, *t, *den);
    gf_mul(r[0], *t, *den);             /* x = u v^3 (u v^7)^((p-5)/8) */

    gf_sqr(*chk, r[0]);
    gf_mul(*chk, *chk, *den);
    if (gf_neq(*chk, *num)) {
        gf_mul(r[0], r[0], I);
    }
    gf_sqr(*chk, r[0]);
    gf_mul(*chk, *chk, *den);
    if (gf_neq(*chk, *num)) {
        return -1;                      /* no square root: not a point */
    }
    if (sign && gf_iszero(r[0])) {
        return -1;                      /* RFC 8032 5.1.3 step 4 */
    }
    if (gf_parity(r[0]) == sign) {
        gf_sub(r[0], gf0, r[0]);
    }
    gf_mul(r[3], r[0], r[1]);
    return 0;
}

/* ---------------------------------------------------------------------------
 * Scalars mod L
 */

/* r = x mod L for the 512-bit x[0..63] in bytes (0 <= x[i] < 256); x is
 * clobbered. With byte digits every intermediate value of the TweetNaCl
 * modL stays far below 2^31. */
static void sc_modL(uint8_t r[32], int32_t x[64]) {
    int32_t carry;
    int i, j;
    for (i = 63; i >= 32; i--) {
        carry = 0;
        for (j = i - 32; j < i - 12; j++) {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry * 256;
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    for (j = 0; j < 32; j++) {
        x[j] += carry - (x[31] >> 4) * L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (j = 0; j < 32; j++) {
        x[j] -= carry * L[j];
    }
    for (i = 0; i < 32; i++) {
        x[i + 1] += x[i] >> 8;
        r[i] = (uint8_t) (x[i] & 255);
    }
}

/* r = h mod L for a 64-byte h (in place allowed). */
static void sc_reduce(lf_ws *w, uint8_t r[32], const uint8_t h[64]) {
    for (int i = 0; i < 64; i++) {
        w->x[i] = h[i];
    }
    sc_modL(r, w->x);
}

/* s < L (public data) */
static int sc_is_canonical(const uint8_t s[32]) {
    for (int i = 31; i >= 0; i--) {
        if (s[i] < L[i]) {
            return 1;
        }
        if (s[i] > L[i]) {
            return 0;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * Ed25519
 */

static int sha512_3(lf_ws *w, uint8_t out[64], const uint8_t *a, size_t alen,
                    const uint8_t *b, size_t blen, const uint8_t *c, size_t clen) {
    if (mbedtls_sha512_starts(&w->sha, 0) != 0 ||
        mbedtls_sha512_update(&w->sha, a, alen) != 0 ||
        (blen && mbedtls_sha512_update(&w->sha, b, blen) != 0) ||
        (clen && mbedtls_sha512_update(&w->sha, c, clen) != 0) ||
        mbedtls_sha512_finish(&w->sha, out) != 0) {
        return -1;
    }
    return 0;
}

/* w->az = clamp(SHA-512(seed)) || prefix, and w->pub = [a] B if asked */
static int ed_expand(lf_ws *w, const uint8_t seed[32], int want_pub) {
    if (sha512_3(w, w->az, seed, 32, NULL, 0, NULL, 0) != 0) {
        return -1;
    }
    w->az[0] &= 248;
    w->az[31] &= 127;
    w->az[31] |= 64;
    if (want_pub) {
        pt_scalarbase(w, w->p, w->az);
        pt_pack(w, w->pub, w->p);
    }
    return 0;
}

int lf_ed25519_public_key(uint8_t pub[LF_ED25519_PUB_LEN], const uint8_t seed[LF_ED25519_SEED_LEN]) {
    int ret = -1;
    lf_ws *w;
    if (!pub || !seed || !(w = ws_new())) {
        return -1;
    }
    if (ed_expand(w, seed, 1) == 0) {
        memcpy(pub, w->pub, 32);
        ret = 0;
    }
    ws_free(w);
    lf_burn_stack();
    return ret;
}

/* The signature is written at the end, so sig may overlap msg. */
int lf_ed25519_sign(uint8_t sig[LF_ED25519_SIG_LEN], const uint8_t *msg, size_t len,
                    const uint8_t seed[LF_ED25519_SEED_LEN], const uint8_t *pub) {
    int ret = -1;
    lf_ws *w;
    if (!sig || !seed || (!msg && len) || !(w = ws_new())) {
        return -1;
    }
    if (!msg) {
        msg = w->out;                   /* len == 0: any valid pointer */
    }
    if (ed_expand(w, seed, pub == NULL) != 0) {
        goto end;
    }
    if (pub) {
        memcpy(w->pub, pub, 32);
    }
    /* r = SHA-512(prefix || M) mod L, R = [r] B */
    if (sha512_3(w, w->r, w->az + 32, 32, msg, len, NULL, 0) != 0) {
        goto end;
    }
    sc_reduce(w, w->r, w->r);
    pt_scalarbase(w, w->p, w->r);
    pt_pack(w, w->out, w->p);
    /* k = SHA-512(R || A || M) mod L */
    if (sha512_3(w, w->h, w->out, 32, w->pub, 32, msg, len) != 0) {
        goto end;
    }
    sc_reduce(w, w->h, w->h);
    /* S = r + k a mod L: the digit products (below 2^21 per column), then
     * byte digits for sc_modL */
    for (int i = 0; i < 64; i++) {
        w->x[i] = i < 32 ? w->r[i] : 0;
    }
    for (int i = 0; i < 32; i++) {
        for (int j = 0; j < 32; j++) {
            w->x[i + j] += (int32_t) w->h[i] * w->az[j];
        }
    }
    for (int i = 0; i < 63; i++) {
        w->x[i + 1] += w->x[i] >> 8;
        w->x[i] &= 255;
    }
    sc_modL(w->out + 32, w->x);
    memcpy(sig, w->out, 64);
    ret = 0;
end:
    ws_free(w);
    lf_burn_stack();
    return ret;
}

int lf_ed25519_verify(const uint8_t sig[LF_ED25519_SIG_LEN], const uint8_t *msg, size_t len,
                      const uint8_t pub[LF_ED25519_PUB_LEN]) {
    int ret = -1;
    uint8_t diff = 0;
    lf_ws *w;
    if (!sig || !pub || (!msg && len)) {
        return -1;
    }
    if (!sc_is_canonical(sig + 32)) {
        return -1;                      /* S >= L */
    }
    if (!(w = ws_new())) {
        return -1;
    }
    if (!msg) {
        msg = w->out;
    }
    if (pt_unpackneg(w, w->q, pub) != 0) {
        goto end;
    }
    if (sha512_3(w, w->h, sig, 32, pub, 32, msg, len) != 0) {
        goto end;
    }
    sc_reduce(w, w->h, w->h);
    pt_scalarmult(w, w->p, w->q, w->h); /* [k](-A) */
    pt_scalarbase(w, w->q, sig + 32);   /* [S]B */
    pt_add(w, w->p, w->q);
    pt_pack(w, w->out, w->p);           /* R' = [S]B - [k]A */
    for (int i = 0; i < 32; i++) {
        diff |= w->out[i] ^ sig[i];
    }
    ret = diff == 0 ? 0 : -1;
end:
    ws_free(w);
    return ret;
}

/* ---------------------------------------------------------------------------
 * X25519
 */

static int x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    int ret = -1;
    uint8_t *z, nz = 0;
    lf_ws *w;
    gf *a, *b, *c, *d, *e, *f, *x;
    if (!out || !scalar || !point || !(w = ws_new())) {
        return -1;
    }
    a = &w->a; b = &w->b; c = &w->c; d = &w->d; e = &w->e; f = &w->f; x = &w->t;
    z = w->az;
    memcpy(z, scalar, 32);
    z[31] = (z[31] & 127) | 64;
    z[0] &= 248;
    gf_unpack(*x, point);
    for (int i = 0; i < 16; i++) {
        (*b)[i] = (*x)[i];
        (*d)[i] = (*a)[i] = (*c)[i] = 0;
    }
    (*a)[0] = (*d)[0] = 1;
    for (int i = 254; i >= 0; i--) {
        int32_t r = (z[i >> 3] >> (i & 7)) & 1;
        gf_cswap(*a, *b, r);
        gf_cswap(*c, *d, r);
        gf_add(*e, *a, *c);
        gf_sub(*a, *a, *c);
        gf_add(*c, *b, *d);
        gf_sub(*b, *b, *d);
        gf_sqr(*d, *e);
        gf_sqr(*f, *a);
        gf_mul(*a, *c, *a);
        gf_mul(*c, *b, *e);
        gf_add(*e, *a, *c);
        gf_sub(*a, *a, *c);
        gf_sqr(*b, *a);
        gf_sub(*c, *d, *f);
        gf_mul(*a, *c, c121665);
        gf_add(*a, *a, *d);
        gf_mul(*c, *c, *a);
        gf_mul(*a, *d, *f);
        gf_mul(*d, *b, *x);
        gf_sqr(*b, *e);
        gf_cswap(*a, *b, r);
        gf_cswap(*c, *d, r);
    }
    gf_inv(*c, *c);
    gf_mul(*a, *a, *c);
    gf_pack(w->out, *a);
    for (int i = 0; i < 32; i++) {
        nz |= w->out[i];
    }
    /* The all-zero result (low-order point) is refused; which of the two
     * cases happened is what the return value tells the caller anyway. */
    if (nz != 0) {
        memcpy(out, w->out, 32);
        ret = 0;
    }
    ws_free(w);
    lf_burn_stack();
    return ret;
}

int lf_x25519(uint8_t out[LF_X25519_LEN], const uint8_t scalar[LF_X25519_LEN],
              const uint8_t point[LF_X25519_LEN]) {
    return x25519(out, scalar, point);
}

int lf_x25519_public_key(uint8_t pub[LF_X25519_LEN], const uint8_t scalar[LF_X25519_LEN]) {
    static const uint8_t nine[32] = { 9 };
    return x25519(pub, scalar, nine);
}
