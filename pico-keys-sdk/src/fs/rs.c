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
 * Reed-Solomon codec, see rs.h. Decoding is the textbook pipeline:
 * syndromes, Berlekamp-Massey error locator, Chien search, Forney error
 * values, and a final syndrome check. Polynomials are stored lowest degree
 * first; codeword byte 0 is the highest degree coefficient (as in reedsolo).
 */

#include <stdbool.h>
#include <string.h>
#include "rs.h"

static uint8_t gf_exp[512];
static uint8_t gf_log[256];
static uint8_t gen_poly[RS_NSYM + 1];   /* highest degree first, gen_poly[0] = 1 */
static int tables_ready = 0;

static inline uint8_t gf_mul(uint8_t a, uint8_t b) {
    if (a == 0 || b == 0) {
        return 0;
    }
    return gf_exp[gf_log[a] + gf_log[b]];
}

static inline uint8_t gf_inv(uint8_t a) {
    return gf_exp[255 - gf_log[a]];
}

static inline uint8_t gf_div(uint8_t a, uint8_t b) {
    if (a == 0) {
        return 0;
    }
    return gf_exp[gf_log[a] + 255 - gf_log[b]];
}

/* alpha^e for any integer e (negative exponents allowed). */
static inline uint8_t gf_alpha(int e) {
    e %= 255;
    if (e < 0) {
        e += 255;
    }
    return gf_exp[e];
}

static void rs_init(void) {
    if (__atomic_load_n(&tables_ready, __ATOMIC_ACQUIRE)) {
        return;
    }
    unsigned x = 1;
    for (int i = 0; i < 255; i++) {
        gf_exp[i] = (uint8_t) x;
        gf_log[x] = (uint8_t) i;
        x <<= 1;
        if (x & 0x100) {
            x ^= 0x11D;
        }
    }
    for (int i = 255; i < 512; i++) {
        gf_exp[i] = gf_exp[i - 255];
    }
    /* g(x) = prod_{i=0}^{nsym-1} (x - alpha^i) */
    uint8_t g[RS_NSYM + 1] = { 1 };
    int glen = 1;
    for (int i = 0; i < RS_NSYM; i++) {
        uint8_t ng[RS_NSYM + 1] = { 0 };
        for (int j = 0; j < glen; j++) {
            ng[j] ^= g[j];
            ng[j + 1] ^= gf_mul(g[j], gf_exp[i]);
        }
        glen++;
        memcpy(g, ng, (size_t) glen);
    }
    memcpy(gen_poly, g, sizeof(gen_poly));
    /* Concurrent first calls compute identical tables, so the race is benign. */
    __atomic_store_n(&tables_ready, 1, __ATOMIC_RELEASE);
}

void rs_encode_block(const uint8_t *data, size_t len, uint8_t parity[RS_NSYM]) {
    rs_init();
    uint8_t rem[RS_NSYM] = { 0 };
    for (size_t i = 0; i < len; i++) {
        uint8_t coef = data[i] ^ rem[0];
        memmove(rem, rem + 1, RS_NSYM - 1);
        rem[RS_NSYM - 1] = 0;
        if (coef != 0) {
            for (int j = 0; j < RS_NSYM; j++) {
                rem[j] ^= gf_mul(gen_poly[j + 1], coef);
            }
        }
    }
    memcpy(parity, rem, RS_NSYM);
}

static bool syndromes(const uint8_t *cw, size_t n, uint8_t synd[RS_NSYM]) {
    bool any = false;
    for (int j = 0; j < RS_NSYM; j++) {
        uint8_t x = gf_exp[j], y = 0;
        for (size_t i = 0; i < n; i++) {
            y = gf_mul(y, x) ^ cw[i];
        }
        synd[j] = y;
        any |= (y != 0);
    }
    return any;
}

int rs_decode_block(uint8_t *data, size_t len, uint8_t parity[RS_NSYM]) {
    rs_init();
    if (len == 0 || len > RS_MAX_DATA) {
        return -1;
    }
    const size_t n = len + RS_NSYM;
    uint8_t cw[255];
    memcpy(cw, data, len);
    memcpy(cw + len, parity, RS_NSYM);

    uint8_t synd[RS_NSYM];
    if (!syndromes(cw, n, synd)) {
        return 0;
    }

    /* Berlekamp-Massey: sigma(x) = prod (1 - X_k x) */
    uint8_t sigma[RS_NSYM + 2] = { 1 }, old[RS_NSYM + 2] = { 1 }, tmp[RS_NSYM + 2];
    int ls = 1, lo = 1;
    for (int i = 0; i < RS_NSYM; i++) {
        uint8_t delta = synd[i];
        for (int j = 1; j < ls && j <= i; j++) {
            delta ^= gf_mul(sigma[j], synd[i - j]);
        }
        memmove(old + 1, old, (size_t) lo);
        old[0] = 0;
        lo++;
        if (delta != 0) {
            if (lo > ls) {
                uint8_t inv = gf_inv(delta);
                for (int k = 0; k < lo; k++) {
                    tmp[k] = gf_mul(old[k], delta);
                }
                for (int k = 0; k < ls; k++) {
                    old[k] = gf_mul(sigma[k], inv);
                }
                int t = lo;
                lo = ls;
                ls = t;
                memcpy(sigma, tmp, (size_t) ls);
            }
            for (int k = 0; k < lo; k++) {
                sigma[k] ^= gf_mul(old[k], delta);
            }
        }
    }
    while (ls > 1 && sigma[ls - 1] == 0) {
        ls--;
    }
    int nerr = ls - 1;
    if (nerr == 0 || 2 * nerr > RS_NSYM) {
        return -1;
    }

    /* Chien search over the (possibly shortened) codeword: an error in the
     * coefficient of x^p makes alpha^-p a root of sigma. */
    int pos[RS_NSYM];
    int found = 0;
    for (int p = 0; p < (int) n; p++) {
        uint8_t xinv = gf_alpha(-p), v = 0;
        for (int k = ls - 1; k >= 0; k--) {
            v = gf_mul(v, xinv) ^ sigma[k];
        }
        if (v == 0) {
            if (found == nerr) {
                return -1;
            }
            pos[found++] = p;
        }
    }
    if (found != nerr) {
        return -1;
    }

    /* Forney: e_k = X_k * omega(X_k^-1) / sigma'(X_k^-1), omega = S*sigma mod x^nsym */
    uint8_t omega[RS_NSYM];
    for (int i = 0; i < RS_NSYM; i++) {
        uint8_t acc = 0;
        for (int k = 0; k <= i && k < ls; k++) {
            acc ^= gf_mul(sigma[k], synd[i - k]);
        }
        omega[i] = acc;
    }
    for (int e = 0; e < nerr; e++) {
        int p = pos[e];
        uint8_t xinv = gf_alpha(-p), om = 0, dp = 0;
        for (int k = RS_NSYM - 1; k >= 0; k--) {
            om = gf_mul(om, xinv) ^ omega[k];
        }
        for (int j = 1; j < ls; j += 2) {
            dp ^= gf_mul(sigma[j], gf_alpha(-p * (j - 1)));
        }
        if (dp == 0) {
            return -1;
        }
        cw[n - 1 - (size_t) p] ^= gf_mul(gf_alpha(p), gf_div(om, dp));
    }

    /* A block with more errors than the code corrects can decode to a wrong
     * codeword; only a clean syndrome check is accepted. */
    if (syndromes(cw, n, synd)) {
        return -1;
    }
    memcpy(data, cw, len);
    memcpy(parity, cw + len, RS_NSYM);
    return nerr;
}

void rs_encode(const uint8_t *data, size_t len, uint8_t *parity) {
    for (size_t off = 0, blk = 0; off < len; off += RS_MAX_DATA, blk++) {
        size_t n = len - off < RS_MAX_DATA ? len - off : RS_MAX_DATA;
        rs_encode_block(data + off, n, parity + blk * RS_NSYM);
    }
}

int rs_decode(uint8_t *data, size_t len, uint8_t *parity) {
    int total = 0;
    bool failed = false;
    for (size_t off = 0, blk = 0; off < len; off += RS_MAX_DATA, blk++) {
        size_t n = len - off < RS_MAX_DATA ? len - off : RS_MAX_DATA;
        int r = rs_decode_block(data + off, n, parity + blk * RS_NSYM);
        if (r < 0) {
            failed = true;
        }
        else {
            total += r;
        }
    }
    return failed ? -1 : total;
}
