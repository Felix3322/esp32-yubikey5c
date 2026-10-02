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

#include "lf_keyio.h"
#include "lf_policy.h"

static const lf_keyio_ops_t *keyio_ops[LF_APP_COUNT];

void lf_keyio_register(uint8_t app, const lf_keyio_ops_t *ops) {
    if (app < LF_APP_COUNT) {
        keyio_ops[app] = ops;
    }
}

const lf_keyio_ops_t *lf_keyio_ops(uint8_t app) {
    return app < LF_APP_COUNT ? keyio_ops[app] : NULL;
}
