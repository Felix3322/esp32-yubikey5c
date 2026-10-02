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
 * Build profiles.
 *
 *  DEVELOPMENT  easy reflashing, verbose logs, no eFuse provisioning, UP may
 *               be emulated. Never ship.
 *  STANDARD     default. Keeps LibreFido features (backup/recovery), secrets
 *               encrypted at rest, UP enforced, logs without secrets.
 *  HARDENED     non-exportable secrets, no recovery export, no debug, and the
 *               firmware refuses to unlock the key store unless Secure Boot,
 *               Flash Encryption (release) and anti-rollback are active.
 *
 * Profiles only restrict: a HARDENED build never enables something a
 * STANDARD build forbids.
 */

#ifndef _PROFILE_H_
#define _PROFILE_H_

#if defined(ESP_PLATFORM)
#include "sdkconfig.h"
#endif

#if defined(CONFIG_LIBREFIDO_PROFILE_HARDENED) || defined(LIBREFIDO_PROFILE_HARDENED)
#define LF_PROFILE_HARDENED     1
#define LF_PROFILE_NAME         "hardened"
#define LF_PROFILE_ID           2
#elif defined(CONFIG_LIBREFIDO_PROFILE_DEVELOPMENT) || defined(LIBREFIDO_PROFILE_DEVELOPMENT)
#define LF_PROFILE_DEVELOPMENT  1
#define LF_PROFILE_NAME         "development"
#define LF_PROFILE_ID           0
#else
#define LF_PROFILE_STANDARD     1
#define LF_PROFILE_NAME         "standard"
#define LF_PROFILE_ID           1
#endif

#ifdef LF_PROFILE_HARDENED
/* Secret material (FIDO device key seed, OpenPGP/PIV private keys) can never
 * leave the device, not even wrapped. */
#define LF_ALLOW_SECRET_EXPORT          0
/* Unauthenticated maintenance commands (rescue PHY writes) are refused. */
#define LF_ALLOW_UNAUTH_MAINTENANCE     0
/* The key store stays locked unless the chip security state is complete. */
#define LF_REQUIRE_CHIP_SECURITY        1
#else
#define LF_ALLOW_SECRET_EXPORT          1
#define LF_ALLOW_UNAUTH_MAINTENANCE     1
#define LF_REQUIRE_CHIP_SECURITY        0
#endif

#ifdef LF_PROFILE_DEVELOPMENT
/* Boards without any button can be exercised when explicitly configured. */
#if defined(CONFIG_LIBREFIDO_DEV_AUTO_UP) || defined(LIBREFIDO_DEV_AUTO_UP)
#define LF_UP_AUTO_ACCEPT               1
#endif
#endif
#ifndef LF_UP_AUTO_ACCEPT
#define LF_UP_AUTO_ACCEPT               0
#endif

#endif // _PROFILE_H_
