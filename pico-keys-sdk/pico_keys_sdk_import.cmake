#
# This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
# Copyright (c) 2022 Pol Henarejos.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

include(pico-keys-sdk/cmake/version.cmake OPTIONAL)

# Other vendors' identities are for personal compatibility experiments only
# and must never be distributed. Yubico's (VID 0x1050) is not available at
# all: LibreFido does not present itself as a YubiKey.
option(VIDPID "Set specific VID/PID from a known platform {NitroHSM, NitroFIDO2, NitroStart, NitroPro, Nitro3, Gnuk, GnuPG}" "None")
if(VIDPID MATCHES "^Yubi")
    message(FATAL_ERROR "VIDPID=${VIDPID}: Yubico USB identities are not supported (LibreFido never presents itself as a YubiKey)")
endif()

message(STATUS "VIDPID:\t\t\t '${VIDPID}'")

if(VIDPID STREQUAL "NitroHSM")
    set(USB_VID 0x20A0)
    set(USB_PID 0x4230)
elseif(VIDPID STREQUAL "NitroFIDO2")
    set(USB_VID 0x20A0)
    set(USB_PID 0x42B1)
elseif(VIDPID STREQUAL "NitroStart")
    set(USB_VID 0x20A0)
    set(USB_PID 0x4211)
elseif(VIDPID STREQUAL "NitroPro")
    set(USB_VID 0x20A0)
    set(USB_PID 0x4108)

elseif(VIDPID STREQUAL "Nitro3")
    set(USB_VID 0x20A0)
    set(USB_PID 0x42B2)
elseif(VIDPID STREQUAL "Gnuk")
    set(USB_VID 0x234B)
    set(USB_PID 0x0000)
elseif(VIDPID STREQUAL "GnuPG")
    set(USB_VID 0x1209)
    set(USB_PID 0x2440)
endif()

if(ESP_PLATFORM)
    if(DEFINED CONFIG_TINYUSB_DESC_CUSTOM_VID)
        set(USB_VID CONFIG_TINYUSB_DESC_CUSTOM_VID)
    endif()
    if(DEFINED CONFIG_TINYUSB_DESC_CUSTOM_PID)
        set(USB_PID CONFIG_TINYUSB_DESC_CUSTOM_PID)
    endif()
endif()

if(NOT DEFINED USB_VID)
    set(USB_VID 0x1D50)
endif()
if(USB_VID MATCHES "^(0x|0X)?0*1050$")
    message(FATAL_ERROR "USB_VID ${USB_VID} is Yubico's: use an identity you are entitled to")
endif()
if(NOT VIDPID STREQUAL "None" AND NOT VIDPID STREQUAL "OFF" AND NOT VIDPID STREQUAL "")
    message(WARNING "VIDPID=${VIDPID}: another vendor's USB identity, for personal use only, never distribute such a build")
endif()
add_definitions(-DUSB_VID=${USB_VID})

if(NOT DEFINED USB_PID)
    set(USB_PID 0x619B)
endif()
add_definitions(-DUSB_PID=${USB_PID})

# Build profile (src/profile.h): -DLIBREFIDO_PROFILE=development|standard|hardened
if(NOT DEFINED LIBREFIDO_PROFILE)
    set(LIBREFIDO_PROFILE standard)
endif()
string(TOLOWER "${LIBREFIDO_PROFILE}" LIBREFIDO_PROFILE)
if(LIBREFIDO_PROFILE STREQUAL "hardened")
    add_definitions(-DLIBREFIDO_PROFILE_HARDENED=1)
elseif(LIBREFIDO_PROFILE STREQUAL "development")
    add_definitions(-DLIBREFIDO_PROFILE_DEVELOPMENT=1)
elseif(NOT LIBREFIDO_PROFILE STREQUAL "standard")
    message(FATAL_ERROR "LIBREFIDO_PROFILE must be development, standard or hardened (not '${LIBREFIDO_PROFILE}')")
endif()
message(STATUS "LibreFido profile:\t '${LIBREFIDO_PROFILE}'")

if(NOT DEFINED DEBUG_APDU)
    set(DEBUG_APDU 0)
endif()
if(NOT DEFINED ENABLE_EMULATION)
    set(ENABLE_EMULATION 0)
endif()

option(ENABLE_DELAYED_BOOT "Enable/disable delayed boot" OFF)
if(ENABLE_DELAYED_BOOT)
    add_definitions(-DPICO_XOSC_STARTUP_DELAY_MULTIPLIER=64)
    message(STATUS "Delayed boot:\t\t enabled")
else()
    message(STATUS "Delayed boot:\t\t disabled")
endif(ENABLE_DELAYED_BOOT)
if(USB_ITF_HID)
    add_definitions(-DUSB_ITF_HID=1)
    message(STATUS "USB HID Interface:\t\t enabled")
endif(USB_ITF_HID)
if(USB_ITF_CCID)
    add_definitions(-DUSB_ITF_CCID=1)
    message(STATUS "USB CCID Interface:\t\t enabled")
    if(USB_ITF_WCID)
        add_definitions(-DUSB_ITF_WCID=1)
        message(STATUS "USB WebCCID Interface:\t enabled")
    endif(USB_ITF_WCID)
endif(USB_ITF_CCID)
add_definitions(-DDEBUG_APDU=${DEBUG_APDU})
if(NOT ESP_PLATFORM)
    add_definitions(-DMBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_LIST_DIR}/config/mbedtls_config.h")
else()
    add_definitions(-DCFG_TUSB_CONFIG_FILE="${CMAKE_CURRENT_LIST_DIR}/src/usb/tusb_config.h")
endif()

message(STATUS "USB VID/PID:\t\t\t ${USB_VID}:${USB_PID}")

if(NOT ESP_PLATFORM)
    set(NEED_UPDATE OFF)

    option(ENABLE_EDDSA "Enable/disable EdDSA support" OFF)
    if(ENABLE_EDDSA)
        message(STATUS "EdDSA support:\t\t enabled")
    else()
        message(STATUS "EdDSA support:\t\t disabled")
    endif(ENABLE_EDDSA)

    set(MBEDTLS_PATH "${CMAKE_CURRENT_LIST_DIR}/mbedtls")
    if(ENABLE_EDDSA)
        # The EdDSA-capable fork must be checked out explicitly; configuring
        # never rewrites submodules or touches the network.
        if(NOT EXISTS "${MBEDTLS_PATH}/library/eddsa.c")
            message(FATAL_ERROR "ENABLE_EDDSA needs the librekeys/mbedtls mbedtls-3.6-eddsa branch in ${MBEDTLS_PATH}")
        endif()
        add_definitions(-DMBEDTLS_ECP_DP_ED25519_ENABLED=1 -DMBEDTLS_ECP_DP_ED448_ENABLED=1 -DMBEDTLS_EDDSA_C=1 -DMBEDTLS_SHA3_C=1)
    endif()
    if(EXISTS "${MBEDTLS_PATH}/include/mbedtls/build_info.h")
        file(STRINGS "${MBEDTLS_PATH}/include/mbedtls/build_info.h" _mbedtls_ver REGEX "#define MBEDTLS_VERSION_STRING ")
        message(STATUS "mbedTLS:\t\t\t ${_mbedtls_ver}")
    endif()
endif(NOT ESP_PLATFORM)

option(ENABLE_PQC "Enable/disable PQC support" OFF)
if(ENABLE_PQC)
    message(STATUS "PQC support:\t\t\t enabled")
    add_definitions(-DENABLE_PQC)
else()
    message(STATUS "PQC support:\t\t\t disabled")
endif(ENABLE_PQC)

set(MBEDTLS_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/aes.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/asn1parse.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/asn1write.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/bignum.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/bignum_core.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ccm.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/cmac.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/cipher.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/cipher_wrap.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/constant_time.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ecdsa.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ecdh.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ecp.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ecp_curves.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/gcm.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/hkdf.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/md.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/md5.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/oid.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pkcs5.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/platform_util.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/rsa.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/rsa_alt_helpers.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/sha1.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/sha256.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/sha512.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/chachapoly.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/chacha20.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/poly1305.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ripemd160.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/des.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/x509write.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/x509write_crt.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/x509_create.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/x509write_csr.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/base64.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pem.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pk.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pk_wrap.c
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pkwrite.c
)

if (ENABLE_EDDSA)
    set(MBEDTLS_SOURCES ${MBEDTLS_SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/eddsa.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/sha3.c
    )
endif()

if(ENABLE_PQC)
if (NOT ESP_PLATFORM)
    file(GLOB_RECURSE MLKEM_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/mlkem/mlkem/src/*.c
    )
    list(FILTER MLKEM_SOURCES EXCLUDE REGEX "/native/")

    add_library(mlkem512 STATIC ${MLKEM_SOURCES})
    target_include_directories(mlkem512 PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mlkem/mlkem/src
        ${CMAKE_CURRENT_LIST_DIR}/config/mlkem
    )
    target_compile_definitions(mlkem512 PRIVATE
        MLK_CONFIG_PARAMETER_SET=512
        MLK_CONFIG_MULTILEVEL_WITH_SHARED
        MLK_CONFIG_NAMESPACE_PREFIX=mlkem
    )

    add_library(mlkem768 STATIC ${MLKEM_SOURCES})
    target_include_directories(mlkem768 PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mlkem/mlkem/src
        ${CMAKE_CURRENT_LIST_DIR}/config/mlkem
    )
    target_compile_definitions(mlkem768 PRIVATE
        MLK_CONFIG_PARAMETER_SET=768
        MLK_CONFIG_MULTILEVEL_NO_SHARED
        MLK_CONFIG_NAMESPACE_PREFIX=mlkem
    )

    add_library(mlkem1024 STATIC ${MLKEM_SOURCES})
    target_include_directories(mlkem1024 PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mlkem/mlkem/src
        ${CMAKE_CURRENT_LIST_DIR}/config/mlkem
    )
    target_compile_definitions(mlkem1024 PRIVATE
        MLK_CONFIG_PARAMETER_SET=1024
        MLK_CONFIG_MULTILEVEL_NO_SHARED
        MLK_CONFIG_NAMESPACE_PREFIX=mlkem
    )
endif()

    set(INCLUDES ${INCLUDES}
        ${CMAKE_CURRENT_LIST_DIR}/mlkem/mlkem
        ${CMAKE_CURRENT_LIST_DIR}/config/mlkem
    )
    add_definitions(-DMLK_CONFIG_NAMESPACE_PREFIX=mlkem -DMLK_CONFIG_MULTILEVEL_BUILD=1)
endif()

set(PICO_KEYS_SOURCES ${PICO_KEYS_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/src/main.c
    ${CMAKE_CURRENT_LIST_DIR}/src/usb/usb.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fs/file.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fs/flash.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fs/otp.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fs/phy.c
    ${CMAKE_CURRENT_LIST_DIR}/src/rng/random.c
    ${CMAKE_CURRENT_LIST_DIR}/src/rng/hwrng.c
    ${CMAKE_CURRENT_LIST_DIR}/src/eac.c
    ${CMAKE_CURRENT_LIST_DIR}/src/crypto_utils.c
    ${CMAKE_CURRENT_LIST_DIR}/src/asn1.c
    ${CMAKE_CURRENT_LIST_DIR}/src/apdu.c
    ${CMAKE_CURRENT_LIST_DIR}/src/rescue.c
    ${CMAKE_CURRENT_LIST_DIR}/src/led/led.c
    ${CMAKE_CURRENT_LIST_DIR}/src/up/up.c
    ${CMAKE_CURRENT_LIST_DIR}/src/sec/security.c
    ${CMAKE_CURRENT_LIST_DIR}/src/sec/sks.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fs/lf_policy.c
    ${CMAKE_CURRENT_LIST_DIR}/src/crypto/lf_25519.c
)
# Ed25519 / X25519 of src/crypto/lf_25519.c (no EdDSA mbedTLS fork needed),
# included as "crypto/lf_25519.h" (src/ is an include directory everywhere).
add_definitions(-DLF_HAVE_25519=1)

# ESP32 and the emulator use the resilient multi-profile store, RP2 targets
# the single journaled store.
if(ESP_PLATFORM OR ENABLE_EMULATION)
    set(PICO_KEYS_SOURCES ${PICO_KEYS_SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/low_flash_v2.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/lf_region.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/lf_store.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/lf_sys.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/lf_boot.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/lf_backup.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/lf_profile.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/lf_mgmt.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/lf_keyio.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/lf_fw.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/rs.c
    )
else()
    set(PICO_KEYS_SOURCES ${PICO_KEYS_SOURCES} ${CMAKE_CURRENT_LIST_DIR}/src/fs/low_flash.c)
endif()

if(ESP_PLATFORM)
    set(PICO_KEYS_SOURCES ${PICO_KEYS_SOURCES} ${CMAKE_CURRENT_LIST_DIR}/src/led/led_neopixel.c)
else()
  if (NOT ENABLE_EMULATION)
    set(PICO_KEYS_SOURCES ${PICO_KEYS_SOURCES}
      ${CMAKE_CURRENT_LIST_DIR}/src/led/led_cyw43.c
      ${CMAKE_CURRENT_LIST_DIR}/src/led/led_pico.c
      ${CMAKE_CURRENT_LIST_DIR}/src/led/led_pimoroni.c
      ${CMAKE_CURRENT_LIST_DIR}/src/led/led_ws2812.c
    )
  endif()
endif()

## mbedTLS reports an stringop overflow for cmac.c
if(NOT ENABLE_EMULATION AND NOT APPLE)
    set_source_files_properties(
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/cmac.c
        PROPERTIES
        COMPILE_FLAGS "-Wno-error=stringop-overflow= -Wno-stringop-overflow"
    )
endif()
set(INCLUDES ${INCLUDES}
    ${CMAKE_CURRENT_LIST_DIR}/src
    ${CMAKE_CURRENT_LIST_DIR}/src/usb
    ${CMAKE_CURRENT_LIST_DIR}/src/fs
    ${CMAKE_CURRENT_LIST_DIR}/src/rng
    ${CMAKE_CURRENT_LIST_DIR}/src/led
    ${CMAKE_CURRENT_LIST_DIR}/src/sec
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/include
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library
)

if(USB_ITF_HID)
    set(MBEDTLS_SOURCES ${MBEDTLS_SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/x509write_crt.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/x509_create.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/x509write_csr.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pk.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pk_wrap.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/pkwrite.c
    )

endif()

    set(CBOR_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/tinycbor/src/cborencoder.c
        ${CMAKE_CURRENT_LIST_DIR}/tinycbor/src/cborparser.c
        ${CMAKE_CURRENT_LIST_DIR}/tinycbor/src/cborparser_dup_string.c
        # cbor_value_validate(): requests are checked before they are parsed
        ${CMAKE_CURRENT_LIST_DIR}/tinycbor/src/cborvalidation.c
    )

    set(INCLUDES ${INCLUDES}
        ${CMAKE_CURRENT_LIST_DIR}/tinycbor/src
    )
set(LIBRARIES
    mbedtls
)

if (NOT ESP_PLATFORM)
    add_library(mbedtls STATIC ${MBEDTLS_SOURCES})
    target_include_directories(mbedtls PUBLIC ${CMAKE_CURRENT_LIST_DIR}/mbedtls/include)
    if(USB_ITF_HID)
        add_library(tinycbor STATIC ${CBOR_SOURCES})
        target_include_directories(tinycbor PUBLIC ${CMAKE_CURRENT_LIST_DIR}/tinycbor/src)
        # Bound recursion in cbor_value_advance() (hostile nesting depth).
        target_compile_definitions(tinycbor PRIVATE CBOR_PARSER_MAX_RECURSIONS=16)
        set(LIBRARIES ${LIBRARIES} tinycbor)
    endif()
endif()

if (PICO_PLATFORM)
    list(APPEND LIBRARIES
        pico_stdlib
        pico_multicore
        pico_rand
        pico_aon_timer
        hardware_flash
        pico_unique_id
        tinyusb_device
        tinyusb_board
        hardware_pio
    )
endif()

if (ENABLE_PQC)
    list(APPEND LIBRARIES
        mlkem512
        mlkem768
        mlkem1024
    )
endif()

set(IS_CYW43 0)
if (PICO_PLATFORM)
    file(READ ${PICO_SDK_PATH}/src/boards/include/boards/${PICO_BOARD}.h content)
    string(REGEX MATCHALL "CYW43_WL_GPIO_LED_PIN" _ ${content})
    if (CMAKE_MATCH_0)
        message(STATUS "Found cyw43 LED:\t\t true")
        set(LIBRARIES ${LIBRARIES} pico_cyw43_arch_none)
        set(IS_CYW43 1)
    endif()
endif()

function(add_impl_library target)
    add_library(${target} INTERFACE)
    string(TOUPPER ${target} TARGET_UPPER)
    target_compile_definitions(${target} INTERFACE LIB_${TARGET_UPPER}=1)
endfunction()

if(USB_ITF_HID)
    set(PICO_KEYS_SOURCES ${PICO_KEYS_SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/hid/hid.c
    )
    set(INCLUDES ${INCLUDES}
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/hid
    )
endif()

if(USB_ITF_CCID)
    set(PICO_KEYS_SOURCES ${PICO_KEYS_SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/ccid/ccid.c
    )
    set(INCLUDES ${INCLUDES}
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/ccid
    )
endif()

if(NOT MSVC)
add_definitions("-fmacro-prefix-map=${CMAKE_CURRENT_LIST_DIR}/=")
endif()
if(MSVC)
    set(PICO_KEYS_SOURCES ${PICO_KEYS_SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/mman.c
    )
endif()
if(ENABLE_EMULATION)
    if(APPLE)
        add_definitions("-Wno-deprecated-declarations")
    endif()
    add_definitions(-DENABLE_EMULATION)
    set(PICO_KEYS_SOURCES ${PICO_KEYS_SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/emulation/emulation.c
    )
    set(MBEDTLS_SOURCES ${MBEDTLS_SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/aesni.c
    )
    set(INCLUDES ${INCLUDES}
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/emulation
    )
else()
    set(PICO_KEYS_SOURCES ${PICO_KEYS_SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/usb_descriptors.c
    )
endif()

if(MSVC)
    set(
        CMAKE_C_FLAGS
        "${CMAKE_C_FLAGS} -wd4820 -wd4255 -wd5045 -wd4706 -wd4061 -wd5105 -wd4141 -wd4200"
    )

    add_compile_definitions(_CRT_SECURE_NO_WARNINGS
        __STDC_WANT_SECURE_LIB__=0
        _WIN32_WINNT_WIN10_TH2=0
        _WIN32_WINNT_WIN10_RS1=0
        _WIN32_WINNT_WIN10_RS2=0
        _WIN32_WINNT_WIN10_RS3=0
        _WIN32_WINNT_WIN10_RS4=0
        _WIN32_WINNT_WIN10_RS5=0
        _STRALIGN_USE_SECURE_CRT=0
        NTDDI_WIN11_DT=0)
endif()

if(PICO_PLATFORM)
pico_sdk_init()
endif()

if(PICO_RP2350)
    pico_set_uf2_family(${CMAKE_PROJECT_NAME} "rp2350-arm-s")
    pico_embed_pt_in_binary(${CMAKE_PROJECT_NAME} "${CMAKE_CURRENT_LIST_DIR}/config/rp2350/pt.json")
    if (NOT IS_CYW43)
        pico_set_binary_type(${CMAKE_PROJECT_NAME} copy_to_ram)
    endif()
    if (SECURE_BOOT_PKEY)
        message(STATUS "Secure Boot Key ${SECURE_BOOT_PKEY}")
        pico_sign_binary(${CMAKE_PROJECT_NAME} ${SECURE_BOOT_PKEY})
        pico_hash_binary(${CMAKE_PROJECT_NAME})
    endif()
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE pico_bootrom)

    set(INCLUDES ${INCLUDES}
        ${CMAKE_CURRENT_LIST_DIR}/config/rp2350/alt
    )
    target_include_directories(mbedtls PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/config/rp2350/alt
    )
    target_link_libraries(mbedtls PRIVATE pico_sha256)
    set(PICO_KEYS_SOURCES ${PICO_KEYS_SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/config/rp2350/alt/sha256_alt.c
    )
    add_definitions(-DMBEDTLS_SHA256_ALT=1)
    set(LIBRARIES ${LIBRARIES} pico_sha256)
endif()
set(INTERNAL_SOURCES ${PICO_KEYS_SOURCES})

if(NOT TARGET pico_keys_sdk)
    if(PICO_PLATFORM)
        pico_add_library(pico_keys_sdk)

        target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${LIBRARIES})
    else()
        add_impl_library(pico_keys_sdk)
    endif()
    target_sources(pico_keys_sdk INTERFACE ${PICO_KEYS_SOURCES})
    target_include_directories(pico_keys_sdk INTERFACE ${INCLUDES})
    target_link_libraries(pico_keys_sdk INTERFACE ${LIBRARIES})
endif()
