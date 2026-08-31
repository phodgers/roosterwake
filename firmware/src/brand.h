/*
 * Brand and product constants.
 *
 * This header is the firmware half of a pair; the other half is cloud/shared/brand.js. Nothing
 * else in the firmware may hardcode a product name, a default relay URL, a setup SSID or the
 * WebSocket subprotocol. Renaming the product should be an edit to two files, not a grep across
 * a codebase, and a grep-and-replace rename is exactly the kind of change that leaves one
 * forgotten string literal in a captive portal title for a year.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_BRAND_H
#define RW_BRAND_H

#include <assert.h>

/* Display name. Used in the captive portal, the USB product string and log banners. */
#define RW_PRODUCT_NAME "Rooster Wake"

/*
 * USB descriptor strings (usbcfg.md §1). VID is Raspberry Pi's 0x2E8A, the SDK default.
 *
 * These two are also passed to the compiler as USBD_MANUFACTURER and USBD_PRODUCT from
 * CMakeLists.txt, because the SDK builds its descriptor table from macros rather than from a
 * header it includes. Change them here and there together; the assertion below is the reminder
 * that they are the same strings.
 */
#define RW_USB_MANUFACTURER "Rooster Wake"
#define RW_USB_PRODUCT      RW_PRODUCT_NAME

_Static_assert(sizeof(RW_USB_PRODUCT) <= 20,
               "USB string descriptors are capped at 20 characters by USBD_DESC_STR_MAX");

/*
 * Relay endpoint used when flash config carries no relay_url (PROTOCOL.md §1).
 *
 * This string is compiled in, and a device dials it forever unless reconfigured — so whatever
 * host it names has to keep resolving for the service life of every unit that ships with it.
 * Changing it after units are in the field means an OTA that travels over the OLD endpoint,
 * with the old host kept alive until the last device has taken the update.
 *
 * That cost was not paid here: the value moved from remotewake.com while the only two devices
 * that had ever used it were on a desk, and both were reflashed. The old host is gone. This is
 * the last moment that was free.
 */
#define RW_DEFAULT_RELAY_URL "wss://relay.roosterwake.com/ws"

/* Setup hotspot SSID is RW_SETUP_SSID_PREFIX "-XXXX", the four hex characters being the low
 * 16 bits of the device_id, so two dongles powered up in the same room are distinguishable. */
#define RW_SETUP_SSID_PREFIX "RoosterWake-Setup"
#define RW_SETUP_SSID_SUFFIX_LEN 5 /* '-' plus four hex digits */

/* IEEE 802.11 caps an SSID at 32 octets. A rename that overflows it produces a hotspot that
 * some clients show truncated and others do not show at all, which is a miserable thing to
 * diagnose in the field, so it is a compile error here instead. */
_Static_assert(sizeof(RW_SETUP_SSID_PREFIX) - 1 + RW_SETUP_SSID_SUFFIX_LEN <= 32,
               "setup SSID prefix leaves no room for the -XXXX suffix within 32 bytes");

/*
 * WebSocket subprotocol (PROTOCOL.md §1). A relay that does not echo this is not a relay.
 *
 * The token names the protocol family and does not track RW_PROTO_VERSION: a relay too old to
 * speak the version below has to be able to answer the socket and say so with close 4000, and
 * refusing the upgrade instead would tell the device it had reached something that is not a
 * Rooster Wake relay at all.
 */
#define RW_WS_SUBPROTOCOL "roosterwake.v1"

/* Wire protocol major version (PROTOCOL.md §10) and usbcfg protocol version (usbcfg.md §8). */
#define RW_PROTO_VERSION  2
#define RW_USBCFG_VERSION 2

/* Firmware version reported in `hello`, `status_result` and `INFO`. */
#define RW_FW_VERSION "2.6.1"

/*
 * Board identifier reported in `hello` (PROTOCOL.md §4) and `INFO` (usbcfg.md §4).
 *
 * Derived, not written down. This value is how a support conversation establishes which chip is
 * in front of it, and a device that reports the wrong board is worse than one that reports
 * nothing — the two differ in flash size, in where the config lives, and in whether the
 * randomness behind TLS comes from a hardware TRNG.
 */
#if defined(PICO_RP2350) && PICO_RP2350
#define RW_BOARD_NAME "pico2_w"
#else
#define RW_BOARD_NAME "pico_w"
#endif

/*
 * Capabilities advertised in `hello` (PROTOCOL.md §4). Each one gates a relay→device command,
 * and a relay must not send a command whose capability is absent, so this list is the single
 * place that decides what this build will be asked to do:
 *
 *   wake   -> `wake`          status -> `status`
 *   probe  -> `probe`         scan   -> `scan`
 *   ota    -> `ota_offer`     plug   -> `plug_scan`, `plug_set`, `plug_status`
 *   plugfw -> `plug_fw_check`, `plug_fw_update`
 *
 * `plugfw` is deliberately its own capability rather than a fourth frame under `plug`: every
 * `plug` build released before the firmware verbs existed would otherwise be sent a question
 * it silently ignores, and a capability refusal is the clean answer an old actor gives.
 *
 * `sched` is reserved by the protocol and has no command yet, so it is not advertised. There
 * is no `log` capability: diagnostics are enabled locally and no frame can turn them on.
 */
#define RW_CAPS_JSON "[\"wake\",\"status\",\"probe\",\"scan\",\"ota\",\"plug\",\"plugfw\"]"

#endif /* RW_BRAND_H */
