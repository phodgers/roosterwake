/*
 * Where things live in flash.
 *
 * Included by the loader, by the application and by the host tests, so there is exactly one
 * statement of the layout and a disagreement is a compile error rather than a device that boots
 * into the middle of an image.
 *
 *   0x000000  loader            32 KB   never replaced over the air
 *   0x008000  slot A           704 KB
 *   0x0B8000  slot B           704 KB
 *             (spare)                   room for both slots to grow
 *   top-16 KB ota state A        4 KB   two copies, higher sequence wins
 *   top-12 KB ota state B        4 KB
 *   top-8 KB  config A           4 KB   config_flash.h owns these two
 *   top-4 KB  config B           4 KB
 *
 * Both boards use identical slot offsets. The Pico 2 W has twice the flash and could hold more,
 * but one layout means one linker script per slot instead of one per slot per board, and the
 * spare on the smaller part is already larger than the image.
 *
 * An image is linked to run at the slot it occupies, because XIP executes in place. That is why
 * a release builds each board twice, and why nothing is ever copied between slots: the update
 * writes the slot the device is not running from, and the loader changes which one it enters.
 * There is no moment when neither slot is bootable.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_OTA_LAYOUT_H
#define RW_OTA_LAYOUT_H

#define RW_FLASH_XIP_BASE 0x10000000u
#define RW_FLASH_SECTOR   4096u

#define RW_LOADER_OFFSET (0u)
#define RW_LOADER_SIZE   (32u * 1024u)

#define RW_SLOT_SIZE     (704u * 1024u)
#define RW_SLOT_A_OFFSET (RW_LOADER_OFFSET + RW_LOADER_SIZE)
#define RW_SLOT_B_OFFSET (RW_SLOT_A_OFFSET + RW_SLOT_SIZE)

/* The usable payload of a slot. The image starts with its vector table at the slot's first byte,
 * so the whole slot is available; the signed header is stripped before anything is written. */
#define RW_SLOT_PAYLOAD_MAX RW_SLOT_SIZE

/* Two sectors immediately below the config pair (config_flash.h takes the top two). */
#define RW_OTA_STATE_B_OFFSET(flash_size) ((uint32_t)(flash_size) - 3u * RW_FLASH_SECTOR)
#define RW_OTA_STATE_A_OFFSET(flash_size) ((uint32_t)(flash_size) - 4u * RW_FLASH_SECTOR)

#define RW_SLOT_OFFSET(slot) ((slot) == 0 ? RW_SLOT_A_OFFSET : RW_SLOT_B_OFFSET)
#define RW_SLOT_XIP(slot)    (RW_FLASH_XIP_BASE + RW_SLOT_OFFSET(slot))

#endif /* RW_OTA_LAYOUT_H */
