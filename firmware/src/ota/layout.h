/*
 * Where things live in flash.
 *
 * Included by the loader, by the application and by the host tests, so there is exactly one
 * statement of the layout and a disagreement is a compile error rather than a device that boots
 * into the middle of an image.
 *
 *   0x000000  loader            64 KB   never replaced over the air
 *   0x010000  slot A           704 KB
 *   0x0C0000  slot B           704 KB
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

/* Firmware version strings are 16 bytes on the wire wherever they appear - in an image
 * header and in the state record - so the width lives here rather than in either. */
#define RW_OTA_VERSION_LEN 17 /* 16 plus a terminator */

#define RW_FLASH_XIP_BASE 0x10000000u
#define RW_FLASH_SECTOR   4096u

#define RW_LOADER_OFFSET (0u)
/*
 * 64 KB, which is more than the loader needs.
 *
 * The size is an alignment decision, not a capacity one: slot A has to begin on a 64 KB boundary
 * so that writing the loader cannot erase into it. Flashing a UF2 spanning both regions when
 * slot A began at 0x008000 left slot A erased, because the bootloader's erase granularity is
 * larger than the 4 KB sector it writes.
 */
#define RW_LOADER_SIZE   (64u * 1024u)

#define RW_SLOT_SIZE     (704u * 1024u)
#define RW_SLOT_A_OFFSET (RW_LOADER_OFFSET + RW_LOADER_SIZE)
#define RW_SLOT_B_OFFSET (RW_SLOT_A_OFFSET + RW_SLOT_SIZE)

/* The usable payload of a slot. The whole slot is available; the signed header is stripped
 * before anything is written. */
#define RW_SLOT_PAYLOAD_MAX RW_SLOT_SIZE

/*
 * Where an image's vector table sits within it, which is not the same on the two chips.
 *
 * An RP2040 image begins with the 256-byte second stage the ROM copies into RAM and runs to set
 * up XIP, and the vector table follows it. An RP2350 image has no such prologue — the ROM
 * configures XIP itself from the metadata block it finds in the image — so the table is the
 * first thing in the image.
 *
 * This is the address the loader hands the processor, and getting it wrong on one chip looks
 * exactly like a slot that was never written: the stack pointer read out of the middle of the
 * table is not in SRAM, the slot is judged unbootable, and the device falls back to the ROM
 * bootloader.
 */
#if defined(PICO_RP2350) && PICO_RP2350
#define RW_SLOT_VECTOR_OFFSET 0u
#else
#define RW_SLOT_VECTOR_OFFSET 0x100u
#endif

/* Two sectors immediately below the config pair (config_flash.h takes the top two). */
#define RW_OTA_STATE_B_OFFSET(flash_size) ((uint32_t)(flash_size) - 3u * RW_FLASH_SECTOR)
#define RW_OTA_STATE_A_OFFSET(flash_size) ((uint32_t)(flash_size) - 4u * RW_FLASH_SECTOR)

#define RW_SLOT_OFFSET(slot) ((slot) == 0 ? RW_SLOT_A_OFFSET : RW_SLOT_B_OFFSET)
#define RW_SLOT_XIP(slot)    (RW_FLASH_XIP_BASE + RW_SLOT_OFFSET(slot))

#endif /* RW_OTA_LAYOUT_H */
