/*
 * Reserve the two configuration sectors at the top of flash.
 *
 * config-format.md section 1 puts slot A at 0x3FE000 and slot B at 0x3FF000, and says the
 * firmware image is linked to stay below them, with the build failing if it does not. This
 * file is that failure: a linker assertion, not a runtime check, because discovering the
 * overlap at runtime means discovering it in a customer's hands, after the image has already
 * erased their Wi-Fi password by being programmed over it.
 *
 * Supplied as an additional -T script. GNU ld concatenates every -T script into one linker
 * script, so this appends to the SDK's memmap without replacing it - which matters, because
 * vendoring a copy of the SDK's memmap would silently go stale on the next SDK update, and the
 * symptom would be a subtly wrong image rather than a build error.
 *
 * ASCII only, and no byte-order mark. GNU ld reports a BOM as "ignoring invalid character" and
 * carries on, which would leave the assertion in place but the file looking broken.
 *
 * __flash_binary_end is provided by the SDK's memmap_default.ld.
 *
 * Verified negatively: lowering the constant makes the link fail with the message below.
 *
 * SPDX-License-Identifier: MIT
 */

ASSERT(__flash_binary_end <= 0x103FE000,
       "firmware image overlaps the configuration sectors at 0x3FE000 - see firmware/docs/config-format.md")
