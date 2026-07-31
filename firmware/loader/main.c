/*
 * The loader: decide which slot to boot, and enter it.
 *
 * Lives in the first 64 KB of flash and is the only thing an over-the-air update never replaces.
 * It has no USB, no radio and no diagnostics — the LED on both supported boards hangs off the
 * CYW43 chip, so lighting it would mean linking the whole Wi-Fi driver into the one component
 * that must stay small and must always work. What it decided is recoverable afterwards from the
 * state record, which the application reports.
 *
 * Everything here runs before the application's own start-up, so it deliberately does as little
 * as possible: read two sectors, pick one of two addresses, jump.
 *
 * SPDX-License-Identifier: MIT
 */
#include <string.h>

#include "hardware/flash.h"
#include "hardware/irq.h"
#include "hardware/resets.h"
#include "hardware/structs/nvic.h"
#include "hardware/structs/scb.h"
#include "hardware/sync.h"
#include "pico/bootrom.h"
#include "pico/stdlib.h"

#include "ota/layout.h"
#include "ota/state.h"

/*
 * An image begins with 256 bytes the ROM bootloader would use as its second stage, and the
 * vector table follows. Only the copy at the very start of flash — this loader's — is ever
 * executed as a second stage; the one at the head of each slot is inert padding, and the address
 * the processor has to be given is the vector table after it.
 */
#define SLOT_VECTOR_OFFSET 0x100u

static const uint8_t *state_sector(uint32_t offset) {
    return (const uint8_t *)(uintptr_t)(RW_FLASH_XIP_BASE + offset);
}

/*
 * Is there something at this address that could plausibly be entered?
 *
 * The stack pointer must land in SRAM and the reset vector inside the slot itself, with the
 * Thumb bit set. An erased slot reads as 0xFFFFFFFF and fails all three, which is the case that
 * matters: a device whose second slot has never been written must not be jumped into because a
 * state record said so.
 */
static bool slot_bootable(uint8_t slot) {
    uint32_t        base = RW_SLOT_XIP(slot);
    const uint32_t *vt   = (const uint32_t *)(uintptr_t)(base + SLOT_VECTOR_OFFSET);
    uint32_t        sp   = vt[0];
    uint32_t        pc   = vt[1];

    if (sp < SRAM_BASE || sp > SRAM_END) {
        return false;
    }
    if (pc < base || pc >= base + RW_SLOT_SIZE) {
        return false;
    }
    return (pc & 1u) != 0u;
}

static void persist(const rw_ota_state_t *s) {
    uint8_t page[FLASH_PAGE_SIZE];
    memset(page, 0, sizeof(page));
    if (rw_ota_state_encode(s, page, sizeof(page)) == 0) {
        return;
    }

    /*
     * Written to both sectors, oldest first is not possible to know here, so both are refreshed.
     * The sequence number in each copy is what makes a torn write survivable: whichever sector
     * was mid-erase when the power went reads as invalid, and the other still carries a record.
     */
    const uint32_t offsets[2] = {
        RW_OTA_STATE_A_OFFSET(PICO_FLASH_SIZE_BYTES),
        RW_OTA_STATE_B_OFFSET(PICO_FLASH_SIZE_BYTES),
    };
    for (int i = 0; i < 2; i++) {
        uint32_t ints = save_and_disable_interrupts();
        flash_range_erase(offsets[i], RW_FLASH_SECTOR);
        flash_range_program(offsets[i], page, FLASH_PAGE_SIZE);
        restore_interrupts(ints);
    }
}

static void __attribute__((noreturn)) enter_slot(uint8_t slot) {
    uint32_t        vt_addr = RW_SLOT_XIP(slot) + SLOT_VECTOR_OFFSET;
    const uint32_t *vt      = (const uint32_t *)(uintptr_t)vt_addr;
    uint32_t        sp      = vt[0];
    uint32_t        pc      = vt[1];

    /*
     * Put USB back in reset before handing over.
     *
     * The ROM bootloader has the device enumerated when it hands control here, and the
     * diagnostic build brings it up again to report. Either way the application initialises USB
     * from scratch and an interrupt left live would fire into its vector table carrying somebody
     * else's state. Holding the peripheral in reset is the one teardown that cannot half-work.
     */
    irq_set_enabled(USBCTRL_IRQ, false);
    reset_block(RESETS_RESET_USBCTRL_BITS);

    /*
     * Hand over a machine in the state a reset would have left: no interrupt enabled, none
     * pending, and PRIMASK clear.
     *
     * The last of those is not optional. The SDK's start-up code does not unmask interrupts —
     * after a reset it has no reason to, because PRIMASK is already clear — so an application
     * entered with them masked runs its initialisation, reaches its main loop, and sits there
     * with no timer and no USB. It looks exactly like a dead board.
     */
    __asm volatile("cpsid i" ::: "memory");
#if defined(PICO_RP2350) && PICO_RP2350
    for (unsigned i = 0; i < 2; i++) {
        nvic_hw->icer[i] = 0xFFFFFFFFu;
        nvic_hw->icpr[i] = 0xFFFFFFFFu;
    }
#else
    nvic_hw->icer = 0xFFFFFFFFu;
    nvic_hw->icpr = 0xFFFFFFFFu;
#endif

    scb_hw->vtor = vt_addr;

    /* Nothing can fire now: every source is disabled and the pending bits are clear. */
    __asm volatile("cpsie i" ::: "memory");

#if defined(PICO_RP2350) && PICO_RP2350
    /* The stack limit register must be cleared before the stack pointer moves, or the first push
     * in the application faults against a limit that belonged to this program. */
    __asm volatile("msr msplim, %0" : : "r"(0u));
#endif

    __asm volatile(
        "msr msp, %0\n"
        "bx  %1\n"
        :
        : "r"(sp), "r"(pc)
        : "memory");
    __builtin_unreachable();
}

#ifdef RW_LOADER_DIAG
#include <stdio.h>

static void report(const char *what, uint8_t slot) {
    uint32_t        base = RW_SLOT_XIP(slot);
    const uint32_t *vt   = (const uint32_t *)(uintptr_t)(base + SLOT_VECTOR_OFFSET);
    printf("# loader %s slot %u base=%08lx sp=%08lx pc=%08lx bootable=%d\n", what,
           (unsigned)slot, (unsigned long)base, (unsigned long)vt[0], (unsigned long)vt[1],
           (int)slot_bootable(slot));
}
#endif

int main(void) {
    rw_ota_state_t s;

    bool have = rw_ota_state_pick(state_sector(RW_OTA_STATE_A_OFFSET(PICO_FLASH_SIZE_BYTES)),
                                  RW_OTA_STATE_LEN,
                                  state_sector(RW_OTA_STATE_B_OFFSET(PICO_FLASH_SIZE_BYTES)),
                                  RW_OTA_STATE_LEN, &s);

    if (!have) {
        /* Never updated, or the records were lost. Slot A is where a factory image goes, and
         * nothing is written: a device that boots fine has no reason to start writing flash. */
        rw_ota_state_default(&s, "");
    } else {
        bool write_back = false;
        rw_ota_state_on_boot(&s, &write_back);
        if (write_back) {
            persist(&s);
        }
    }

#ifdef RW_LOADER_DIAG
    stdio_init_all();
    for (int i = 0; i < 30; i++) {
        printf("# loader state: have=%d active=%u fallback=%u trial=%u confirmed=%d sram=%08lx..%08lx\n",
               (int)have, (unsigned)s.active, (unsigned)s.fallback, (unsigned)s.trial,
               (int)s.confirmed, (unsigned long)SRAM_BASE, (unsigned long)SRAM_END);
        report("A", RW_OTA_SLOT_A);
        report("B", RW_OTA_SLOT_B);
        sleep_ms(500);
    }
#endif

    if (!slot_bootable(s.active)) {
        /*
         * The record points at a slot with nothing in it. That should not happen — the
         * application only stages a slot it has written and verified — but the cost of being
         * wrong is a device that does not start, so the other slot is tried regardless of what
         * the record says.
         */
        uint8_t other = rw_ota_other_slot(s.active);
        if (slot_bootable(other)) {
            enter_slot(other);
        }
        /*
         * Neither slot holds an image. Sitting in a loop would look identical to a dead board,
         * so the ROM bootloader is entered instead: the device appears as a drive and can be
         * recovered by dropping a UF2 on it, which is the recovery path this whole design keeps
         * open on purpose.
         */
        reset_usb_boot(0, 0);
    }

    enter_slot(s.active);
}
