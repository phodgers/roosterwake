/*
 * The slot probe: a program small enough to be obviously correct, whose only job is to say where
 * it is running from and to drive the state record by hand. See README.md.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>

#include "hardware/structs/scb.h"
#include "hardware/watchdog.h"
#include "pico/bootrom.h"
#include "pico/stdlib.h"

#include "brand.h"
#include "ota/layout.h"
#include "ota/ota.h"
#include "rw_log.h"

/* Reported alongside the slot so that two images flashed minutes apart are distinguishable in a
 * terminal, which is the whole difficulty of testing a thing that boots one of two copies of
 * itself. */
#ifndef RW_PROBE_TAG
#define RW_PROBE_TAG "?"
#endif

static char slot_letter(uint8_t slot) {
    return slot == RW_OTA_SLOT_B ? 'B' : 'A';
}

static void report(void) {
    const rw_ota_state_t *s    = rw_ota_state();
    uint8_t               here = rw_ota_running_slot();

    printf("\n"
           "probe %s  board=%s  fw=%s  flash=%u KB\n"
           "  running slot %c   xip=%08lx  main=%08lx  vtor=%08lx\n"
           "  record: seq=%lu active=%c fallback=%c trial=%u confirmed=%s version=%s\n",
           RW_PROBE_TAG, RW_BOARD_NAME, RW_FW_VERSION,
           (unsigned)(PICO_FLASH_SIZE_BYTES / 1024u), slot_letter(here),
           (unsigned long)RW_SLOT_XIP(here), (unsigned long)(uintptr_t)&report,
           (unsigned long)scb_hw->vtor, (unsigned long)s->seq, slot_letter(s->active),
           slot_letter(s->fallback), (unsigned)s->trial, s->confirmed ? "yes" : "no",
           s->version[0] ? s->version : "-");

    if (rw_ota_on_trial()) {
        printf("  ON TRIAL: %u boot(s) left, then the loader returns to slot %c\n",
               (unsigned)rw_ota_trials_left(), slot_letter(s->fallback));
    }
    printf("  keys: s state  c confirm  x stage the other slot  r reboot  b bootsel\n");
}

/*
 * A heartbeat on the boards that have an LED of their own.
 *
 * Only the plain Pico and Pico 2 define PICO_DEFAULT_LED_PIN; on the wireless boards the LED
 * hangs off the CYW43 chip, and reaching it would drag the whole radio driver into a program
 * whose value is that it does not need one.
 */
static void heartbeat(bool on) {
#ifdef PICO_DEFAULT_LED_PIN
    gpio_put(PICO_DEFAULT_LED_PIN, on);
#else
    (void)on;
#endif
}

static void handle(int key) {
    switch (key) {
        case 's':
            report();
            break;

        case 'c':
            rw_ota_confirm_running_image();
            report();
            break;

        case 'x': {
            uint8_t spare = rw_ota_spare_slot();
            printf("staging slot %c\n", slot_letter(spare));
            if (!rw_ota_stage_slot(spare, RW_FW_VERSION)) {
                printf("refused\n");
            }
            report();
            break;
        }

        case 'r':
            printf("rebooting\n");
            watchdog_reboot(0, 0, 0);
            break;

        case 'b':
            printf("entering the ROM bootloader\n");
            reset_usb_boot(0, 0);
            break;

        default:
            break;
    }
}

int main(void) {
    stdio_init_all();

#ifdef PICO_DEFAULT_LED_PIN
    gpio_init(PICO_DEFAULT_LED_PIN);
    gpio_set_dir(PICO_DEFAULT_LED_PIN, GPIO_OUT);
#endif

    /* The record is what the loader acted on, so it is worth seeing the same lines the firmware
     * would log about it. */
    rw_log_set_enabled(true);
    rw_ota_init();

    absolute_time_t next = get_absolute_time();
    bool            lit  = false;

    for (;;) {
        int key = getchar_timeout_us(250 * 1000);
        if (key != PICO_ERROR_TIMEOUT) {
            handle(key);
        }

        lit = !lit;
        heartbeat(lit);

        /* Repeated rather than printed once, because a USB serial port cannot be opened until
         * the device has enumerated and the first report is always missed. */
        if (absolute_time_diff_us(get_absolute_time(), next) <= 0) {
            report();
            next = make_timeout_time_ms(3000);
        }
    }
}
