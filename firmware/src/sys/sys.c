/*
 * Watchdog, uptime and reset reason. See sys.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "sys/sys.h"

#include "hardware/gpio.h"
#include "hardware/structs/io_qspi.h"
#include "hardware/structs/sio.h"
#include "hardware/sync.h"
#include "hardware/watchdog.h"
#include "pico/bootrom.h"
#include "pico/cyw43_arch.h"
#include "pico/time.h"

/* The power-on/brownout latch lives in a different peripheral on each chip. */
#if defined(PICO_RP2350) && PICO_RP2350
#include "hardware/structs/powman.h"
#else
#include "hardware/structs/vreg_and_chip_reset.h"
#endif

#include "rw_log.h"

static const char *s_reset_reason = "unknown";
static absolute_time_t s_boot_time;
static bool            s_network_ready;

void rw_sys_init(void) {
    s_boot_time = get_absolute_time();

    /*
     * Order matters. watchdog_enable() writes the scratch register that
     * watchdog_enable_caused_reboot() reads, so the reason has to be latched first or every
     * boot after the first one looks like a watchdog reset.
     */
    bool had_por = false;
    bool had_bor = false;

#if defined(PICO_RP2350) && PICO_RP2350
    const uint32_t chip_reset = powman_hw->chip_reset;
    had_por = (chip_reset & POWMAN_CHIP_RESET_HAD_POR_BITS) != 0;
    had_bor = (chip_reset & POWMAN_CHIP_RESET_HAD_BOR_BITS) != 0;
#else
    /*
     * RP2040 latches the same information in VREG_AND_CHIP_RESET, and has no separate brownout
     * bit — its brownout detector asserts the same power-on reset. So a brownout on RP2040
     * reports "power_on", which is the honest answer: the chip cannot tell us otherwise, and
     * inventing a distinction the silicon does not make would put a wrong word in a support
     * conversation.
     */
    const uint32_t chip_reset = vreg_and_chip_reset_hw->chip_reset;
    had_por = (chip_reset & VREG_AND_CHIP_RESET_CHIP_RESET_HAD_POR_BITS) != 0;
#endif

    if (had_por) {
        s_reset_reason = "power_on";
    } else if (had_bor) {
        s_reset_reason = "brownout";
    } else if (watchdog_enable_caused_reboot()) {
        /* Our own 8 s watchdog fired: the firmware hung. */
        s_reset_reason = "watchdog";
    } else if (watchdog_caused_reboot()) {
        /* watchdog_reboot() with a zero scratch magic — a deliberate restart from usbcfg. */
        s_reset_reason = "software";
    }

    watchdog_enable(RW_WATCHDOG_TIMEOUT_MS, false);
}

void rw_sys_feed_watchdog(void) {
    watchdog_update();
}

void rw_sys_set_network_ready(bool ready) {
    s_network_ready = ready;
}

void rw_sys_pump_ms(uint32_t ms) {
    absolute_time_t deadline = make_timeout_time_ms(ms);
    do {
        if (s_network_ready) {
            cyw43_arch_poll();
        }
        watchdog_update();
        /* One millisecond is short enough that lwIP's 250 ms TCP timer and the cyw43 driver's
         * interrupt-driven work are never starved, and long enough that this is not a spin. */
        sleep_ms(1);
    } while (!time_reached(deadline));
}

uint32_t rw_sys_uptime_s(void) {
    return (uint32_t)(absolute_time_diff_us(s_boot_time, get_absolute_time()) / 1000000);
}

const char *rw_sys_reset_reason(void) {
    return s_reset_reason;
}

void rw_sys_reboot(uint32_t delay_ms) {
    RW_LOG_INFO("rebooting in %lu ms", (unsigned long)delay_ms);
    /* A zero pc reboots down the normal flash path and leaves scratch[4] clear, which is what
     * makes the next boot report "software" rather than "watchdog". */
    watchdog_reboot(0, 0, delay_ms);
    while (true) {
        tight_loop_contents();
    }
}

/*
 * BOOTSEL is wired to the flash chip-select line, which is why reading it is not a GPIO read.
 *
 * The sequence disables the CS output driver, lets the line settle, samples it, and restores
 * the driver. For the duration, the flash cannot be addressed — so this function must execute
 * from RAM and must not be interrupted by anything that would fetch from XIP. Both are
 * enforced here rather than left to the caller.
 */
bool __no_inline_not_in_flash_func(rw_sys_bootsel_pressed)(void) {
    const uint cs_pin = 1; /* QSPI_SS */

    uint32_t irq = save_and_disable_interrupts();

    hw_write_masked(&io_qspi_hw->io[cs_pin].ctrl,
                    GPIO_OVERRIDE_LOW << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);

    /* The line is pulled up through the flash chip; it needs a moment to rise once the driver
     * is released. A fixed spin rather than a timer because the timer code lives in flash. */
    for (volatile int i = 0; i < 1000; i++) {
        (void)i;
    }

    bool pressed = (sio_hw->gpio_hi_in & (1u << cs_pin)) == 0;

    hw_write_masked(&io_qspi_hw->io[cs_pin].ctrl,
                    GPIO_OVERRIDE_NORMAL << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);

    restore_interrupts(irq);
    return pressed;
}

void rw_sys_reboot_to_bootloader(void) {
    RW_LOG_INFO("rebooting into the UF2 bootloader");
    /* Both interfaces enabled, no activity LED: mass storage for drag-and-drop UF2 and
     * PICOBOOT for tools that drive the device programmatically (usbcfg.md §1). */
    reset_usb_boot(0, 0);
    while (true) {
        tight_loop_contents();
    }
}
