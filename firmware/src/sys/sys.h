/*
 * Watchdog, uptime and reset reason.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_SYS_H
#define RW_SYS_H

#include <stdbool.h>
#include <stdint.h>

/*
 * Watchdog period. Long enough that a slow DNS lookup, a TLS handshake on a congested link or
 * a 4 KB flash program never trip it, short enough that a wedged device recovers before anyone
 * gets as far as reaching behind the router. Every blocking path in this firmware either
 * completes well inside this or pumps through rw_sys_pump_ms(), which feeds it.
 */
#define RW_WATCHDOG_TIMEOUT_MS 8000

/* Start the watchdog and latch the reset reason. Call once, first thing in main(). */
void rw_sys_init(void);

/* Feed the watchdog. Called from the main loop and from every pumping wait. */
void rw_sys_feed_watchdog(void);

/*
 * Wait `ms` while keeping the system alive: polls the network stack (once it exists) and feeds
 * the watchdog. Used by the WoL burst gap and anywhere else a real delay is unavoidable.
 *
 * Nothing in this firmware may call sleep_ms() directly for more than a few milliseconds. In a
 * poll-mode lwIP build a plain sleep is a period during which no packet is processed and no
 * TCP timer runs, and the symptom of getting that wrong is a connection that dies once a day.
 */
void rw_sys_pump_ms(uint32_t ms);

/* Announce that cyw43_arch is up, so rw_sys_pump_ms() may poll it. */
void rw_sys_set_network_ready(bool ready);

/* Seconds since boot. Wraps after 136 years, which is not our problem. */
uint32_t rw_sys_uptime_s(void);

/*
 * Bytes of C heap not currently allocated.
 *
 * Reported because this device's hardest resource limit is RAM, not flash or CPU, and the way it
 * bites is invisible: a TLS session needs its record buffers in one contiguous piece, so the
 * connection simply never forms and every layer above reports something vaguer than "no memory".
 * A number here turns that into a fact somebody can act on.
 *
 * This is free heap, not the largest free block, so it is an upper bound on what an allocation
 * can get. Fragmentation makes the real figure smaller and nothing here can see it.
 */
uint32_t rw_sys_heap_free(void);

/*
 * Why the device last restarted, as one of: "power_on", "brownout", "watchdog", "software",
 * "unknown". Reported in `status_result` (PROTOCOL.md §4) and `INFO` (usbcfg.md §4).
 *
 * "watchdog" versus "software" is the distinction that matters: the first means this firmware
 * hung, the second means somebody asked for a reboot.
 */
const char *rw_sys_reset_reason(void);

/* Reboot after `delay_ms`, so a usbcfg response reaches the host before the port disappears. */
void rw_sys_reboot(uint32_t delay_ms);

/* Reboot into the RP2350 UF2 bootloader (usbcfg.md §4, BOOTSEL). Does not return. */
void rw_sys_reboot_to_bootloader(void);

/*
 * Whether the BOOTSEL button is held.
 *
 * The board has no other button, so this is the only physical input a user has, and
 * config-format.md §8 makes holding it for five seconds at power-on the factory reset. Reading
 * it means briefly driving the flash chip-select line as an input, which is why the
 * implementation runs from RAM with interrupts off.
 */
bool rw_sys_bootsel_pressed(void);

#endif /* RW_SYS_H */
