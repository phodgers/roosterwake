/*
 * Remote Wake firmware entry point.
 *
 * One thread, one loop, no allocation after start-up. Everything that can block is either
 * bounded and pumped (rw_sys_pump_ms) or deferred to this loop by the layer that received it.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <string.h>

#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"
#include "pico/unique_id.h"

#include "brand.h"
#include "config/config.h"
#include "config/config_flash.h"
#include "led/led.h"
#include "net/arplearn.h"
#include "net/net.h"
#include "proto/auth.h"
#include "proto/proto.h"
#include "provisioning/provisioning.h"
#include "rw_log.h"
#include "sys/sys.h"
#include "sys/wallclock.h"
#include "tls/tls.h"
#include "usbcfg/usbcfg.h"

/* config-format.md §8: hold BOOTSEL for five seconds at power-on. Sampled after the watchdog
 * is running, so a user holding the button does not trip it. */
#define FACTORY_RESET_HOLD_MS 5000

/* The loop never blocks longer than this, so timers, the keepalive and the watchdog all stay
 * responsive without spinning the core flat out. */
#define LOOP_SLICE_MS 10

/* How often to retry a radio that did not initialise. Long enough not to thrash the SPI bus,
 * short enough that a transient power-up fault clears itself while somebody is still watching. */
#define RADIO_RETRY_MS 10000

static rw_config_t s_config;

/*
 * Persist a configuration the relay pushed. Called from proto's deferred command execution,
 * which runs on this loop — never from inside a network callback, because this erases a flash
 * sector with interrupts off and the second core locked out.
 */
static bool save_config_hook(rw_config_t *cfg) {
    rw_flash_status_t st = rw_config_flash_save(cfg);
    if (st != RW_FLASH_OK) {
        RW_LOG_ERROR("config: save failed (%d)", (int)st);
        return false;
    }
    return true;
}

static void wake_sent_hook(void) {
    rw_led_wake_sent();
}

static const rw_relay_hooks_t k_relay_hooks = {
    .save_config  = save_config_hook,
    .on_wake_sent = wake_sent_hook,
};

/*
 * Derive the device_id from the board's unique flash ID.
 *
 * PROTOCOL.md §2 requires it to be stable for the life of the device and to survive a factory
 * reset, which rules out anything stored in the config sectors. The flash ID is 8 bytes and
 * per-part, which is exactly the shape the protocol asks for.
 */
static void derive_device_id(char *out) {
    pico_unique_board_id_t id;
    pico_get_unique_board_id(&id);
    rw_hex_encode(id.id, 8, out);
}

/*
 * Enough configuration to join Wi-Fi and stop being a setup hotspot.
 *
 * Deliberately does **not** require a token. Joining a network and authenticating to a relay are
 * two different capabilities, and conflating them meant a device provisioned through the captive
 * portal — which has no way to obtain a token — rebooted into setup mode for ever, having
 * apparently saved everything correctly. A device with credentials and no token now joins the
 * network and simply does not reach the relay, which is a state the dashboard and the LED can
 * both describe honestly.
 */
static bool is_provisioned(const rw_config_t *cfg) {
    return cfg->ssid[0] != '\0' && cfg->device_id[0] != '\0';
}

static void check_factory_reset(void) {
    if (!rw_sys_bootsel_pressed()) {
        return;
    }

    RW_LOG_WARN("hold BOOTSEL for %d ms to factory reset", FACTORY_RESET_HOLD_MS);
    absolute_time_t deadline = make_timeout_time_ms(FACTORY_RESET_HOLD_MS);
    while (!time_reached(deadline)) {
        if (!rw_sys_bootsel_pressed()) {
            return; /* released early: not a reset */
        }
        rw_sys_feed_watchdog();
        rw_led_task();
        sleep_ms(20);
    }

    RW_LOG_WARN("factory reset: erasing both config slots");
    rw_led_set(RW_LED_ERROR);
    if (rw_config_flash_factory_reset() != RW_FLASH_OK) {
        RW_LOG_ERROR("factory reset failed");
        return;
    }
    /* Confirmed by two seconds of solid LED, then a reboot into the unprovisioned state. */
    rw_led_wake_sent();
    for (int i = 0; i < 100; i++) {
        rw_led_task();
        rw_sys_feed_watchdog();
        sleep_ms(20);
    }
    rw_sys_reboot(100);
}

/* Pick the LED pattern that matches what the device is actually doing. */
static void update_led(bool provisioned) {
    if (rw_tls_insecure()) {
        /* PROTOCOL.md §1.1: the error pattern runs continuously while verification is off, so
         * a device left in that state is visibly wrong from across the room rather than
         * quietly wrong for a year. */
        rw_led_set(RW_LED_ERROR);
        return;
    }
    if (!provisioned) {
        rw_led_set(RW_LED_SETUP_AP);
        return;
    }

    switch (rw_relay_state()) {
        case RW_RELAY_READY:
            rw_led_set(RW_LED_CONNECTED);
            return;
        case RW_RELAY_AUTH_FAILED:
        case RW_RELAY_STOPPED:
            /* §3.3: a device that silently retries against a relay that cannot prove it holds
             * our token is worse than one that visibly fails. */
            rw_led_set(RW_LED_ERROR);
            return;
        case RW_RELAY_OFFLINE:
        case RW_RELAY_BACKOFF:
        case RW_RELAY_CONNECTING:
        case RW_RELAY_AUTHENTICATING:
            /*
             * Split on whether Wi-Fi is up. Both halves used to show the joining blink, so an
             * owner could not tell "still trying to reach your router" from "on your network,
             * just not linked to the cloud" — and the second is a normal, working state for a
             * self-hosted or unclaimed device, in which local Wake-on-LAN is fine.
             */
            rw_led_set(rw_net_state() == RW_NET_JOINED ? RW_LED_ONLINE : RW_LED_JOINING);
            return;
    }
    rw_led_set(RW_LED_JOINING);
}

int main(void) {
    rw_sys_init();
    stdio_init_all();

    if (!rw_config_flash_load(&s_config)) {
        rw_config_init(&s_config);
    }

    /*
     * Diagnostics are opt-in (usbcfg.md §7). Set before anything else logs, so a device with
     * the flag on captures its own start-up.
     *
     * RW_FORCE_DIAG_LOG overrides the flag at build time. It exists because the config flag is
     * unreachable on a device that has no configuration yet — which is precisely the state
     * setup mode runs in, and therefore precisely the state whose logs are hardest to get.
     */
#ifdef RW_FORCE_DIAG_LOG
    rw_log_set_enabled(true);
#else
    rw_log_set_enabled((s_config.flags & RW_CFG_FLAG_DIAG_LOG) != 0);
#endif

    RW_LOG_INFO("%s %s (%s), reset reason %s", RW_PRODUCT_NAME, RW_FW_VERSION, RW_BOARD_NAME,
                rw_sys_reset_reason());

    /*
     * The device_id is derived, not stored. A config image written by mkconfig may carry one;
     * if it disagrees with this board's unique ID the derived value wins, because the relay
     * identifies the device by something the device cannot change and a mismatched image would
     * otherwise let one board impersonate another.
     */
    char derived[RW_DEVICE_ID_HEX + 1];
    derive_device_id(derived);
    if (strcmp(s_config.device_id, derived) != 0) {
        if (s_config.device_id[0] != '\0') {
            RW_LOG_WARN("config: device_id %s does not match this board; using %s",
                        s_config.device_id, derived);
        }
        snprintf(s_config.device_id, sizeof(s_config.device_id), "%s", derived);
    }

    /*
     * The radio may fail to come up: a bad board, a brownout during the firmware load, or a
     * CYW43 that did not answer. That used to spin here on a loop that fed no watchdog, so the
     * device rebooted every eight seconds for ever — and USB never stayed enumerated long
     * enough to ask it why. The one channel that does not depend on the radio was unusable
     * exactly when it was the only channel left.
     *
     * So a radio failure is now survivable. The main loop runs, usbcfg answers INFO and STATUS
     * over USB, and the radio is retried in the background. The LED cannot help here whatever
     * we do — it hangs off the CYW43 chip that just failed — so nothing pretends otherwise.
     */
    bool            radio_ok    = rw_net_init();
    absolute_time_t radio_retry = make_timeout_time_ms(RADIO_RETRY_MS);
    if (radio_ok) {
        rw_led_init();
    } else {
        RW_LOG_ERROR("radio: cyw43 did not initialise; USB configuration only, retrying");
    }

    check_factory_reset();

    if (!rw_tls_init((s_config.flags & RW_CFG_FLAG_TLS_INSECURE) != 0)) {
        RW_LOG_ERROR("tls: initialisation failed");
        rw_led_set(RW_LED_ERROR);
    }

    rw_relay_init(&s_config, &k_relay_hooks);
    rw_usbcfg_init(&s_config);

    const bool provisioned = radio_ok && is_provisioned(&s_config);
    if (!radio_ok) {
        /* Nothing below this point can run without a radio. Fall straight into the loop, where
         * usbcfg still answers and the retry lives. */
    } else if (provisioned) {
        RW_LOG_INFO("config: seq %lu, %u target(s), relay %s", (unsigned long)s_config.seq,
                    s_config.target_count,
                    s_config.relay_url[0] ? s_config.relay_url : RW_DEFAULT_RELAY_URL);
        rw_net_start(s_config.ssid, s_config.psk, s_config.wifi_auth);
        rw_relay_start();
    } else {
        /*
         * Unprovisioned: bring up the setup hotspot and its captive portal, so a person with
         * nothing but a phone can get the device onto their network. The usbcfg channel and a
         * config UF2 from tools/mkconfig remain available in parallel — all three paths write
         * the same record, and whichever completes first wins.
         */
        RW_LOG_WARN("unprovisioned: starting setup mode");
        if (!rw_provisioning_start(&s_config)) {
            /* No hotspot means no over-the-air setup at all. Say so on the LED rather than
             * sitting there looking like a device that is merely waiting. */
            RW_LOG_ERROR("setup mode failed to start; USB configuration only");
            rw_led_set(RW_LED_ERROR);
        }
    }

    while (true) {
        /* Poll mode: this is the only place lwIP and the cyw43 driver run, so every callback
         * they raise lands on this context. That is what lets the TLS and WebSocket state
         * machines be written without re-entrancy guards. */
        if (radio_ok) {
            cyw43_arch_poll();
        }
        rw_sys_feed_watchdog();

        /* Serviced first, and unconditionally: a device that has wedged its relay session — or
         * never got a radio at all — is exactly the device someone plugs into a laptop to ask
         * what is wrong, and the answer has to still arrive. */
        rw_usbcfg_task();

        /*
         * Once a COMMIT, REBOOT or FACTORY_RESET has been acknowledged the device has under a
         * second to live. Starting a TLS handshake or a flash write in that window achieves
         * nothing and risks being interrupted half-way, so the loop coasts on the LED alone.
         */
        if (radio_ok && !rw_usbcfg_reboot_pending()) {
            rw_net_task();
            rw_arp_learn_tick();
            rw_relay_task();
            rw_provisioning_task();
        }

        if (!radio_ok && time_reached(radio_retry)) {
            /* Retry rather than reboot. A reboot loop takes USB down with it, and USB is the
             * only way anyone can find out what is wrong with a device whose radio is dead. */
            RW_LOG_WARN("radio: retrying cyw43 initialisation");
            radio_ok = rw_net_init();
            if (radio_ok) {
                RW_LOG_INFO("radio: came up on retry; rebooting into the normal path");
                rw_sys_reboot(100);
            }
            radio_retry = make_timeout_time_ms(RADIO_RETRY_MS);
        }

        if (radio_ok) {
            update_led(provisioned);
            rw_led_task();
        }

        if (radio_ok) {
            /* Sleeps until the driver has work or the slice expires, whichever comes first. */
            cyw43_arch_wait_for_work_until(make_timeout_time_ms(LOOP_SLICE_MS));
        } else {
            /* No driver to wait on. A plain sleep still keeps usbcfg responsive and the
             * watchdog fed, which is the entire job in this state. */
            sleep_ms(LOOP_SLICE_MS);
        }
    }
}
