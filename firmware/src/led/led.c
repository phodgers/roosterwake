/*
 * Status LED patterns. See led.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "led/led.h"

#include <stddef.h>

#include "pico/cyw43_arch.h"
#include "pico/time.h"

typedef struct {
    bool     on;
    uint32_t ms;
} led_step_t;

/* Fast: unmistakably "not configured yet, come and set me up". */
static const led_step_t k_setup_ap[] = {
    {true, 120}, {false, 120},
};

/* Slow: working on it. Twice the period of the setup blink so the two are not confusable at
 * a glance, which they are at any ratio closer than 2:1. */
static const led_step_t k_joining[] = {
    {true, 400}, {false, 400},
};

/*
 * Two short pulses then a long gap. Mostly dark on purpose: this is the steady state, it runs
 * for months, and a dongle that blinks continuously in a bedroom gets unplugged.
 */
static const led_step_t k_connected[] = {
    {true, 60}, {false, 180}, {true, 60}, {false, 2700},
};

/* SOS: ... --- ... with a long gap before it repeats. */
static const led_step_t k_error[] = {
    {true, 180}, {false, 180}, {true, 180}, {false, 180}, {true, 180}, {false, 540},
    {true, 540}, {false, 180}, {true, 540}, {false, 180}, {true, 540}, {false, 540},
    {true, 180}, {false, 180}, {true, 180}, {false, 180}, {true, 180}, {false, 1500},
};

/* Solid, then the resting pattern resumes. */
static const led_step_t k_wake_sent[] = {
    {true, 2000},
};

typedef struct {
    const led_step_t *steps;
    size_t            count;
} led_pattern_def_t;

static const led_pattern_def_t k_patterns[] = {
    [RW_LED_SETUP_AP]   = {k_setup_ap, sizeof(k_setup_ap) / sizeof(k_setup_ap[0])},
    [RW_LED_JOINING]    = {k_joining, sizeof(k_joining) / sizeof(k_joining[0])},
    [RW_LED_CONNECTED]  = {k_connected, sizeof(k_connected) / sizeof(k_connected[0])},
    [RW_LED_ERROR]      = {k_error, sizeof(k_error) / sizeof(k_error[0])},
};

static rw_led_pattern_t s_resting = RW_LED_SETUP_AP;
static const led_pattern_def_t *s_active;
static bool            s_transient;
static size_t          s_step;
static absolute_time_t s_next_change;
static bool            s_last_written;
static bool            s_initialised;

static const led_pattern_def_t k_wake_def = {k_wake_sent,
                                             sizeof(k_wake_sent) / sizeof(k_wake_sent[0])};

static void write_led(bool on) {
    /* Each write is an SPI transaction to the CYW43439, so only spend one when the level
     * actually changes. */
    if (!s_initialised || on != s_last_written) {
        cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, on);
        s_last_written = on;
        s_initialised  = true;
    }
}

static void begin(const led_pattern_def_t *def, bool transient) {
    s_active      = def;
    s_transient   = transient;
    s_step        = 0;
    s_next_change = make_timeout_time_ms(def->steps[0].ms);
    write_led(def->steps[0].on);
}

void rw_led_init(void) {
    s_initialised = false;
    begin(&k_patterns[RW_LED_SETUP_AP], false);
}

void rw_led_set(rw_led_pattern_t pattern) {
    if (pattern == s_resting) {
        return;
    }
    s_resting = pattern;
    if (!s_transient) {
        begin(&k_patterns[pattern], false);
    }
    /* A wake flash in progress is allowed to finish: it is the acknowledgement of an action
     * the user just took, and interrupting it to report a state change loses that. */
}

void rw_led_wake_sent(void) {
    begin(&k_wake_def, true);
}

void rw_led_task(void) {
    if (s_active == NULL) {
        rw_led_init();
        return;
    }
    if (!time_reached(s_next_change)) {
        return;
    }

    s_step++;
    if (s_step >= s_active->count) {
        if (s_transient) {
            begin(&k_patterns[s_resting], false);
            return;
        }
        s_step = 0;
    }
    s_next_change = make_timeout_time_ms(s_active->steps[s_step].ms);
    write_led(s_active->steps[s_step].on);
}
