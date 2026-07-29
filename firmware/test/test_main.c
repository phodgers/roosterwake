/*
 * Host test runner. See rw_test.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "rw_test.h"

#include <stdarg.h>

int         rw_tests_run;
int         rw_tests_failed;
const char *rw_current_case = "(none)";
const char *rw_test_data_dir;

void rw_test_begin(const char *name) {
    rw_current_case = name;
}

void rw_test_fail(const char *file, int line, const char *fmt, ...) {
    rw_tests_failed++;
    fprintf(stderr, "FAIL  %s\n      %s:%d: ", rw_current_case, file, line);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void rw_check_mem(const char *file, int line, const char *what, const void *actual,
                  const void *expected, size_t len) {
    const unsigned char *a = (const unsigned char *)actual;
    const unsigned char *e = (const unsigned char *)expected;
    for (size_t i = 0; i < len; i++) {
        if (a[i] != e[i]) {
            rw_test_fail(file, line, "%s: first difference at byte %zu: got 0x%02x, expected 0x%02x",
                         what, i, a[i], e[i]);
            return;
        }
    }
}

typedef struct {
    const char *name;
    void (*fn)(void);
} suite_t;

int main(int argc, char **argv) {
    /* Where the golden vectors live. argv[1] wins (ctest passes it), then the path baked in at
     * configure time, then the working directory.
     *
     * The compiled-in default matters more than it looks. Without it the binary only finds the
     * vectors when run from firmware/test, so `./rw_tests` from a build directory skips the
     * entire config suite — which is the suite that proves the C encoder agrees byte-for-byte
     * with the JS one, and is therefore the last thing that should depend on where you happened
     * to be standing. It fails loudly rather than silently, but "loudly, and only sometimes" is
     * still the wrong contract for the most load-bearing test in the firmware. */
#ifdef RW_TEST_DATA_DIR
    rw_test_data_dir = (argc > 1) ? argv[1] : RW_TEST_DATA_DIR;
#else
    rw_test_data_dir = (argc > 1) ? argv[1] : ".";
#endif

    static const suite_t suites[] = {
        {"config", test_config},
        {"wol", test_wol},
        {"ws_frame", test_ws_frame},
        {"ws_handshake", test_ws_handshake},
        {"auth", test_auth},
        {"json", test_json},
        {"url", test_url},
        {"usbcfg", test_usbcfg},
        {"provisioning", test_provisioning},
    };

    for (size_t i = 0; i < sizeof(suites) / sizeof(suites[0]); i++) {
        int before_run    = rw_tests_run;
        int before_failed = rw_tests_failed;
        printf("== %s\n", suites[i].name);
        suites[i].fn();
        printf("   %d checks, %d failed\n", rw_tests_run - before_run,
               rw_tests_failed - before_failed);
    }

    printf("\n%d checks, %d failures\n", rw_tests_run, rw_tests_failed);
    if (rw_tests_run == 0) {
        fprintf(stderr, "no checks ran - the harness is broken, not the code\n");
        return 2;
    }
    return rw_tests_failed == 0 ? 0 : 1;
}
