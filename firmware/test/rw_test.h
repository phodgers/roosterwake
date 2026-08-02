/*
 * A minimal assert harness.
 *
 * No framework. The whole point of these tests is that they run anywhere with a C compiler and
 * nothing else — CI, a laptop, a reviewer's machine — because the golden vectors they check
 * are a contract between three codebases and a test that is awkward to run is a test that
 * stops being run.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_TEST_H
#define RW_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int rw_tests_run;
extern int rw_tests_failed;
extern const char *rw_current_case;

void rw_test_begin(const char *name);
void rw_test_fail(const char *file, int line, const char *fmt, ...);

#define RW_CHECK(cond)                                                        \
    do {                                                                      \
        rw_tests_run++;                                                       \
        if (!(cond)) {                                                        \
            rw_test_fail(__FILE__, __LINE__, "expected %s", #cond);           \
        }                                                                     \
    } while (0)

#define RW_CHECK_MSG(cond, ...)                                               \
    do {                                                                      \
        rw_tests_run++;                                                       \
        if (!(cond)) {                                                        \
            rw_test_fail(__FILE__, __LINE__, __VA_ARGS__);                    \
        }                                                                     \
    } while (0)

#define RW_CHECK_EQ_INT(actual, expected)                                     \
    do {                                                                      \
        rw_tests_run++;                                                       \
        long long a_ = (long long)(actual);                                   \
        long long e_ = (long long)(expected);                                 \
        if (a_ != e_) {                                                       \
            rw_test_fail(__FILE__, __LINE__, "%s: got %lld, expected %lld",   \
                         #actual, a_, e_);                                    \
        }                                                                     \
    } while (0)

#define RW_CHECK_EQ_STR(actual, expected)                                     \
    do {                                                                      \
        rw_tests_run++;                                                       \
        const char *a_ = (actual);                                            \
        const char *e_ = (expected);                                          \
        if (a_ == NULL || e_ == NULL || strcmp(a_, e_) != 0) {                \
            rw_test_fail(__FILE__, __LINE__, "%s: got \"%s\", expected \"%s\"", \
                         #actual, a_ ? a_ : "(null)", e_ ? e_ : "(null)");    \
        }                                                                     \
    } while (0)

/* Byte-compare with a hex diff on the first mismatch, because "buffers differ" is useless when
 * the buffer is a 612-byte flash record. */
void rw_check_mem(const char *file, int line, const char *what, const void *actual,
                  const void *expected, size_t len);

#define RW_CHECK_EQ_MEM(actual, expected, len)                                \
    do {                                                                      \
        rw_tests_run++;                                                       \
        rw_check_mem(__FILE__, __LINE__, #actual, (actual), (expected), (len)); \
    } while (0)

/* Each suite. */
void test_config(void);
void test_wol(void);
void test_ws_frame(void);
void test_ws_handshake(void);
void test_auth(void);
void test_json(void);
void test_url(void);
void test_usbcfg(void);
void test_provisioning(void);
void test_ota_image(void);
void test_ota_state(void);
void test_nbns(void);

/* Path to firmware/test, passed in by CMake so the vectors are found wherever the build runs. */
extern const char *rw_test_data_dir;

#endif /* RW_TEST_H */
