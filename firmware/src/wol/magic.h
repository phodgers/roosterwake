/*
 * Wake-on-LAN magic packet construction.
 *
 * Split from the sender so it compiles into the native host tests with no network stack. The
 * payload is the part that is a wire format; everything else is plumbing.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_WOL_MAGIC_H
#define RW_WOL_MAGIC_H

#include <stdint.h>

/* 6 synchronisation bytes plus the target MAC sixteen times. */
#define RW_WOL_MAGIC_LEN 102

/*
 * Write the 102-byte magic packet payload for `mac` into `out`.
 *
 * There is no SecureOn password field. It is optional in the original AMD specification,
 * unsupported by most consumer NICs, and adding six more bytes that some receivers reject is
 * a poor trade for a feature nobody has asked for.
 */
void rw_wol_build_magic(const uint8_t mac[6], uint8_t out[RW_WOL_MAGIC_LEN]);

#endif /* RW_WOL_MAGIC_H */
