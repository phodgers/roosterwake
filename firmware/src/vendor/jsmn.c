/*
 * The single instantiation of jsmn's implementation.
 *
 * jsmn.h carries its body inline unless JSMN_HEADER is defined. proto/json.h defines it, so
 * every other translation unit sees declarations only and this one provides the code.
 *
 * SPDX-License-Identifier: MIT
 */
#include "vendor/jsmn.h"
