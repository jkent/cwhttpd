/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include "libesphttpd/port.h"


typedef struct ehttpd_ws_priv_t ehttpd_ws_priv_t;
typedef struct ehttpd_ws_frame_t ehttpd_ws_frame_t;
typedef struct ehttpd_ws_t ehttpd_ws_t;

struct ehttpd_ws_frame_t {
    uint8_t flags;
    uint8_t len8;
    uint64_t len;
    uint8_t mask[4];
};

struct ehttpd_ws_priv_t {
    ehttpd_ws_frame_t frame;
    ehttpd_ws_t *next; // in linked list
};
