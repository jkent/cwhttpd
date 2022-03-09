/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include "cwhttpd/port.h"


typedef struct cwhttpd_ws_priv_t cwhttpd_ws_priv_t;
typedef struct cwhttpd_ws_frame_t cwhttpd_ws_frame_t;
typedef struct cwhttpd_ws_t cwhttpd_ws_t;

struct cwhttpd_ws_frame_t {
    uint8_t flags;
    uint8_t len8;
    uint64_t len;
    uint8_t mask[4];
};

struct cwhttpd_ws_priv_t {
    cwhttpd_ws_frame_t frame;
    cwhttpd_ws_t *next; // in linked list
};
