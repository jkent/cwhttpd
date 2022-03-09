/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include "cwhttpd/httpd.h"

// New connection callback
void cwhttpd_new_conn_cb(
    cwhttpd_conn_t *conn
);
