/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include "libesphttpd/httpd.h"

typedef enum ehttpd_cb_status_t ehttpd_cb_status_t;

enum ehttpd_cb_status_t {
    EHTTPD_CB_SUCCESS,
    EHTTPD_CB_CLOSED,
    EHTTPD_CB_ERROR_MEMORY,
    EHTTPD_CB_ERROR
};

// Platform dependent code shall call these.
ehttpd_cb_status_t ehttpd_sent_cb(
    ehttpd_conn_t *conn
);

ehttpd_cb_status_t ehttpd_recv_cb(
    ehttpd_conn_t *conn,
    void *buf,
    size_t len
);
