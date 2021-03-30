/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "httpd.h"
#include "ws_priv.h"


typedef struct ehttpd_ws_t ehttpd_ws_t;
typedef enum ehttpd_ws_flags_t ehttpd_ws_flags_t;
typedef void(*ehttpd_ws_handler_t)(
    ehttpd_ws_t *ws /** [in] WebSocket instance */
);

enum ehttpd_ws_flags_t {
    EHTTPD_WS_FLAG_NONE = 0,
    EHTTPD_WS_FLAG_MORE = (1 << 0), /**< data is not the final data in the
                                         message; more follows */
    EHTTPD_WS_FLAG_BIN  = (1 << 1), /**< data is binary instead of text */
    EHTTPD_WS_FLAG_CONT = (1 << 2), /**< this is a continuation frame (after
                                         EHTTPD_WS_FLAG_CONT) */
    EHTTPD_WS_FLAG_DONE = (1 << 3), /**< this is the last recv (fin) */
};

/**
 * \brief WebSocket instance data
 */
struct ehttpd_ws_t {
    ehttpd_ws_priv_t priv; /**< internal data */
    ehttpd_conn_t *conn; /**< esphttpd connection data */
    ehttpd_flags_t flags; /**< post-recv information */
    void *user; /**< user data */
};

/**
 * \brief Receive data
 *
 * \note **ws->flags** is updated after this call
 */
ssize_t ehttpd_ws_recv(
    ehttpd_ws_t *ws, /** [in] WebSocket instance */
    void *buf, /** [in] bytes */
    size_t len /** [in] data length */
);

/**
 * \brief Send data over WebSocket
 */
ssize_t ehttpd_ws_send(
    ehttpd_ws_t *ws, /** [in] WebSocket instance */
    const void *buf, /** [in] bytes */
    size_t len, /** [in] data length */
    ehttpd_ws_flags_t flags /** [in] flags */
);

/**
 * \brief Close a WebSocket
 */
void ehttpd_ws_close(
    ehttpd_ws_t *ws, /** [in] WebSocket instance */
    int reason /** [in] reason code (See RFC 6455 7.4.1) */
);

/**
 * \brief Broadcast data to all WebSockets at resource
 */
int ehttpd_ws_broadcast(
    ehttpd_inst_t *inst, /** [in] esphttpd server instance */
    const char *resource, /** [in] route */
    const void *buf, /** [in] bytes */
    int len, /** [in] data length */
    int flags /** [in] flags */
);


#ifdef __cplusplus
} /* extern "C" */
#endif
