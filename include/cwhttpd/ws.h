/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "httpd.h"
#include "ws_priv.h"


typedef struct cwhttpd_ws_t cwhttpd_ws_t;
typedef enum cwhttpd_ws_flags_t cwhttpd_ws_flags_t;
typedef void(*cwhttpd_ws_handler_t)(
    cwhttpd_ws_t *ws /** [in] WebSocket instance */
);

enum cwhttpd_ws_flags_t {
    CWHTTPD_WS_FLAG_NONE = 0,
    CWHTTPD_WS_FLAG_MORE = (1 << 0), /**< data is not the final data in the
                                         message; more follows */
    CWHTTPD_WS_FLAG_BIN  = (1 << 1), /**< data is binary instead of text */
    CWHTTPD_WS_FLAG_CONT = (1 << 2), /**< this is a continuation frame (after
                                         CWHTTPD_WS_FLAG_CONT) */
    CWHTTPD_WS_FLAG_DONE = (1 << 3), /**< this is the last recv (fin) */
};

/**
 * \brief WebSocket instance data
 */
struct cwhttpd_ws_t {
    cwhttpd_ws_priv_t priv; /**< internal data */
    cwhttpd_conn_t *conn; /**< esphttpd connection data */
    cwhttpd_flags_t flags; /**< post-recv information */
    void *user; /**< user data */
};

/**
 * \brief Receive data
 *
 * \note **ws->flags** is updated after this call
 */
ssize_t cwhttpd_ws_recv(
    cwhttpd_ws_t *ws, /** [in] WebSocket instance */
    void *buf, /** [in] bytes */
    size_t len /** [in] data length */
);

/**
 * \brief Send data over WebSocket
 */
ssize_t cwhttpd_ws_send(
    cwhttpd_ws_t *ws, /** [in] WebSocket instance */
    const void *buf, /** [in] bytes */
    size_t len, /** [in] data length */
    cwhttpd_ws_flags_t flags /** [in] flags */
);

/**
 * \brief Close a WebSocket
 */
void cwhttpd_ws_close(
    cwhttpd_ws_t *ws, /** [in] WebSocket instance */
    int reason /** [in] reason code (See RFC 6455 7.4.1) */
);

/**
 * \brief Broadcast data to all WebSockets at resource
 */
int cwhttpd_ws_broadcast(
    cwhttpd_inst_t *inst, /** [in] esphttpd server instance */
    const char *resource, /** [in] route */
    const void *buf, /** [in] bytes */
    int len, /** [in] data length */
    int flags /** [in] flags */
);


#ifdef __cplusplus
} /* extern "C" */
#endif
