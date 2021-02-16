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
typedef void(*ehttpd_ws_connected_cb_t)(
    ehttpd_ws_t *ws
);
typedef void(*ehttpd_ws_recv_cb_t)(
    ehttpd_ws_t *ws,
    const uint8_t *buf,
    int len,
    ehttpd_ws_flags_t flags
);
typedef void(*ehttpd_ws_sent_cb_t)(
    ehttpd_ws_t *ws
);
typedef void(*ehttpd_ws_close_cb_t)(
    ehttpd_ws_t *ws
);

enum ehttpd_ws_flags_t {
    EHTTPD_WS_FLAG_NONE = 0,
    EHTTPD_WS_FLAG_MORE = (1 << 0), //Set if the data is not the final data in the message; more follows
    EHTTPD_WS_FLAG_BIN  = (1 << 1), //Set if the data is binary instead of text
    EHTTPD_WS_FLAG_CONT = (1 << 2), //set if this is a continuation frame (after EHTTPD_WS_FLAG_CONT)
};

/**
 * \brief Websocket instance data
 */
struct ehttpd_ws_t {
    ehttpd_ws_priv_t priv; /**< internal data */
    ehttpd_conn_t *conn; /**< esphttpd connection data */
    ehttpd_ws_recv_cb_t recv_cb; /**< receive callback */
    ehttpd_ws_sent_cb_t sent_cb; /**< sent callback */
    ehttpd_ws_close_cb_t close_cb; /**< close callback */
    void *user; /**< user data */
};

/**
 * \brief Send data over websocket
 */
int ehttpd_ws_send(
    ehttpd_ws_t *ws, /** [in] websocket instance */
    const void *buf, /** [in] bytes */
    int len, /** [in] data length */
    ehttpd_ws_flags_t flags /** [in] flags */
);

/**
 * \brief Close a websocket
 */
void ehttpd_ws_close(
    ehttpd_ws_t *ws, /** [in] websocket instance */
    int reason /** [in] reason code (TODO: needs more info) */
);

/**
 * \brief Broadcast data to all websockets at resource
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
