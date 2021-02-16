/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <stddef.h>
#include <stdint.h>


/**
 * \brief Max length of request head.
 */
#ifndef CONFIG_EHTTPD_MAX_REQUEST_SIZE
# define CONFIG_EHTTPD_MAX_REQUEST_SIZE 1024
#endif

/**
 * \brief Max send buffer size.
 */
#ifndef CONFIG_EHTTPD_SENDBUF_SIZE
# define CONFIG_EHTTPD_SENDBUF_SIZE 2048
#endif

typedef struct ehttpd_conn_priv_t ehttpd_conn_priv_t;

// Struct to keep extension->mime data in
typedef struct {
    const char *ext;
    const char *mimetype;
} mime_map_t;

// The mappings from file extensions to mime types. If you need an extra mime
// type, add it here.
static const mime_map_t mime_types[] = {
    {"htm",   "text/html"},
    {"html",  "text/html"},
    {"css",   "text/css"},
    {"js",    "text/javascript"},
    {"txt",   "text/plain"},
    {"jpg",   "image/jpeg"},
    {"jpeg",  "image/jpeg"},
    {"png",   "image/png"},
    {"svg",   "image/svg+xml"},
    {"xml",   "text/xml"},
    {"json",  "application/json"},
    {"woff",  "font/woff"},
    {"woff2", "font/woff2"},
    {NULL,    "text/html"}, // default value
};

// Flags
enum {
    HFL_NEW_CONN            = (1 << 0),
    HFL_REQUEST_STARTED     = (1 << 1),
    HFL_REQUEST_CLOSE       = (1 << 2),
    HFL_SEND_CHUNKED        = (1 << 3),
    HFL_CLOSE_AFTER_SENT    = (1 << 4),

    HFL_RECEIVED_HTTP11     = (1 << 8),
    HFL_RECEIVED_CONN_CLOSE = (1 << 9),
    HFL_RECEIVED_CONN_ALIVE = (1 << 10),

    HFL_SENT_HEADERS        = (1 << 16),
    HFL_SENT_CONTENT_LENGTH = (1 << 17),
    HFL_SENT_CONN_CLOSE     = (1 << 18),
};

/**
 * \brief Private data for HTTP connection
 */
struct ehttpd_conn_priv_t {
    char request[CONFIG_EHTTPD_MAX_REQUEST_SIZE]; /**< request and header data */
    uint8_t sendbuf[CONFIG_EHTTPD_SENDBUF_SIZE]; /**< send buffer */
    size_t sendbuf_len; /**< length of send buffer */
    uint8_t *chunk_start; /**< points to a location in sendbuf */
    uint32_t flags; /**< connection state */
};
