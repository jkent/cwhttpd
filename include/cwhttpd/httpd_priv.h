/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>


/**
 * \brief Max length of request head.
 */
#ifndef CONFIG_CWHTTPD_MAX_REQUEST_SIZE
# define CONFIG_CWHTTPD_MAX_REQUEST_SIZE 1024
#endif

typedef struct cwhttpd_conn_t cwhttpd_conn_t;
typedef struct cwhttpd_conn_priv_t cwhttpd_conn_priv_t;

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
    HFL_REQUEST_CLOSE       = (1 << 0),
    HFL_SEND_CHUNKED        = (1 << 1),
    HFL_SENDING_HEADER      = (1 << 2),
    HFL_SENDING_CHUNK       = (1 << 3),
    HFL_CLOSE               = (1 << 4),

    HFL_RECEIVED_HTTP11     = (1 << 8),
    HFL_RECEIVED_CONN_CLOSE = (1 << 9),
    HFL_RECEIVED_CONN_ALIVE = (1 << 10),

    HFL_SENT_RESPONSE       = (1 << 16),
    HFL_SENT_HEADERS        = (1 << 17),
    HFL_SENT_CONTENT_LENGTH = (1 << 18),
    HFL_SENT_FINAL_CHUNK    = (1 << 19),
    HFL_SENT_CONN_CLOSE     = (1 << 20),
};

/**
 * \brief Private data for HTTP connection
 */
struct cwhttpd_conn_priv_t {
    char req[CONFIG_CWHTTPD_MAX_REQUEST_SIZE]; /**< request and header data */
    char *data;
    size_t req_len;
    size_t chunk_left;
    uint32_t flags; /**< connection state */
};
