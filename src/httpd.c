/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* Copyright 2017 Jeroen Domburg <git@j0h.nl> */
/* Copyright 2017 Chris Morgan <chmorgan@gmail.com> */
/* Copyright 2021 Jeff Kent <jeff@jkent.net> */

#include "cb.h"
#include "log.h"
#include "libesphttpd/httpd.h"
#include "libesphttpd/httpd_priv.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#if defined(UNIX)
# include <bsd/string.h>
#endif


const char *ehttpd_get_header(ehttpd_conn_t *conn, const char *name)
{
    char *p = conn->headers;
    const char *value = NULL;

    while (*p) {
        if (strcasecmp(p, name) == 0) {
            while (*p) { /* skip name */
                p++;
            }
            if (*p == '\0' && *(p + 1) == '\0') {
                break;
            }
            p++; /* skip null */
            while (*p == ' ') { /* skip spaces */
                p++;
            }
            value = p;
        } else {
            while (*p) { /* skip name */
                p++;
            }
            if (*p == '\0' && *(p + 1) == '\0') {
                break;
            }
            p++; /* skip null */
        }
        while (*p) { /* skip value */
            p++;
        }
        if (*p == '\0' && *(p + 1) == '\0') {
            break;
        }
        p++; /* skip null */
        if (*p == '\n') {
            p++;
        }
    }

    return value;
}

void ehttpd_set_chunked_encoding(ehttpd_conn_t *conn, bool enable)
{
    if (conn->priv.flags & HFL_SENT_HEADERS) {
        EHTTPD_LOGE(__func__, "headers already sent");
        return;
    }

    conn->priv.flags &= ~HFL_SEND_CHUNKED;
    if (enable && (conn->priv.flags & HFL_RECEIVED_HTTP11)) {
        conn->priv.flags |= HFL_SEND_CHUNKED;
    }
}

void ehttpd_set_close(ehttpd_conn_t *conn, bool close)
{
    if (conn->priv.flags & HFL_SENT_HEADERS) {
        EHTTPD_LOGE(__func__, "headers already sent");
        return;
    }

    if (close) {
        EHTTPD_LOGI(__func__, "requesting close %p", conn);
        conn->priv.flags |= HFL_REQUEST_CLOSE;
    } else {
        conn->priv.flags &= ~HFL_REQUEST_CLOSE;
    }
}

void ehttpd_start_response(ehttpd_conn_t *conn, int code)
{
    const char *message;

    switch (code) {
        case 100:
            message = "Continue";
            break;
        case 101:
            message = "Switching Protocol";
            break;
        case 200:
            message = "OK";
            break;
        case 201:
            message = "Created";
            break;
        case 204:
            message = "No Content";
            break;
        case 301:
            message = "Moved Permanently";
            break;
        case 302:
            message = "Found";
            break;
        case 303:
            message = "See Other";
            break;
        case 307:
            message = "Temporary Redirect";
            break;
        case 308:
            message = "Permanent Redirect";
            break;
        case 400:
            message = "Bad Request";
            break;
        case 401:
            message = "Unauthorized";
            break;
        case 403:
            message = "Forbidden";
            break;
        case 404:
            message = "Not Found";
            break;
        case 405:
            message = "Method Not Allowed";
            break;
        case 411:
            message = "Length Required";
            break;
        case 414:
            message = "URI Too Long";
            break;
        case 500:
            message = "Internal Server Error";
            break;
        case 501:
            message = "Not Implemented";
            break;
        default:
            message = "OK";
            break;
    }

    ehttpd_enqueuef(conn, "HTTP/1.%d %d %s\r\n",
            (conn->priv.flags & HFL_RECEIVED_HTTP11) ? 1 : 0, code, message);

    ehttpd_header(conn, "Server", "ehttpd/" EHTTPD_VERSION);

    if (conn->priv.flags & HFL_SEND_CHUNKED) {
        ehttpd_header(conn, "Transfer-Encoding", "chunked");
    }

#ifdef CONFIG_EHTTPD_ENABLE_CORS
    ehttpd_header(conn, "Access-Control-Allow-Origin", CONFIG_EHTTPD_CORS_ORIGIN);
    ehttpd_header(conn, "Access-Control-Allow-Methods", CONFIG_EHTTPD_CORS_METHODS);
#endif
}

void ehttpd_add_cache_header(ehttpd_conn_t *conn, const char *mime)
{
    if (mime != NULL) {
        if (strcmp(mime, "text/html") == 0) {
            return;
        }
        if (strcmp(mime, "text/plain") == 0) {
            return;
        }
        if (strcmp(mime, "text/csv") == 0) {
            return;
        }
        if (strcmp(mime, "application/json") == 0) {
            return;
        }
    }

    ehttpd_header(conn, "Cache-Control",
            "max-age=7200, public, must-revalidate");
}

void ehttpd_header(ehttpd_conn_t *conn, const char *name, const char *value)
{
    if (strcasecmp(name, "Content-Length") == 0) {
        conn->priv.flags |= HFL_SENT_CONTENT_LENGTH;
    }

    if ((strcasecmp(name, "Connection") == 0) &&
            (strcasecmp(name, "close") == 0)) {
        conn->priv.flags |= HFL_SENT_CONN_CLOSE;
    }

    ehttpd_enqueuef(conn, "%s: %s\r\n", name, value);
}

void ehttpd_end_headers(ehttpd_conn_t *conn)
{
    if (conn->priv.flags & HFL_REQUEST_CLOSE) {
        ehttpd_header(conn, "Connection", "close");
    } else if (!(conn->priv.flags & HFL_SENT_CONTENT_LENGTH)) {
        if (!(conn->priv.flags & HFL_SEND_CHUNKED)) {
            if (conn->priv.flags & HFL_RECEIVED_HTTP11) {
                ehttpd_header(conn, "Connection", "close");
            }
        }
    } else if (conn->priv.flags & HFL_RECEIVED_CONN_ALIVE) {
        ehttpd_header(conn, "Connection", "keep-alive");
    }

    ehttpd_enqueue(conn, "\r\n", 2);
    conn->priv.flags |= HFL_SENT_HEADERS;
}

ssize_t ehttpd_prepare(ehttpd_conn_t *conn, void **buf, size_t len)
{
    if ((conn->priv.flags & HFL_SEND_CHUNKED) &&
            (conn->priv.flags & HFL_SENT_HEADERS)) {
        if (conn->priv.chunk_start == NULL) {
            if ((conn->priv.sendbuf_len + 6 + len) >
                    (CONFIG_EHTTPD_SENDBUF_SIZE - 2)) {
                return -1;
            }

            // Establish start of chunk
            // Use a chunk length placeholder of 4 characters
            conn->priv.chunk_start =
                    &conn->priv.sendbuf[conn->priv.sendbuf_len];
            memcpy(conn->priv.chunk_start, "0000\r\n", 6);
            conn->priv.sendbuf_len += 6;
        }

        if (conn->priv.sendbuf_len + len > CONFIG_EHTTPD_SENDBUF_SIZE - 2) {
            return -1;
        }

        *buf = conn->priv.sendbuf + conn->priv.sendbuf_len;
        return CONFIG_EHTTPD_SENDBUF_SIZE - conn->priv.sendbuf_len - 2;
    } else if (conn->priv.sendbuf_len + len > CONFIG_EHTTPD_SENDBUF_SIZE) {
        return -1;
    } else {
        *buf = conn->priv.sendbuf + conn->priv.sendbuf_len;
        return CONFIG_EHTTPD_SENDBUF_SIZE - conn->priv.sendbuf_len;
    }
}

bool ehttpd_enqueue(ehttpd_conn_t *conn, const void *buf, ssize_t len)
{
    if (len < 0) {
        len = (int) strlen(buf);
    }

    if (len == 0) {
        return true;
    }

    void *p;
    ssize_t available = ehttpd_prepare(conn, &p, len);
    if (available < 0) {
        return false;
    }

    memcpy(p, buf, len);
    conn->priv.sendbuf_len += len;
    return true;
}

bool ehttpd_enqueuef(ehttpd_conn_t *conn, const char *fmt, ...)
{
    va_list va;

    va_start(va, fmt);
    size_t len = ehttpd_vsnprintf(NULL, 0, fmt, va);
    va_end(va);

    void *p;
    ssize_t available = ehttpd_prepare(conn, &p, len);
    if (available < len) {
        return false;
    }

    va_start(va, fmt);
    ehttpd_vsnprintf(p, available, fmt, va);
    va_end(va);
    conn->priv.sendbuf_len += len;
    return true;
}

static uint8_t hex_nibble(int val)
{
    val &= 0xf;
    if (val < 10) {
        return '0' + val;
    }
    return 'A' + (val - 10);
}

// Function to send any data in conn->priv.sendbuf. Do not use in route
// handlers unless you know what you are doing! Also, if you do set
// conn->route to NULL to indicate the connection is closed, do it BEFORE
// calling this.
void ehttpd_flush(ehttpd_conn_t *conn)
{
    ssize_t len;

    if (conn->priv.flags & HFL_SEND_CHUNKED) {
        if (conn->priv.chunk_start != NULL) {
            // We're sending chunked data, and the chunk needs fixing up.
            // Finish chunk with cr/lf
            if (conn->priv.sendbuf_len <= (CONFIG_EHTTPD_SENDBUF_SIZE - 2)) {
                memcpy(&conn->priv.sendbuf[conn->priv.sendbuf_len], "\r\n", 2);
                conn->priv.sendbuf_len += 2;
            } else {
                EHTTPD_LOGE(__func__, "sendbuf full");
            }
            // Calculate length of chunk
            // +2 is to remove the two characters written above via
            // ehttpd_enqueue(), those bytes aren't counted in the chunk
            // length
            len = ((&conn->priv.sendbuf[conn->priv.sendbuf_len]) -
                    conn->priv.chunk_start) - (6 + 2);
            // Fix up chunk header to correct value
            conn->priv.chunk_start[0] = hex_nibble(len >> 12);
            conn->priv.chunk_start[1] = hex_nibble(len >> 8);
            conn->priv.chunk_start[2] = hex_nibble(len >> 4);
            conn->priv.chunk_start[3] = hex_nibble(len >> 0);
            // Reset chunk hdr for next call
            conn->priv.chunk_start = NULL;
        }

        if ((conn->priv.flags & HFL_SENT_HEADERS) && (conn->route == NULL)) {
            if (conn->priv.sendbuf_len + 5 <= CONFIG_EHTTPD_SENDBUF_SIZE) {
                // Connection finished sending whatever needs to be sent. Add
                // NULL chunk to indicate this.
                memcpy(&conn->priv.sendbuf[conn->priv.sendbuf_len],
                        "0\r\n\r\n", 5);
                conn->priv.sendbuf_len += 5;
            } else {
                EHTTPD_LOGE(__func__, "sendbuf full");
            }
        }
    }

    if (conn->priv.sendbuf_len != 0) {
        len = ehttpd_send(conn, conn->priv.sendbuf, conn->priv.sendbuf_len);
        if (len < 0) {
            return; /* do nothing, connection closed */
        } else if (len != conn->priv.sendbuf_len) {
            EHTTPD_LOGE(__func__,
                    "send buf tried to write %d bytes, wrote %d",
                    conn->priv.sendbuf_len, len);
        }
        conn->priv.sendbuf_len = 0;
    }
}

void ehttpd_end_request(ehttpd_conn_t *conn)
{
    conn->route = NULL; // The route handler is complete

    EHTTPD_LOGD(__func__, "request ended %p", conn);

    if (!(conn->priv.flags & HFL_SENT_HEADERS)) {
        ehttpd_end_headers(conn);
    }

    ehttpd_flush(conn);

    if (conn->priv.flags & HFL_CLOSE_AFTER_SENT) {
        /* do nothing */
    } else if (conn->priv.flags & HFL_REQUEST_CLOSE) {
        conn->priv.flags |= HFL_CLOSE_AFTER_SENT;
    } else if (!(conn->priv.flags & HFL_SEND_CHUNKED)) {
        if (!(conn->priv.flags & HFL_SENT_CONTENT_LENGTH)) {
            conn->priv.flags |= HFL_CLOSE_AFTER_SENT;
        }
    } else {
        if (conn->post) {
            free(conn->post);
        }
        ehttpd_inst_t *inst = conn->inst;
        memset(conn, 0, sizeof(*conn));
        conn->inst = inst;
        EHTTPD_LOGV(__func__, "conn cleaned %p", conn);
    }
}


/******************************
 * \section Utility Functions
 ******************************/

void ehttpd_redirect(ehttpd_conn_t *conn, const char *url)
{
    ehttpd_start_response(conn, 302);
    ehttpd_header(conn, "Location", url);
    ehttpd_end_headers(conn);
}

static ehttpd_status_t ehttpd_route_not_found(ehttpd_conn_t *conn)
{
    if (conn->closed) {
        return EHTTPD_STATUS_DONE;
    }

    if (conn->post == NULL || conn->post->received == conn->post->len) {
        EHTTPD_LOGD(__func__, "%p", conn);
        ehttpd_start_response(conn, 404);
        ehttpd_end_headers(conn);
        ehttpd_enqueue(conn, "404 File not found.", -1);
        return EHTTPD_STATUS_DONE;
    }

    return EHTTPD_STATUS_MORE; // make sure to eat-up all the post data that
                               // the client may be sending!
}

static const ehttpd_route_t route_not_found =
    {NULL, ehttpd_route_not_found, NULL, NULL};

// Returns a static char *to a mime type for a given url to a file.
const char *ehttpd_get_mimetype(const char *url)
{
    char *urlp = (char *) url;
    int i = 0;

    // Find the extension
    const char *ext = urlp + strlen(urlp) - 1;
    while (ext != urlp && *ext != '.') {
        ext--;
    }

    if (*ext == '.') {
        ext++;
    }

    while (mime_types[i].ext != NULL && strcasecmp(ext, mime_types[i].ext) != 0) {
        i++;
    }

    return mime_types[i].mimetype;
}

static int decode_hex(char c)
{
    if (c >= '0' && c <= '9') {
         return c - '0';
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return 0;
}

size_t ehttpd_url_decode(const char *in, ssize_t in_len, char *out,
        size_t *out_len)
{
    if (in_len == -1) {
        in_len = strlen(in);
    }

    const char *in_start = in;
    char *out_start = out;
    size_t out_pos = 0;
    int escape = 0;

    while (in - in_start < in_len) {
        if (escape == 1) {
            if (out_pos < *out_len) {
                *out = decode_hex(*in) << 4;
            }
            escape++;
        } else if (escape == 2) {
            if (out_pos < *out_len) {
                *out++ |= decode_hex(*in);
            }
            out_pos++;
            escape = 0;
        } else if (*in == '%') {
            escape = 1;
        } else if (*in == '+') {
            if (out_pos < *out_len) {
                *out++ = ' ';
            }
            out_pos++;
        } else {
            if (out_pos < *out_len) {
                *out++ = *in;
            }
            out_pos++;
        }
        in++;
    }

    if (out_pos < *out_len) {
        *out = '\0';
    } else if (*out_len) {
        *out-- = '\0';
    }
    *out_len = out_pos + 1;
    return out - out_start;
}

ssize_t ehttpd_find_param(const char *needle, const char *haystack, char *out,
        size_t *out_len)
{
    size_t needle_len = strlen(needle);
    const char *p = haystack;
    const char *end;

    while (p != NULL && *p != '\0' && *p != '\n' && *p != '\r') {
        if (strncmp(p, needle, needle_len) == 0 && p[needle_len] == '=') {
            p += needle_len + 1; /* move pointer to value */
            end = (const char *) strchr(p, '&'); /* find the end of the value */
            if (end == NULL) {
                end = p + strlen(p);
            }
            return ehttpd_url_decode(p, end - p, out, out_len);
        }
        p = strchr(p, '&');
        if (p != NULL) {
            p += 1;
        }
    }
    return -1;
}


/*******************************
 * \section Callback Functions
 *******************************/

// Callback called when the data on a socket has been successfully
// sent.
ehttpd_cb_status_t ehttpd_sent_cb(ehttpd_conn_t *conn)
{
    ehttpd_cb_status_t cb_status = EHTTPD_CB_SUCCESS;

    ehttpd_lock(conn->inst);

    if (conn->priv.flags & HFL_CLOSE_AFTER_SENT) { // Marked for destruction?
        ehttpd_disconnect(conn);
        cb_status = EHTTPD_CB_SUCCESS;
        // NOTE: No need to call ehttpd_flush
    } else {
        // If we don't have a route handler, there's nothing to do but wait
        // for something from the client.
        if (conn->route == NULL) {
            cb_status = EHTTPD_CB_SUCCESS;
        } else {
            conn->priv.sendbuf_len = 0;

            ehttpd_status_t status = conn->route->handler(conn); // Execute route handler.

            if (status == EHTTPD_STATUS_DONE) {
                // No special action for EHTTPD_STATUS_DONE
            } else if (status == EHTTPD_STATUS_NOTFOUND || status == EHTTPD_STATUS_AUTHENTICATED) {
                EHTTPD_LOGE(__func__, "route handler returned %d", status);
            }

            if ((status == EHTTPD_STATUS_DONE) || (status == EHTTPD_STATUS_NOTFOUND) ||
                    (status == EHTTPD_STATUS_AUTHENTICATED)) {
                ehttpd_end_request(conn);
            }

            ehttpd_flush(conn);
        }
    }

    ehttpd_unlock(conn->inst);
    return cb_status;
}

// This is called when the headers have been received and the connection is
// ready to send the result headers and data.
// We need to find the route handler to call, call it, and dependent on what it
// returns either find the next route handler, wait till the route handler data
// is sent or close up the connection.
static void process_request(ehttpd_conn_t *conn)
{
#ifdef CONFIG_EHTTPD_ENABLE_CORS
    // CORS preflight, allow the token we received before
    if (conn->method == EHTTPD_METHOD_OPTIONS) {
        ehttpd_start_response(conn, 200);
        ehttpd_header(conn, "Access-Control-Allow-Origin", CONFIG_EHTTPD_CORS_ORIGIN);
        ehttpd_header(conn, "Access-Control-Allow-Methods", CONFIG_EHTTPD_CORS_METHODS);
        ehttpd_end_headers(conn);
        ehttpd_end_request(conn);
        ehttpd_flush(conn);
        return;
    }
#endif

    // find a route that can handle the request
    const ehttpd_route_t *route = conn->inst->routes;
    while (true) {
        while (route->route != NULL) {
            if ((strcmp(route->route, conn->url) == 0) ||
                    ((route->route[strlen(route->route) - 1] == '*') &&
                    (strncmp(route->route, conn->url, strlen(route->route) - 1) == 0))) {
                conn->route = route;
                conn->user = NULL;
                break;
            }
            route++;
        }

        if (route->route == NULL) {
            conn->route = &route_not_found;
        }

        ehttpd_status_t status = conn->route->handler(conn);
        if (status == EHTTPD_STATUS_MORE) {
            ehttpd_flush(conn);
            break;
        } else if (status == EHTTPD_STATUS_DONE) {
            ehttpd_end_request(conn);
            break;
        } else if (status == EHTTPD_STATUS_NOTFOUND || status == EHTTPD_STATUS_AUTHENTICATED) {
            route++; // look at the next route
        }
    }
}

// Parse a line of header data and modify the connection data accordingly.
static ehttpd_cb_status_t parse_request(ehttpd_conn_t *conn)
{
    ehttpd_cb_status_t status = EHTTPD_CB_SUCCESS;
    char *e = conn->priv.request;

    if (strncasecmp(e, "GET ", 4) == 0) {
        conn->method = EHTTPD_METHOD_GET;
        e += 3;
    } else if (strncasecmp(e, "POST ", 5) == 0) {
        conn->method = EHTTPD_METHOD_POST;
        e += 4;
    } else if (strncasecmp(e, "OPTIONS ", 8) == 0) {
        conn->method = EHTTPD_METHOD_OPTIONS;
        e += 7;
    } else if (strncasecmp(e, "PUT ", 4) == 0) {
        conn->method = EHTTPD_METHOD_PUT;
        e += 3;
    } else if (strncasecmp(e, "PATCH ", 6) == 0) {
        conn->method = EHTTPD_METHOD_PATCH;
        e += 5;
    } else if (strncasecmp(e, "DELETE ", 7) == 0) {
        conn->method = EHTTPD_METHOD_DELETE;
        e += 6;
    } else {
        EHTTPD_LOGE(__func__, "unsupported request method");
        return EHTTPD_CB_ERROR;
    }
    *e++ = '\0';

    // Skip past spaces after the method
    while (*e == ' ') {
        e++;
    }
    conn->url = e;

    // Remove extra slashes in url
    char last = '\0';
    char *p = e;
    int n = 0;
    while (*e && *e != '\n') {
        if (*e == '\r' || *e == '\n') {
            return EHTTPD_CB_ERROR;
        }
        if (*e == ' ' || *e == '?') {
            last = *e++;
            break;
        } else if (*e != '/' || last != '/') {
            *p++ = *e;
            n++;
        }
        last = *e++;
    }
    *p = '\0';

    // Parse out query arguments
    if (last == '?') {
        conn->args = e;
        while (*e && *e != ' ') {
            if (*e == '\r' || *e == '\n') {
                return EHTTPD_CB_ERROR;
            }
            e++;
        }
        last = *e;
        *e++ = '\0';
    }

    // Skip past spaces before the HTTP version
    if (last == ' ') {
        while (*e == ' ') {
            if (*e == '\r' || *e == '\n') {
                return EHTTPD_CB_ERROR;
            }
            e++;
        }

        const char *ver = e;

        while (*e && *e != ' ' && *e != '\r' && *e != '\n') {
            e++;
        }
        if (*e == '\r') {
            *e++ = '\0';
        }
        if (*e == '\n') {
            *e++ = '\0';
        }

        // Set flags if HTTP/1.1
        if (strcasecmp(ver, "HTTP/1.1") == 0) {
            conn->priv.flags |= HFL_RECEIVED_HTTP11;
            conn->priv.flags |= HFL_SEND_CHUNKED;
        }
    }

    if (conn->args) {
        EHTTPD_LOGD(__func__, "%s %s?%s", conn->priv.request, conn->url,
                conn->args);
    } else {
        EHTTPD_LOGD(__func__, "%s %s", conn->priv.request, conn->url);
    }

    conn->headers = e;
    return status;
}

static ehttpd_cb_status_t parse_headers(ehttpd_conn_t *conn)
{
    ehttpd_cb_status_t status = EHTTPD_CB_SUCCESS;
    const char *value;

    conn->hostname = ehttpd_get_header(conn, "Host");

    value = ehttpd_get_header(conn, "Content-Length");
    if (value != NULL) {
        if (conn->post == NULL) {
            conn->post = malloc(sizeof(ehttpd_post_t));
            if (conn->post == NULL) {
                EHTTPD_LOGE(__func__, "malloc failed %d bytes", sizeof(ehttpd_post_t));
                return EHTTPD_CB_ERROR_MEMORY;
            } else {
                memset(conn->post, 0, sizeof(*conn->post));
            }
        }
        if (conn->post != NULL) {
            conn->post->len = atoi(value);
        }
    }

    value = ehttpd_get_header(conn, "Content-Type");
    if (value != NULL) {
        if (strstr(value, "multipart/form-data")) {
            // It's multipart form data so let's pull out the boundary
            // TODO: implement multipart support in the server
            if (conn->post == NULL) {
                conn->post = malloc(sizeof(ehttpd_post_t));
                if (conn->post == NULL) {
                    EHTTPD_LOGE(__func__, "malloc failed %d bytes", sizeof(ehttpd_post_t));
                    return EHTTPD_CB_ERROR_MEMORY;
                } else {
                    memset(conn->post, 0, sizeof(*conn->post));
                }
            }
            if (conn->post != NULL) {
                char *b;
                const char *boundaryToken = "boundary=";
                if ((b = strstr(value, boundaryToken)) != NULL) {
                    conn->post->boundary = b + strlen(boundaryToken);
                    EHTTPD_LOGD(__func__, "boundary = %s", conn->post->boundary);
                }
            }
        }
    }

    value = ehttpd_get_header(conn, "Connection");
    if (value != NULL) {
        if (strstr(value, "keep-alive")) {
            conn->priv.flags |= HFL_RECEIVED_CONN_ALIVE;
        } else if (strstr(value, "close")) {
            conn->priv.flags |= HFL_RECEIVED_CONN_CLOSE;
        }
    }

    return status;
}

// Callback called when there's data available on a socket.
ehttpd_cb_status_t ehttpd_recv_cb(ehttpd_conn_t *conn, void *buf, size_t len)
{
    ehttpd_cb_status_t status = EHTTPD_CB_SUCCESS;

    ehttpd_lock(conn->inst);

    if (conn->closed) {
        if (conn->route) {
            conn->route->handler(conn); // Execute handler if needed
        }
        if (conn->post) {
            free(conn->post);
        }
        ehttpd_unlock(conn->inst);
        return EHTTPD_CB_CLOSED;
    }

    char *data = buf;

    if (!conn->headers) {
        EHTTPD_LOGD(__func__, "new request %p", conn);
        conn->priv.flags |= HFL_REQUEST_STARTED;
#if defined(CONFIG_EHTTPD_DEFAULT_CLOSE)
        conn->priv.flags |= HFL_REQUEST_CLOSE;
#endif

        data = strnstr(data, "\r\n\r\n", len);

        if ((data == NULL) ||
                (data - (char *) buf > CONFIG_EHTTPD_MAX_REQUEST_SIZE - 2)) {
            EHTTPD_LOGE(__func__, "request too long");
            return EHTTPD_CB_ERROR_MEMORY;
        }

        /* save the request */
        char *p = conn->priv.request;
        memcpy(p, buf, data - (char *)buf);

        /* triple terminate */
        p[data - (char *) buf + 1] = '\0';
        p[data - (char *) buf + 2] = '\0';

        while (*p) {
            p = strchr(p, ':');
            if (!p) {
                break;
            }
            *p++ = '\0';
            p = strchr(p, '\r');
            if (!p) {
                break;
            }
            *p++ = '\0';
            p++;
        }

        parse_request(conn);
        parse_headers(conn);

        len -= data - (char *) buf + 4;
        data = data + 4;
    }

    if (conn->post == NULL) {
        if (len > 0) {
            if (conn->recv_handler) {
                ehttpd_status_t status = conn->recv_handler(conn, data, len);
                if (status == EHTTPD_STATUS_DONE) {
                    EHTTPD_LOGD(__func__, "recv_handler done");
                    ehttpd_end_request(conn);
                }
            } else {
                EHTTPD_LOGE(__func__, "unexpected data");
                ehttpd_unlock(conn->inst);
                return EHTTPD_CB_ERROR;
            }
        } else {
            process_request(conn);
        }
    } else if (conn->post != NULL) {
        if (conn->post->received + len > conn->post->len) {
            EHTTPD_LOGE(__func__, "unexpected data");
            ehttpd_unlock(conn->inst);
            return EHTTPD_CB_ERROR;
        }
        memcpy(conn->post->buf, data, len);
        conn->post->buf_len = len;
        conn->post->received += len;
        if (conn->post->received == conn->post->len) {
            if (conn->route) {
                ehttpd_status_t status = conn->route->handler(conn);
                if (status == EHTTPD_STATUS_DONE) {
                    ehttpd_end_request(conn);
                }
            } else {
                process_request(conn);
            }
        }
    }

    ehttpd_flush(conn);
    ehttpd_unlock(conn->inst);

    return status;
}
