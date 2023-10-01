/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* Copyright 2017 Jeroen Domburg <git@j0h.nl> */
/* Copyright 2017 Chris Morgan <chmorgan@gmail.com> */
/* Copyright 2021 Jeff Kent <jeff@jkent.net> */

#include "cb.h"
#include "log.h"
#include "cwhttpd/httpd.h"
#include "cwhttpd/httpd_priv.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>


#define MIN(a, b) ({ \
    __typeof__(a) _a = a; \
    __typeof__(b) _b = b; \
    _a < _b ? _a : _b; \
})

/*******************************
 * \section Instance Functions
 *******************************/

void cwhttpd_route_vinsert(cwhttpd_inst_t *inst, ssize_t index, const char *path,
        cwhttpd_route_handler_t handler, size_t argc, va_list args)
{
    cwhttpd_route_t *new_route = calloc(1,
            sizeof(cwhttpd_route_t) + (sizeof(void *) * argc));
    if (new_route == NULL) {
        return;
    }

    if (index < 0) {
        index = inst->num_routes + index;
        if (index >= inst->num_routes) {
            index = 0;
        }
    } else if (index >= inst->num_routes) {
        index = inst->num_routes;
    }

    if (inst->num_routes == 0) {
        inst->route_head = new_route;
        inst->route_tail = new_route;
    } else if (index == 0) {
        new_route->next = inst->route_head;
        inst->route_head = new_route;
    } else if (index == inst->num_routes) {
        inst->route_tail->next = new_route;
        inst->route_tail = new_route;
    } else {
        cwhttpd_route_t *route = inst->route_head;
        for (int i = 0; i < index - 1; i++) {
            route = route->next;
        }
        new_route->next = route->next;
        route->next = new_route;
    }

    new_route->path = path;
    new_route->handler = handler;
    new_route->argc = argc;
    for (int i = 0; i < argc; i++) {
        new_route->argv[i] = va_arg(args, void *);
    }
    inst->num_routes++;
}

void cwhttpd_route_insert(cwhttpd_inst_t *inst, ssize_t index, const char *path,
        cwhttpd_route_handler_t handler, size_t argc, ...)
{
    va_list args;

    va_start(args, argc);
    cwhttpd_route_vinsert(inst, index, path, handler, argc, args);
    va_end(args);
}

void cwhttpd_route_append(cwhttpd_inst_t *inst, const char *path,
        cwhttpd_route_handler_t handler, size_t argc, ...)
{
    va_list args;

    va_start(args, argc);
    cwhttpd_route_vinsert(inst, inst->num_routes, path, handler, argc, args);
    va_end(args);
}

cwhttpd_route_t *cwhttpd_route_get(cwhttpd_inst_t *inst, ssize_t index)
{
    if (inst->num_routes == 0) {
        return NULL;
    } else if (index < 0) {
        index = inst->num_routes + index;
        if (index >= inst->num_routes) {
            index = 0;
        }
    } else if (index >= inst->num_routes - 1) {
        index = inst->num_routes - 1;
    }

    cwhttpd_route_t *route = inst->route_head;
    for (int i = 0; i < index - 1; i++) {
        route = route->next;
    }
    return route;
}

void cwhttpd_route_remove(cwhttpd_inst_t *inst, ssize_t index)
{
    if (inst->num_routes == 0) {
        return;
    } else if (index < 0) {
        index = inst->num_routes + index;
        if (index >= inst->num_routes) {
            index = 0;
        }
    } else if (index >= inst->num_routes - 1) {
        index = inst->num_routes - 1;
    }

    cwhttpd_route_t *route = inst->route_head;
    if (index == 0) {
        inst->route_head = route->next;
        if (inst->num_routes == 2) {
            inst->route_tail = route->next;
        } else if (inst->num_routes == 1) {
            inst->route_tail = NULL;
        }
    } else {
        for (int i = 0; i < index - 1; i++) {
            route = route->next;
        }
        cwhttpd_route_t *temp = route->next;
        route->next = route->next->next;
        if (index == inst->num_routes - 1) {
            inst->route_tail = route;
        }
        route = temp;
    }

    free(route);
    inst->num_routes--;
}


/*********************************
 * \section Connection Functions
 *********************************/

ssize_t cwhttpd_recv(cwhttpd_conn_t *conn, void *buf, size_t len)
{
    size_t datalen = conn->priv.data - conn->priv.req - conn->priv.req_len;
    if (datalen > 0) {
        len = (len > datalen) ? datalen : len;
        memcpy(buf, conn->priv.data, len);
        conn->priv.data += len;
        return len;
    }

    return cwhttpd_plat_recv(conn, buf, len);
}

ssize_t cwhttpd_send(cwhttpd_conn_t *conn, const void *buf, ssize_t len)
{
    if (len < 0) {
        len = strlen(buf);
    }

    if (!(conn->priv.flags & HFL_SENT_HEADERS)) {
        /* End headers if we're sending data */
        if (conn->priv.flags & HFL_SEND_CHUNKED) {
            cwhttpd_send_header(conn, "Transfer-Encoding", "chunked");
        }
        if (conn->priv.flags & HFL_REQUEST_CLOSE) {
            cwhttpd_send_header(conn, "Connection", "close");
        } else if (!(conn->priv.flags & HFL_SENT_CONTENT_LENGTH)) {
            if (!(conn->priv.flags & HFL_SEND_CHUNKED)) {
                if (conn->priv.flags & HFL_RECEIVED_HTTP11) {
                    cwhttpd_send_header(conn, "Connection", "close");
                }
            }
        } else if (conn->priv.flags & HFL_RECEIVED_CONN_ALIVE) {
            cwhttpd_send_header(conn, "Connection", "keep-alive");
        }
        cwhttpd_plat_send(conn, "\r\n", 2);
        conn->priv.flags |= HFL_SENT_HEADERS;
    }

    bool end_chunk = false;
    size_t count = 0;
    if (conn->priv.flags & HFL_SEND_CHUNKED) {
        ssize_t ret;
        if (!(conn->priv.flags & HFL_SENDING_CHUNK)) {
            end_chunk = true;
            conn->priv.chunk_left = len;
            ret = cwhttpd_chunk_start(conn, len);
            if (ret < 0) {
                return ret;
            }
            count += ret;
        }
        if (len > conn->priv.chunk_left) {
            LOGE(__func__, "chunk overflow");
            return -1;
        }
        conn->priv.chunk_left -= len;
        ret = cwhttpd_plat_send(conn, buf, len);
        if (ret < 0) {
            return ret;
        }
        count += ret;
        if (end_chunk) {
            ret = cwhttpd_chunk_end(conn);
            if (ret < 0) {
                return ret;
            }
            count += ret;
        }
    } else {
        conn->priv.chunk_left -= len;
        count = cwhttpd_plat_send(conn, buf, len);
    }

    if (len == 0) {
        conn->priv.flags |= HFL_SENT_FINAL_CHUNK;
    }

    return count;
}

ssize_t cwhttpd_sendf(cwhttpd_conn_t *conn, const char *fmt, ...)
{
    va_list va;

    va_start(va, fmt);
    size_t len = cwhttpd_vsnprintf(NULL, 0, fmt, va);
    va_end(va);

    char *buf = malloc(len + 1);
    if (buf == NULL) {
        return -1;
    }

    va_start(va, fmt);
    cwhttpd_vsnprintf(buf, len + 1, fmt, va);
    va_end(va);

    if (conn->priv.flags & HFL_SENDING_HEADER) {
        cwhttpd_plat_send(conn, buf, len);
    } else {
        cwhttpd_send(conn, buf, len);
    }

    free(buf);
    return len;
}

const char *cwhttpd_get_header(cwhttpd_conn_t *conn, const char *name)
{
    char *p = conn->request.headers;
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

void cwhttpd_set_chunked(cwhttpd_conn_t *conn, bool enable)
{
    if (conn->priv.flags & HFL_SENT_HEADERS) {
        LOGE(__func__, "headers already sent");
        return;
    }

    conn->priv.flags &= ~HFL_SEND_CHUNKED;
    if (enable && (conn->priv.flags & HFL_RECEIVED_HTTP11)) {
        conn->priv.flags |= HFL_SEND_CHUNKED;
    }
}

void cwhttpd_set_close(cwhttpd_conn_t *conn, bool close)
{
    if (conn->priv.flags & HFL_SENT_HEADERS) {
        LOGE(__func__, "headers already sent");
        return;
    }

    if (close) {
        LOGI(__func__, "requesting close %p", conn);
        conn->priv.flags |= HFL_REQUEST_CLOSE;
    } else {
        conn->priv.flags &= ~HFL_REQUEST_CLOSE;
    }
}

ssize_t cwhttpd_response(cwhttpd_conn_t *conn, int code)
{
    const char *message;

    if (conn->priv.flags & HFL_SENT_RESPONSE) {
        LOGE(__func__, "response already sent");
        return 0;
    }

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

    size_t total = 0;

    uint32_t flags = conn->priv.flags;
    conn->priv.flags |= HFL_SENDING_HEADER;
    ssize_t r = cwhttpd_sendf(conn, "HTTP/1.%d %d %s\r\n",
            (conn->priv.flags & HFL_RECEIVED_HTTP11) ? 1 : 0, code, message);
    conn->priv.flags = flags | HFL_SENT_RESPONSE;
    if (r <= 0) {
        return r;
    }
    total = r;

    r = cwhttpd_send_header(conn, "Server", "cwhttpd/" CWHTTPD_VERSION);
    if (r <= 0) {
        return r;
    }
    total += r;

    return total;
}

ssize_t cwhttpd_send_header(cwhttpd_conn_t *conn, const char *name, const char *value)
{
    if (conn->priv.flags & HFL_SENT_HEADERS) {
        LOGE(__func__, "headers already sent");
        return 0;
    }

    if (strcasecmp(name, "Content-Length") == 0) {
        conn->priv.chunk_left = strtol(value, NULL, 10);
        conn->priv.flags |= HFL_SENT_CONTENT_LENGTH;
    }

    if ((strcasecmp(name, "Connection") == 0) &&
            (strcasecmp(name, "close") == 0)) {
        conn->priv.flags |= HFL_SENT_CONN_CLOSE;
    }

    uint32_t flags = conn->priv.flags;
    conn->priv.flags |= HFL_SENDING_HEADER;
    ssize_t r = cwhttpd_sendf(conn, "%s: %s\r\n", name, value);
    conn->priv.flags = flags;

    return r;
}

ssize_t cwhttpd_send_cache_header(cwhttpd_conn_t *conn, const char *mime)
{
    if (mime != NULL) {
        if (strcmp(mime, "text/html") == 0) {
            return 0;
        }
        if (strcmp(mime, "text/plain") == 0) {
            return 0;
        }
        if (strcmp(mime, "text/csv") == 0) {
            return 0;
        }
        if (strcmp(mime, "application/json") == 0) {
            return 0;
        }
    }

    return cwhttpd_send_header(conn, "Cache-Control",
            "max-age=7200, public, must-revalidate");
}

ssize_t cwhttpd_chunk_start(cwhttpd_conn_t *conn, size_t len)
{
    if (!(conn->priv.flags & HFL_SEND_CHUNKED)) {
        return 0;
    }
    if (conn->priv.flags & HFL_SENDING_CHUNK) {
        LOGE(__func__, "chunk framing");
        return -1;
    }
    conn->priv.flags |= HFL_SENDING_CHUNK;
    conn->priv.chunk_left = 10;
    ssize_t ret = cwhttpd_sendf(conn, "%x\r\n", len);
    conn->priv.chunk_left = len;
    return ret;
}

ssize_t cwhttpd_chunk_end(cwhttpd_conn_t *conn)
{
    if (!(conn->priv.flags & HFL_SEND_CHUNKED)) {
        return 0;
    }
    if (!(conn->priv.flags & HFL_SENDING_CHUNK) ||
            (conn->priv.chunk_left != 0)) {
        LOGE(__func__, "chunk framing");
        return -1;
    }
    ssize_t ret = cwhttpd_plat_send(conn, "\r\n", 2);
    conn->priv.flags &= ~HFL_SENDING_CHUNK;
    return ret;
}


/******************************
 * \section Utility Functions
 ******************************/

__attribute__((__weak__))
cwhttpd_status_t cwhttpd_route_404(cwhttpd_conn_t *conn)
{
    LOGD(__func__, "%p", conn);
    cwhttpd_response(conn, 404);
    cwhttpd_send(conn, "file not found", -1);
    return CWHTTPD_STATUS_DONE;
}

void cwhttpd_redirect(cwhttpd_conn_t *conn, const char *url)
{
    cwhttpd_response(conn, 302);
    cwhttpd_send_header(conn, "Location", url);
}

// Returns a static char *to a mime type for a given url to a file.
const char *cwhttpd_get_mimetype(const char *url)
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

size_t cwhttpd_url_decode(const char *in, ssize_t in_len, char *out,
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

ssize_t cwhttpd_find_param(const char *needle, const char *haystack, char *out,
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
            return cwhttpd_url_decode(p, end - p, out, out_len);
        }
        p = strchr(p, '&');
        if (p != NULL) {
            p += 1;
        }
    }
    return -1;
}


/*******************************
 * \section Connection Handler
 *******************************/

/* This list must be kept in sync with the cwhttpd_method_t enum in httpd.h */
static const char *cwhttpd_methods[] = {
    "GET",
    "POST",
    "OPTIONS",
    "PUT",
    "PATCH",
    "DELETE",
};

static bool parse_request(cwhttpd_conn_t *conn)
{
    char *e = conn->priv.req;
    const char *method = e;
    if ((e = strchr(e, ' ')) == NULL) {
        return false;
    }
    *e++ = '\0';

    // Skip past spaces after the method
    while (*e == ' ') {
        e++;
    }
    conn->request.url = e;

    // Remove extra slashes in url
    char last = '\0';
    char *p = e;
    int n = 0;
    while (*e && *e != '\n') {
        if (*e == '\r' || *e == '\n') {
            return false;
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
        conn->request.args = e;
        while (*e && *e != ' ') {
            if (*e == '\r' || *e == '\n') {
                return false;
            }
            e++;
        }
        last = *e;
        *e++ = '\0';
    }

    // Skip past spaces before HTTP version
    if (last == ' ') {
        while (*e == ' ') {
            if (*e == '\r' || *e == '\n') {
                return false;
            }
            e++;
        }
        const char *version = e;
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
        if (strcasecmp(version, "HTTP/1.1") == 0) {
            conn->priv.flags |= HFL_RECEIVED_HTTP11;
            conn->priv.flags |= HFL_SEND_CHUNKED;
        }
    }

    if (conn->request.args) {
        LOGD(__func__, "%s %s?%s %p", conn->priv.req, conn->request.url,
                conn->request.args, conn);
    } else {
        LOGD(__func__, "%s %s %p", conn->priv.req, conn->request.url,
                conn);
    }

    conn->request.headers = e;

    for (conn->request.method = CWHTTPD_METHOD_GET;
            conn->request.method < CWHTTPD_METHOD_UNKNOWN;
            conn->request.method++) {
        if (strcasecmp(method, cwhttpd_methods[conn->request.method]) == 0) {
            break;
        }
    }

    return true;
}

static bool parse_headers(cwhttpd_conn_t *conn)
{
    const char *value;
    char *p = conn->request.headers;

    /* terminate headers */
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

    conn->request.hostname = cwhttpd_get_header(conn, "Host");

    value = cwhttpd_get_header(conn, "Content-Length");
    if (value != NULL) {
        if (conn->post == NULL) {
            conn->post = calloc(1, sizeof(cwhttpd_post_t));
            if (conn->post == NULL) {
                LOGE(__func__, "calloc failed %d bytes",
                        sizeof(cwhttpd_post_t));
                return false;
            }
        }
        if (conn->post != NULL) {
            conn->post->len = atoi(value);
        }
    }

    value = cwhttpd_get_header(conn, "Content-Type");
    if (value != NULL) {
        if (strstr(value, "multipart/form-data")) {
            // It's multipart form data so let's pull out the boundary
            // TODO: implement multipart support in the server
            if (conn->post == NULL) {
                conn->post = calloc(1, sizeof(cwhttpd_post_t));
                if (conn->post == NULL) {
                    LOGE(__func__, "calloc failed %d bytes",
                            sizeof(cwhttpd_post_t));
                    return false;
                }
            }
            if (conn->post != NULL) {
                char *b;
                const char *boundaryToken = "boundary=";
                if ((b = strstr(value, boundaryToken)) != NULL) {
                    conn->post->boundary = b + strlen(boundaryToken);
                    LOGD(__func__, "boundary = %s", conn->post->boundary);
                }
            }
        }
    }

    value = cwhttpd_get_header(conn, "Connection");
    if (value != NULL) {
        if (strstr(value, "keep-alive")) {
            conn->priv.flags |= HFL_RECEIVED_CONN_ALIVE;
        } else if (strstr(value, "close")) {
            conn->priv.flags |= HFL_RECEIVED_CONN_CLOSE;
        }
    }

    return true;
}

static const cwhttpd_route_t route_404 = {NULL, cwhttpd_route_404, NULL, 0};

// renamed to my_strnstr incase name conflict with library version
static char *my_strnstr(const char *s1, const char *s2, size_t n)
{   // simplistic algorithm with O(n2) worst case

    size_t i, len;
    char c = *s2;

    if (c == '\0')
        return (char *)s1;

    for (len = strlen(s2); len <= n; n--, s1++) {
        if (*s1 == c) {
            for (i = 1;; i++) {
                if (i == len)
                    return (char *)s1;
                if (s1[i] != s2[i])
                    break;
            }
        }
    }
    return NULL;
}

void cwhttpd_new_conn_cb(cwhttpd_conn_t *conn)
{
    bool first_request = true;

    do {
        if (!first_request) {
            if (conn->post) {
                free(conn->post);
            }
            if (!(conn->priv.flags & HFL_CLOSE)) {
                cwhttpd_inst_t *inst = conn->inst;
                memset(conn, 0, sizeof(*conn));
                conn->inst = inst;
                LOGV(__func__, "conn cleaned %p", conn);
            }
        }
        first_request = false;

        ssize_t len = cwhttpd_plat_recv(conn, conn->priv.req,
                CONFIG_CWHTTPD_MAX_REQUEST_SIZE);
        if (len <= 0) {
            return;
        }
        conn->priv.req_len = len;
        conn->priv.data = my_strnstr(conn->priv.req, "\r\n\r\n",
                conn->priv.req_len);
        if (conn->priv.data == NULL) {
            cwhttpd_response(conn, 400);
            return;
        }

        /* double terminate */
        conn->priv.data[0] = '\0';
        conn->priv.data[1] = '\0';
        conn->priv.data += 4;

        if (!parse_request(conn)) {
            cwhttpd_response(conn, 400);
            return;
        }

#ifdef CONFIG_CWHTTPD_ENABLE_CORS
        /* CORS preflight */
        if (conn->request.method == CWHTTPD_METHOD_OPTIONS) {
            cwhttpd_set_chunked(conn, false);
            cwhttpd_response(conn, 204);
            cwhttpd_send_header(conn, "Access-Control-Allow-Origin",
                    CONFIG_CWHTTPD_CORS_ORIGIN);
            cwhttpd_send_header(conn, "Access-Control-Allow-Methods",
                    CONFIG_CWHTTPD_CORS_METHODS);
            continue;
        }
#endif

        if (!parse_headers(conn)) {
            cwhttpd_response(conn, 500);
            return;
        }

        const cwhttpd_route_t *route = conn->inst->route_head;
        while (true) {
            while (route != NULL) {
                if ((strcmp(route->path, conn->request.url) == 0) ||
                        ((route->path[strlen(route->path) - 1] == '*') &&
                        (strncmp(route->path, conn->request.url,
                                strlen(route->path) - 1) == 0))) {
                    conn->route = route;
                    break;
                }
                route = route->next;
            }

            if (route == NULL) {
                conn->route = &route_404;
            }

more:
            if (conn->post && conn->post->received < conn->post->len) {
                ssize_t chunk;
                if (conn->priv.req_len - (conn->priv.data -
                        conn->priv.req) > 0) {
                    chunk = MIN(conn->priv.req_len -
                            (conn->priv.data - conn->priv.req),
                            sizeof(conn->post->buf) - conn->post->buf_len);
                    memcpy(conn->post->buf + conn->post->buf_len,
                            conn->priv.data, chunk);
                    conn->priv.data += chunk;
                } else {
                    chunk = cwhttpd_plat_recv(conn, conn->post->buf +
                            conn->post->buf_len, MIN(conn->post->len,
                            sizeof(conn->post->buf) - conn->post->buf_len));
                    if (chunk < 0) {
                        return;
                    }
                }
                conn->post->buf_len += chunk;
                conn->post->received += chunk;
            }

            cwhttpd_status_t status = conn->route->handler(conn);
            if ((status == CWHTTPD_STATUS_NOTFOUND) ||
                    (status == CWHTTPD_STATUS_AUTHENTICATED)) {
                route = route->next;
            } else if (status == CWHTTPD_STATUS_MORE) {
                goto more;
            } else if (status == CWHTTPD_STATUS_DONE) {
                break;
            } else if (status == CWHTTPD_STATUS_CLOSE) {
                conn->priv.flags |= HFL_CLOSE;
                break;
            } else if (status == CWHTTPD_STATUS_FAIL) {
                return;
            }
        }

        if (conn->priv.flags & HFL_SEND_CHUNKED) {
            if (conn->priv.flags & HFL_SENDING_CHUNK) {
                cwhttpd_chunk_end(conn);
            }
            if (!(conn->priv.flags & HFL_SENT_FINAL_CHUNK)) {
                cwhttpd_send(conn, NULL, 0);
            }
        } else if (conn->priv.flags & HFL_SENT_CONTENT_LENGTH) {
            if (conn->priv.chunk_left != 0) {
                LOGE(__func__, "Content-Length header does not match "
                        "sent length %p", conn);
                break;
            }
        }
    } while (!(conn->priv.flags & HFL_CLOSE));
}
