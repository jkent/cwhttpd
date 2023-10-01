/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
Route handlers to let httpd use the filesystem to serve the files in it.
*/

#include "log.h"
#include "cwhttpd/route.h"
#include "cwhttpd/httpd.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/unistd.h>
#include <sys/stat.h>
#include <sys/errno.h>


#define TRY(X) ({ \
    ssize_t n = X; \
    if (n < 0) { \
        r = CWHTTPD_STATUS_FAIL; \
        goto cleanup; \
    } \
    n; \
})

#define FILE_CHUNK_LEN    (1024)
#define MAX_FILENAME_LENGTH (256)

#define ESPFS_FLAG_GZIP (1 << 1)

#define F_REOPEN_RAW 1000


static bool get_filepath(cwhttpd_conn_t *conn, char *path, size_t len,
        struct stat *st, const char *index)
{
    size_t out_len = 0;
    const char *url = conn->request.url;
    const cwhttpd_route_t *route = conn->route;
    const char *rpath = route->path;

    while (*rpath == *url) {
        rpath++;
        url++;
    }
    while (*url == '/') {
        url++;
    }

    out_len = 0;
    if (route->argc < 1) {
        out_len += strlcpy(path + out_len, url, len - out_len);
    } else {
        out_len += strlcpy(path + out_len, route->argv[0], len - out_len);
        if (path[out_len - 1] == '/') {
            out_len += strlcpy(path + out_len, url, len - out_len);
        }
    }
    if (path[out_len - 1] == '/') {
        out_len += strlcpy(path + out_len, index, len - out_len);
    }

    if (stat(path, st) != 0) {
        return false;
    }

    if (S_ISDIR(st->st_mode)) {
        out_len += strlcpy(path + out_len, "/", len - out_len);
        out_len += strlcpy(path + out_len, index, len - out_len);
        if (stat(path, st) != 0) {
            return false;
        }
    }

    if (S_ISREG(st->st_mode)) {
        return true;
    }

    return false;
}

cwhttpd_status_t cwhttpd_route_fs_get(cwhttpd_conn_t *conn)
{
    cwhttpd_status_t r = CWHTTPD_STATUS_DONE;

    /* Only process GET requests, otherwise fallthrough */
    if (conn->request.method != CWHTTPD_METHOD_GET) {
        return CWHTTPD_STATUS_NOTFOUND;
    }

    /* We can use buf here because its not needed until reading data */
    char buf[FILE_CHUNK_LEN];
    struct stat st;
    if (!get_filepath(conn, buf, sizeof(buf), &st, "index.html")) {
        return CWHTTPD_STATUS_NOTFOUND;
    }

    bool deflate_compression = false;
#if defined(ESP_PLATFORM)
    if (st.st_spare4[0] == 0x474F5246) { /* FROG */
        if ((st.st_spare4[1] & 0xFF) == 1) {
            deflate_compression = true;
        }
    }
#endif

    const char *mimetype = cwhttpd_get_mimetype(buf);

    FILE *f = fopen(buf, "r");
    if (f == NULL) {
        return CWHTTPD_STATUS_NOTFOUND;
    }

    if (deflate_compression) {
        /* Check the request Accept-Encoding header for deflate. Reopen raw
         * if present */
        const char *header = cwhttpd_get_header(conn, "Accept-Encoding");
        if (header && strstr(header, "deflate") == NULL) {
            deflate_compression = false;
        }
    }
    if (deflate_compression && fcntl(fileno(f), F_REOPEN_RAW) != 0) {
        deflate_compression = false;
    }
    if (deflate_compression && fstat(fileno(f), &st) != 0) {
        deflate_compression = false;
    }

    TRY(cwhttpd_response(conn, 200));
    if (deflate_compression) {
        TRY(cwhttpd_send_header(conn, "Content-Encoding", "deflate"));
    }
    if (mimetype) {
        TRY(cwhttpd_send_header(conn, "Content-Type", mimetype));
    }
    TRY(cwhttpd_send_cache_header(conn, mimetype));

    size_t len;
    TRY(cwhttpd_chunk_start(conn, st.st_size));
    while ((len = fread(buf, 1, FILE_CHUNK_LEN, f)) > 0) {
        TRY(cwhttpd_send(conn, buf, len));
    }
    TRY(cwhttpd_chunk_end(conn));

cleanup:
    fclose(f);
    return r;
}

cwhttpd_status_t cwhttpd_route_fs_tpl(cwhttpd_conn_t *conn)
{
    cwhttpd_status_t r = CWHTTPD_STATUS_DONE;

    /* Only process GET requests, otherwise fallthrough */
    if (conn->request.method != CWHTTPD_METHOD_GET) {
        return CWHTTPD_STATUS_NOTFOUND;
    }

    /* We can use buf here because its not needed until reading data */
    char buf[FILE_CHUNK_LEN];
    struct stat st;
    if (!get_filepath(conn, buf, sizeof(buf), &st, "index.tpl")) {
        return CWHTTPD_STATUS_NOTFOUND;
    }

    const char *mimetype = cwhttpd_get_mimetype(buf);

    FILE *f = fopen(buf, "r");
    if (f == NULL) {
        return CWHTTPD_STATUS_NOTFOUND;
    }

    cwhttpd_tpl_cb_t cb = conn->route->argv[1];
    TRY(cwhttpd_response(conn, 200));
    if (mimetype) {
        TRY(cwhttpd_send_header(conn, "Content-Type", mimetype));
    }

    void *user = NULL;
    size_t len;
    int token_pos = -1;
    char token[32];
    do {
        len = fread(buf, 1, FILE_CHUNK_LEN, f);
        int raw_count = 0;
        uint8_t *p = (uint8_t *) buf;
        if (len > 0) {
            for (size_t i = 0; i < len; i++) {
                if (token_pos < 0) {
                    /* we're in ordinary text */
                    if (buf[i] == '%') {
                        /* send collected raw data */
                        if (raw_count != 0) {
                            TRY(cwhttpd_send(conn, p, raw_count));
                            raw_count = 0;
                        }
                        /* start collecting token chars */
                        token_pos = 0;
                    } else {
                        raw_count++;
                    }
                } else {
                    /* we're in token text */
                    if (buf[i] == '%') {
                        if (token_pos == 0) {
                            /* this is an escape sequence */
                            TRY(cwhttpd_send(conn, "%", 1));
                        } else {
                            /* this is a token */
                            token[token_pos] = '\0'; /* zero terminate */
                            cb(conn, token, &user);
                        }

                        /* collect normal characters again */
                        p = (uint8_t *) &buf[i + 1];
                        token_pos = -1;
                    } else {
                        if (token_pos < (sizeof(token) - 1)) {
                            token[token_pos++] = buf[i];
                        }
                    }
                }
            }
        }

        /* send remainder */
        if (raw_count != 0) {
            TRY(cwhttpd_send(conn, p, raw_count));
        }
    } while (len == FILE_CHUNK_LEN);

cleanup:
    /* we're done */
    cb(conn, NULL, &user);
    fclose(f);
    return r;
}
