/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "log.h"
#include "libesphttpd/route.h"
#include "libesphttpd/httpd.h"
#include "../../libespfs/include/libespfs/espfs.h"

#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#if defined(UNIX)
# include <bsd/string.h>
#endif


#define TRY(X) ({ \
    ssize_t n = X; \
    if (n < 0) { \
        r = EHTTPD_STATUS_FAIL; \
        goto cleanup; \
    } \
    n; \
})

#define FILE_CHUNK_LEN (1024)

static ehttpd_status_t get_filepath(ehttpd_conn_t *conn, char *path,
        size_t len, espfs_stat_t *s, const char *index)
{
    size_t out_len = 0;
    const char *url = conn->request.url;
    const ehttpd_route_t *route = conn->route;
    const char *rpath = route->path;

    while (*url && *rpath == *url) {
        rpath++;
        url++;
    }

    if (route->argc < 1) {
        out_len = strlcpy(path, url, len);
        if (path[out_len - 1] == '/') {
            if (index == NULL) {
                path[out_len - 1] = '\0';
                out_len -= 1;
            } else {
                out_len += strlcpy(path + out_len, index, len - out_len);
            }
        }
    } else {
        out_len = strlcpy(path, route->argv[0], len);
        if (path[out_len - 1] == '/') {
            out_len += strlcpy(path + out_len, url, len - out_len);
            if (path[out_len - 1] == '/') {
                if (index == NULL) {
                    path[out_len - 1] = '\0';
                    out_len -= 1;
                } else {
                    out_len += strlcpy(path + out_len, index, len - out_len);
                }
            }
        }
    }

    if (!espfs_stat(conn->inst->espfs, path, s)) {
        return EHTTPD_STATUS_NOTFOUND;
    }

    if ((index == NULL) && (s->type == ESPFS_TYPE_DIR)) {
        out_len += strlcpy(path + out_len, "/", len - out_len);
        return EHTTPD_STATUS_OK;
    }

    if (s->type == ESPFS_TYPE_FILE) {
        return EHTTPD_STATUS_OK;
    }

    if (s->type == ESPFS_TYPE_DIR) {
        out_len += strlcpy(path + out_len, "/", len - out_len);
        char *p = path + out_len;
        out_len += strlcpy(path + out_len, index, len - out_len);
        if (!espfs_stat(conn->inst->espfs, path, s)) {
            return EHTTPD_STATUS_NOTFOUND;
        }
        if (s->type == ESPFS_TYPE_FILE) {
            *p = '\0';
            ehttpd_redirect(conn, path);
            return EHTTPD_STATUS_DONE;
        }
    }

    return EHTTPD_STATUS_NOTFOUND;
}

ehttpd_status_t ehttpd_route_espfs_get(ehttpd_conn_t *conn)
{
    ehttpd_status_t r = EHTTPD_STATUS_DONE;

    /* Only process GET requests, otherwise fallthrough */
    if (conn->request.method != EHTTPD_METHOD_GET) {
        return EHTTPD_STATUS_NOTFOUND;
    }

    /* We can use buf here because its not needed until reading data */
    char buf[FILE_CHUNK_LEN];
    espfs_stat_t st;
    ehttpd_status_t status = get_filepath(conn, buf, sizeof(buf), &st,
            "index.html");
    if (status != EHTTPD_STATUS_OK) {
        return status;
    }

    espfs_file_t *f = espfs_fopen(conn->inst->espfs, buf);
    if (f == NULL) {
        return EHTTPD_STATUS_NOTFOUND;
    }

    const char *mimetype = ehttpd_get_mimetype(buf);

    bool gzip_encoding = (st.flags & ESPFS_FLAG_GZIP);
    if (gzip_encoding) {
        /* Check the request Accept-Encoding header for gzip. Return a 404
         * response if not present */
        const char *header = ehttpd_get_header(conn, "Accept-Encoding");
        if (header && strstr(header, "gzip") == NULL) {
            EHTTPD_LOGW(__func__, "client does not accept gzip!");
            espfs_fclose(f);
            TRY(ehttpd_response(conn, 404));
            TRY(ehttpd_send_header(conn, "Content-Type", "text/plain"));
            TRY(ehttpd_send(conn, "only gzip file available", -1));
            return EHTTPD_STATUS_DONE;
        }
    }

    ehttpd_set_chunked(conn, false);
    TRY(ehttpd_response(conn, 200));
    if (gzip_encoding) {
        TRY(ehttpd_send_header(conn, "Content-Encoding", "gzip"));
    }
    if (!(conn->priv.flags & HFL_SEND_CHUNKED)) {
        snprintf(buf, sizeof(buf), "%d", st.size);
        TRY(ehttpd_send_header(conn, "Content-Length", buf));
    }
    if (mimetype) {
        TRY(ehttpd_send_header(conn, "Content-Type", mimetype));
    }
    if (st.flags & ESPFS_FLAG_CACHE) {
        TRY(ehttpd_send_cache_header(conn, NULL));
    }

    ssize_t len;
    TRY(ehttpd_chunk_start(conn, st.size));
    while ((len = espfs_fread(f, buf, sizeof(buf))) > 0) {
        TRY(ehttpd_send(conn, buf, len));
    }
    TRY(ehttpd_chunk_end(conn));

cleanup:
    espfs_fclose(f);
    return r;
}

ehttpd_status_t ehttpd_route_espfs_tpl(ehttpd_conn_t *conn)
{
    ehttpd_status_t r = EHTTPD_STATUS_DONE;

    /* Only process GET requests, otherwise fallthrough */
    if (conn->request.method != EHTTPD_METHOD_GET) {
        return EHTTPD_STATUS_NOTFOUND;
    }

    /* We can use buf here because its not needed until reading data */
    char buf[FILE_CHUNK_LEN];
    espfs_stat_t st;
    if (!get_filepath(conn, buf, sizeof(buf), &st, "index.tpl")) {
        return EHTTPD_STATUS_NOTFOUND;
    }

    if (st.flags & ESPFS_FLAG_GZIP) {
        EHTTPD_LOGE(__func__, "template has gzip encoding");
        return EHTTPD_STATUS_NOTFOUND;
    }

    const char *mimetype = ehttpd_get_mimetype(buf);

    espfs_file_t *f = espfs_fopen(conn->inst->espfs, buf);
    if (f == NULL) {
        return EHTTPD_STATUS_NOTFOUND;
    }

    ehttpd_response(conn, 200);
    if (mimetype) {
        ehttpd_send_header(conn, "Content-Type", mimetype);
    }
    ehttpd_send_cache_header(conn, mimetype);

    ehttpd_tpl_cb_t cb = conn->route->argv[1];
    void *user = NULL;
    size_t len;
    int token_pos = -1;
    char token[32];
    do {
        len = espfs_fread(f, buf, FILE_CHUNK_LEN);
        int raw_count = 0;
        uint8_t *p = (uint8_t *) buf;
        if (len > 0) {
            for (size_t i = 0; i < len; i++) {
                if (token_pos < 0) {
                    /* we're on ordinary text */
                    if (buf[i] == '%') {
                        /* send collected raw data */
                        if (raw_count != 0) {
                            TRY(ehttpd_send(conn, p, raw_count));
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
                            TRY(ehttpd_send(conn, "%", 1));
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
            TRY(ehttpd_send(conn, p, raw_count));
        }
    } while (len == FILE_CHUNK_LEN);

cleanup:
    /* we're done */
    cb(conn, NULL, &user);
    espfs_fclose(f);
    return r;
}

ehttpd_status_t ehttpd_route_espfs_index(ehttpd_conn_t *conn)
{
    ehttpd_status_t r = EHTTPD_STATUS_DONE;

    /* Only process GET requests, otherwise fallthrough */
    if (conn->request.method != EHTTPD_METHOD_GET) {
        return EHTTPD_STATUS_NOTFOUND;
    }

    char buf[FILE_CHUNK_LEN];
    espfs_stat_t st;
    ehttpd_status_t status = get_filepath(conn, buf, sizeof(buf), &st, NULL);
    if (status != EHTTPD_STATUS_OK) {
        return status;
    }

    if (st.type != ESPFS_TYPE_DIR) {
        return EHTTPD_STATUS_NOTFOUND;
    }

    size_t len = strlen(conn->request.url);
    if (conn->request.url[len - 1] != '/') {
        len = strlcpy(buf, conn->request.url, sizeof(buf));
        len = strlcpy(buf + len, "/", sizeof(buf) - len);
        ehttpd_redirect(conn, buf);
        return EHTTPD_STATUS_DONE;
    }

    const char *parent = espfs_get_path(conn->inst->espfs, st.index);
    uint16_t start_index = 0;
    uint16_t current_index = start_index = st.index;
    bool files = false;

    ehttpd_response(conn, 200);
    ehttpd_send_header(conn, "Content-Type", "text/html");

    TRY(ehttpd_sendf(conn,
            "<!DOCTYPE html>\n"
            "<html>\n"
            "<head>\n"
            "<meta charset=\"UTF-8\">\n"
            "<title>Index of %H</title>\n"
            "</head>\n"
            "<body>\n"
            "<h1>Index of %H</h1>\n"
            "<pre>\n"
            "[DIR ]          <a href=\"./\">./</a>\n"
            "[DIR ]          <a href=\"../\">../</a>\n",
            conn->request.url, conn->request.url));

    do {
        const char *path = espfs_get_path(conn->inst->espfs, current_index);
        if (path != NULL) {
            espfs_stat(conn->inst->espfs, path, &st);
        }

        if (path == NULL && !files) {
            files = true;
            current_index = start_index;
            path = espfs_get_path(conn->inst->espfs, current_index);
            espfs_stat(conn->inst->espfs, path, &st);
        } else if (path == NULL && files) {
            break;
        }

        if (path == parent) {
            current_index++;
            continue;
        }

        const char *p = parent;
        while (*p && *p++ == *path++);

        if (!files && st.type == ESPFS_TYPE_DIR) {
            if (path[0] != '/') {
                files = true;
                current_index = start_index;
                continue;
            }
            path++;
            if (strchr(path, '/')) {
                current_index++;
                continue;
            }
            TRY(ehttpd_sendf(conn,
                    "[DIR ]          <a href=\"%H/\">%H/</a>\n", path, path));
            current_index++;
        } else if (files && st.type == ESPFS_TYPE_FILE) {
            if (path[0] != '/') {
                break;
            }
            path++;
            if (strchr(path, '/')) {
                current_index++;
                continue;
            }
            TRY(ehttpd_sendf(conn, "[FILE] %-8d <a href=\"%H\">%H</a>\n",
                    st.size, path, path));
            current_index++;
        }
        current_index++;
    } while (true);

    TRY(ehttpd_send(conn, "</pre>\n</body>\n</html>\n", -1));

cleanup:
    return r;
}
