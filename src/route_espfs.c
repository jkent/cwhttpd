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


#define FILE_CHUNK_LEN (1024)

static ehttpd_status_t get_filepath(ehttpd_conn_t *conn, char *path,
        size_t len, espfs_stat_t *s, const char *index)
{
    size_t out_len = 0;
    const char *url = conn->url;
    const char *route = conn->route->path;
    const char *arg = conn->route->arg;

    while (*url && *route == *url) {
        route++;
        url++;
    }

    if (arg == NULL) {
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
        out_len = strlcpy(path, arg, len);
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
        return EHTTPD_STATUS_FOUND;
    }

    if (s->type == ESPFS_TYPE_FILE) {
        return EHTTPD_STATUS_FOUND;
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
    char buf[256];
    espfs_file_t *f = conn->user;

    if (conn->closed) {
        if (f != NULL) {
            espfs_fclose(f);
            return EHTTPD_STATUS_DONE;
        }
    }

    if (f == NULL) {
        if (conn->method != EHTTPD_METHOD_GET) {
            return EHTTPD_STATUS_NOTFOUND;
        }

        espfs_stat_t st;
        ehttpd_status_t status = get_filepath(conn, buf, sizeof(buf), &st,
                "index.html");
        if (status != EHTTPD_STATUS_FOUND) {
            return status;
        }

        f = espfs_fopen(conn->inst->espfs, buf);
        if (f == NULL) {
            return EHTTPD_STATUS_NOTFOUND;
        }

        const char *mimetype = ehttpd_get_mimetype(buf);

        bool gzip_encoding = (st.flags & ESPFS_FLAG_GZIP);
        if (gzip_encoding) {
            /* Check the request Accept-Encoding header for gzip. Return a 500
             * response if not present */
            const char *header = ehttpd_get_header(conn, "Accept-Encoding");
            if (header && strstr(header, "gzip") == NULL) {
                EHTTPD_LOGW(__func__, "client does not accept gzip!");
                espfs_fclose(f);
                ehttpd_start_response(conn, 404);
                ehttpd_header(conn, "Content-Type", "text/plain");
                ehttpd_end_headers(conn);
                ehttpd_enqueue(conn, "only gzip file available", -1);
                return EHTTPD_STATUS_DONE;
            }
        }

        conn->user = f;
        ehttpd_start_response(conn, 200);
        if (gzip_encoding) {
            ehttpd_header(conn, "Content-Encoding", "gzip");
        }
        if (!(conn->priv.flags & HFL_SEND_CHUNKED)) {
            snprintf(buf, sizeof(buf), "%d", st.size);
            ehttpd_header(conn, "Content-Length", buf);
        }
        if (mimetype) {
            ehttpd_header(conn, "Content-Type", mimetype);
        }
        if (st.flags & ESPFS_FLAG_CACHE) {
            ehttpd_add_cache_header(conn, NULL);
        }
        ehttpd_end_headers(conn);
    }

    void *p;
    size_t available = ehttpd_prepare(conn, &p, 0);
    size_t len = espfs_fread(f, p, available);
    conn->priv.sendbuf_len += len;

    if (len == available) {
        return EHTTPD_STATUS_MORE;
    }

    espfs_fclose(f);
    return EHTTPD_STATUS_DONE;
}

typedef struct {
    espfs_file_t *f;
    void *user;
    char token[32];
    int token_pos;
    ehttpd_tpl_cb_t cb;
} template_data_t;

ehttpd_status_t ehttpd_route_espfs_tpl(ehttpd_conn_t *conn)
{
    template_data_t *tpd = conn->user;
    char buf[FILE_CHUNK_LEN];

    if (conn->closed) {
        tpd->cb(conn, NULL, &tpd->user);
        if (tpd->f != NULL) {
            espfs_fclose(tpd->f);
        }
        free(tpd);
        return EHTTPD_STATUS_DONE;
    }

    if (tpd == NULL) {
        /* First call to this route handler */
        /* We can use buf here because its not needed until reading data */
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

        tpd = (template_data_t *) malloc(sizeof(template_data_t));
        if (tpd == NULL) {
            EHTTPD_LOGE(__func__, "malloc fail");
            return EHTTPD_STATUS_NOTFOUND;
        }
        conn->user = tpd;
        tpd->f = f;
        tpd->user = NULL;
        tpd->token_pos = -1;
        tpd->cb = conn->route->arg2;

        ehttpd_start_response(conn, 200);
        if (mimetype) {
            ehttpd_header(conn, "Content-Type", mimetype);
        }
        ehttpd_add_cache_header(conn, mimetype);
        ehttpd_end_headers(conn);
    }

    tpd->cb(conn, NULL, &tpd->user);

    size_t len = espfs_fread(tpd->f, buf, FILE_CHUNK_LEN);
    int raw_count = 0;
    uint8_t *p = (uint8_t *) buf;
    if (len > 0) {
        for (size_t i = 0; i < len; i++) {
            if (tpd->token_pos < 0) {
                /* we're on ordinary text */
                if (buf[i] == '%') {
                    /* send collected raw data */
                    if (raw_count != 0) {
                        ehttpd_enqueue(conn, p, raw_count);
                        raw_count = 0;
                    }
                    /* start collecting token chars */
                    tpd->token_pos = 0;
                } else {
                    raw_count++;
                }
            } else {
                /* we're in token text */
                if (buf[i] == '%') {
                    if (tpd->token_pos == 0) {
                        /* this is an escape sequence */
                        ehttpd_enqueue(conn, "%", 1);
                    } else {
                        /* this is a token */
                        tpd->token[tpd->token_pos] = '\0'; /* zero terminate */
                        tpd->cb(conn, tpd->token, &tpd->user);
                    }

                    /* collect normal characters again */
                    p = (uint8_t *) &buf[i + 1];
                    tpd->token_pos = -1;
                } else {
                    if (tpd->token_pos < (sizeof(tpd->token) - 1)) {
                        tpd->token[tpd->token_pos++] = buf[i];
                    }
                }
            }
        }
    }

    /* send remainder */
    if (raw_count != 0) {
        ehttpd_enqueue(conn, p, raw_count);
    }

    if (len == FILE_CHUNK_LEN) {
        return EHTTPD_STATUS_MORE;
    }

    /* we're done */
    tpd->cb(conn, NULL, &tpd->user);
    espfs_fclose(tpd->f);
    free(tpd);
    return EHTTPD_STATUS_DONE;
}

typedef struct {
    const char *parent;
    uint16_t start_index;
    uint16_t current_index;
    bool files;
} index_data_t;

ehttpd_status_t ehttpd_route_espfs_index(ehttpd_conn_t *conn)
{
    char buf[256];
    espfs_stat_t st;
    index_data_t *data;

    if (conn->closed) {
        if (conn->user) {
            free(conn->user);
        }
    }

    if (conn->user == NULL) {
        ehttpd_status_t status = get_filepath(conn, buf, sizeof(buf), &st,
                NULL);
        if (status != EHTTPD_STATUS_FOUND) {
            return status;
        }

        if (st.type != ESPFS_TYPE_DIR) {
            return EHTTPD_STATUS_NOTFOUND;
        }

        size_t len = strlen(conn->url);
        if (conn->url[len - 1] != '/') {
            len = strlcpy(buf, conn->url, sizeof(buf));
            len = strlcpy(buf + len, "/", sizeof(buf) - len);
            ehttpd_redirect(conn, buf);
            return EHTTPD_STATUS_DONE;
        }

        conn->user = malloc(sizeof(index_data_t));
        if (conn->user == NULL) {
            EHTTPD_LOGE(__func__, "malloc fail");
            return EHTTPD_STATUS_NOTFOUND;
        }
        memset(conn->user, 0, sizeof(index_data_t));
        data = (index_data_t *) conn->user;
        data->parent = espfs_get_path(conn->inst->espfs, st.index);
        data->current_index = data->start_index = st.index;

        ehttpd_start_response(conn, 200);
        ehttpd_header(conn, "Content-Type", "text/html");
        ehttpd_end_headers(conn);

        ehttpd_enqueuef(conn,
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
                conn->url, conn->url);
        return EHTTPD_STATUS_MORE;
    }
    data = (index_data_t *) conn->user;

    do {
        const char *path = espfs_get_path(conn->inst->espfs,
                data->current_index);
        if (path != NULL) {
            espfs_stat(conn->inst->espfs, path, &st);
        }

        if (path == NULL && !data->files) {
            data->files = true;
            data->current_index = data->start_index;
            path = espfs_get_path(conn->inst->espfs, data->current_index);
            espfs_stat(conn->inst->espfs, path, &st);
        } else if (path == NULL && data->files) {
            break;
        }

        if (path == data->parent) {
            data->current_index++;
            continue;
        }

        const char *p = data->parent;
        while (*p && *p++ == *path++);

        if (!data->files && st.type == ESPFS_TYPE_DIR) {
            if (path[0] != '/') {
                data->files = true;
                data->current_index = data->start_index;
                continue;
            }
            path++;
            if (strchr(path, '/')) {
                data->current_index++;
                continue;
            }
            ehttpd_enqueuef(conn, "[DIR ]          <a href=\"%H/\">%H/</a>\n",
                    path, path);
            data->current_index++;
            return EHTTPD_STATUS_MORE;
        } else if (data->files && st.type == ESPFS_TYPE_FILE) {
            if (path[0] != '/') {
                break;
            }
            path++;
            if (strchr(path, '/')) {
                data->current_index++;
                continue;
            }
            ehttpd_enqueuef(conn, "[FILE] %-8d <a href=\"%H\">%H</a>\n",
                    st.size, path, path);
            data->current_index++;
            return EHTTPD_STATUS_MORE;
        }
        data->current_index++;
    } while (true);

    ehttpd_enqueue(conn, "</pre>\n</body>\n</html>\n", -1);
    free(conn->user);
    return EHTTPD_STATUS_DONE;
}
