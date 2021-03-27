/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
Route handlers to let httpd use the filesystem to serve the files in it.
*/

#include "log.h"
#include "libesphttpd/route.h"
#include "libesphttpd/httpd.h"

#include <assert.h>
#include <frozen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/unistd.h>
#include <sys/stat.h>
#include <sys/errno.h>
#if defined(UNIX)
# include <bsd/string.h>
#endif


#define FILE_CHUNK_LEN    (1024)
#define MAX_FILENAME_LENGTH (256)

#define ESPFS_FLAG_GZIP (1 << 1)


static bool get_filepath(ehttpd_conn_t *conn, char *path, size_t len,
        struct stat *st, const char *index)
{
    size_t out_len = 0;
    const char *url = conn->url;
    const ehttpd_route_t *route = conn->route;
    const char *rpath = route->path;

    while (*rpath == *url) {
        rpath++;
        url++;
    }

    if (route->argc < 1) {
        out_len = strlcpy(path, url, len);
        if (path[out_len - 1] == '/') {
            out_len += strlcpy(path + out_len, index, len - out_len);
        }
    } else {
        out_len = strlcpy(path, route->argv[0], len);
        if (path[out_len - 1] == '/') {
            out_len += strlcpy(path + out_len, url, len - out_len);
            if (path[out_len - 1] == '/') {
                out_len += strlcpy(path + out_len, index, len - out_len);
            }
        }
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

ehttpd_status_t ehttpd_route_fs_get(ehttpd_conn_t *conn)
{
    FILE *f = conn->user;
    char buf[FILE_CHUNK_LEN];

    if (conn->closed) {
        if (f != NULL){
            fclose(f);
        }
        EHTTPD_LOGE(__func__, "Connection aborted!");
        return EHTTPD_STATUS_DONE;
    }

    if (f == NULL) {
        /* First call to this route handler */

        /* Only process GET requests, otherwise fallthrough */
        if (conn->method != EHTTPD_METHOD_GET) {
            return EHTTPD_STATUS_NOTFOUND;
        }

        /* We can use buf here because its not needed until reading data */
        struct stat st;
        if (!get_filepath(conn, buf, sizeof(buf), &st, "index.html")) {
            return EHTTPD_STATUS_NOTFOUND;
        }

        bool gzip_encoding = false;
#if defined(CONFIG_IDF_TARGET_ESP8266) || defined(ESP_PLATFORM)
        if (st.st_spare4[0] == 0x73665345) {
            if (st.st_spare4[0] & 2) {
                gzip_encoding = true;
            }
        }

        if (st.st_spare4[0] == 0x2B534645) {
            if (st.st_spare4[0] & 1) {
                gzip_encoding = true;
            }
        }
#endif

        const char *mimetype = ehttpd_get_mimetype(buf);

        f = fopen(buf, "r");
        if (f == NULL) {
            /* file not found, look for filename.gz */
            strlcat(buf, ".gz", sizeof(buf));
            f = fopen(buf, "r");
            gzip_encoding = true;
        }

        if (f == NULL) {
            return EHTTPD_STATUS_NOTFOUND;
        }

        if (gzip_encoding) {
            /* Check the request Accept-Encoding header for gzip. Return a 500
             * response if not present. */
            const char *header = ehttpd_get_header(conn, "Accept-Encoding");
            if (header && strstr(header, "gzip") == NULL) {
                EHTTPD_LOGE(__func__, "client does not accept gzip!");
                fclose(f);
                ehttpd_start_response(conn, 500);
                ehttpd_end_headers(conn);
                return EHTTPD_STATUS_DONE;
            }
        }

        conn->user = f;
        ehttpd_start_response(conn, 200);
        if (gzip_encoding) {
            ehttpd_header(conn, "Content-Encoding", "gzip");
        }
        if (mimetype) {
            ehttpd_header(conn, "Content-Type", mimetype);
        }
        ehttpd_add_cache_header(conn, mimetype);
        ehttpd_end_headers(conn);
    }

    size_t len = fread(buf, 1, FILE_CHUNK_LEN, f);
    if (len > 0) {
        ehttpd_enqueue(conn, buf, len);
    }

    if (len == FILE_CHUNK_LEN) {
        return EHTTPD_STATUS_MORE;
    }

    fclose(f);
    return EHTTPD_STATUS_DONE;
}

typedef struct {
    FILE *f;
    void *user;
    char token[32];
    int token_pos;
    ehttpd_tpl_cb_t cb;
} template_data_t;

ehttpd_status_t ehttpd_route_fs_tpl(ehttpd_conn_t *conn)
{
    template_data_t *tpd = conn->user;
    FILE *f;
    char buf[FILE_CHUNK_LEN];

    if (conn->closed) {
        tpd->cb(conn, NULL, &tpd->user);
        if(tpd->f != NULL){
            fclose(tpd->f);
        }
        free(tpd);
        return EHTTPD_STATUS_DONE;
    }

    if (tpd == NULL) {
        /* First call to this route handler */
        /* We can use buf here because its not needed until reading data */
        struct stat st;
        if (!get_filepath(conn, buf, sizeof(buf), &st, "index.tpl")) {
            return EHTTPD_STATUS_NOTFOUND;
        }

        bool gzip_encoding = false;

#if defined(CONFIG_IDF_TARGET_ESP8266) || defined(ESP_PLATFORM)
        if (st.st_spare4[0] == 0x73665345) {
            if (st.st_spare4[0] & 2) {
                gzip_encoding = true;
            }
        }

        if (st.st_spare4[0] == 0x2B534645) {
            if (st.st_spare4[0] & 1) {
                gzip_encoding = true;
            }
        }
#endif

        if (gzip_encoding) {
            EHTTPD_LOGE(__func__, "template has gzip encoding");
            return EHTTPD_STATUS_NOTFOUND;
        }

        const char *mimetype = ehttpd_get_mimetype(buf);

        f = fopen(buf, "r");
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
        tpd->cb = conn->route->argv[1];

        ehttpd_start_response(conn, 200);
        if (mimetype) {
            ehttpd_header(conn, "Content-Type", mimetype);
        }
        ehttpd_add_cache_header(conn, mimetype);
        ehttpd_end_headers(conn);
    }

    tpd->cb(conn, NULL, &tpd->user);

    size_t len = fread(buf, 1, FILE_CHUNK_LEN, tpd->f);
    int raw_count = 0;
    uint8_t *p = (uint8_t *) buf;
    if (len > 0) {
        for (size_t i = 0; i < len; i++) {
            if (tpd->token_pos < 0) {
                /* we're in ordinary text */
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
    fclose(tpd->f);
    free(tpd);
    return EHTTPD_STATUS_DONE;
}

static int create_missing_directories(const char *fullpath)
{
    /* make a copy for modifications */
    char *path = strndup(fullpath, MAX_FILENAME_LENGTH);
    assert(path != NULL);

    for (int i = 0; path[i] != '\0'; i++) {
        if (i > 0 && path[i] == '/') {
            struct stat filestat;
            path[i] = '\0';  /* truncate path */
            int result = stat(path, &filestat);
            if (result == 0 && S_ISDIR(filestat.st_mode)) {
                path[i] = '/';
                continue;
            } else if (result != 0 && errno == ENOENT) {
                if (mkdir(path, S_IRWXU) != 0) {
                    EHTTPD_LOGE(__func__, "mkdir failed");
                    path[i] = '/';
                    return 1;
                }
           }
           path[i] = '/'; /* restore path */
       }
    }
    free(path);
    return 0;
}

typedef struct {
    enum {UPSTATE_START, UPSTATE_WRITE, UPSTATE_DONE} state;
    FILE *file;
    char filepath[MAX_FILENAME_LENGTH];
    char *filename;
    size_t filepath_len;
    int b_written;
    const char *errtxt;
} upload_data_t;

ehttpd_status_t ehttpd_route_fs_put(ehttpd_conn_t *conn)
{
    upload_data_t *data = (upload_data_t *) conn->user;

    if (conn->closed) {
        if (data != NULL) {
            if(data->file != NULL) {
                fclose(data->file);
                EHTTPD_LOGD(__func__, "fclose: %s, r", data->filename);
            }
            free(data);
        }
        EHTTPD_LOGE(__func__, "Connection aborted!");
        return EHTTPD_STATUS_DONE;
    }

    if (data == NULL) {
        /* First call to this route handler */
        if (conn->post == NULL || (conn->method != EHTTPD_METHOD_PUT &&
                conn->method != EHTTPD_METHOD_POST)) {
            return EHTTPD_STATUS_NOTFOUND; /* fallthrough */
        }
        data = (upload_data_t *) malloc(sizeof(upload_data_t));
        if (data == NULL) {
            EHTTPD_LOGE(__func__, "malloc fail");
            goto err;
        }
        conn->user = data;
        memset(data, 0, sizeof(upload_data_t));

        if (conn->post->boundary != NULL) {
            /* TODO: handle multipart/form-data POST */
            /* upload using xhr.send(file), not xhr.send(form) */
            EHTTPD_LOGE(__func__, "multipart/form-data is not supported");
            goto err;
        }

        const char *basepath = conn->route->argv[0];
        if (basepath == NULL || *basepath == 0) {
            goto err;
        }

        strlcpy(data->filepath, basepath, sizeof(data->filepath));
        data->filepath_len = strlen(data->filepath);
        if (data->filepath[data->filepath_len - 1] == '/') {
            data->filename = data->filepath + data->filepath_len;
        } else {
            data->filename = data->filepath;
        }

        if (*data->filename == '\0' && conn->post != NULL) {
            size_t len = sizeof(data->filepath) - data->filepath_len;
            ehttpd_find_param("filename", conn->post->buf, data->filename,
                    &len);
        }

        if (*data->filename == '\0') {
            size_t len = sizeof(data->filepath) - data->filepath_len;
            ehttpd_find_param("filename", conn->args, data->filename,
                    &len);
        }

        if (*data->filename == '\0') {
            const char *url = conn->url;
            const char *route_url = conn->route->path;

            while (*url && *route_url++ == *url++);
            strlcpy(data->filename, url,
                    sizeof(data->filepath) - data->filepath_len);
        }

        EHTTPD_LOGI(__func__, "Uploading: %s", data->filepath);

        if (create_missing_directories(data->filepath) != 0) {
            data->errtxt = "Error creating directories!";
            goto err;
        }

        /* Open file */
        data->file = fopen(data->filepath, "w");
        if (data->file == NULL) {
            data->errtxt = "Can't open file for writing!";
            EHTTPD_LOGE(__func__, "%s", data->errtxt);
            goto err;
        }

        data->state = UPSTATE_WRITE;
    }

    EHTTPD_LOGD(__func__, "Chunk: %d bytes, ", conn->post->buf_len);

    if (data->state == UPSTATE_WRITE) {
        if (data->file != NULL){
            int count = fwrite(conn->post->buf, 1, conn->post->buf_len,
                    data->file);
            data->b_written += count;
            if (count != conn->post->buf_len) {
                EHTTPD_LOGE(__func__, "write error");
            }
            if (data->b_written >= conn->post->len) {
                data->state = UPSTATE_DONE;
            }
        }
        /* eat any extra bytes */
    } else if (data->state == UPSTATE_DONE) {
        EHTTPD_LOGE(__func__, "extra data received");
        /* ignore those bytes. */
    }

err:
    if (conn->post->received != conn->post->len) {
        return EHTTPD_STATUS_MORE;
    }

    /* we're done */
    if(data->file != NULL){
        fclose(data->file);
    }
    EHTTPD_LOGI(__func__, "Total: %d bytes written.", data->b_written);

    char *json = json_asprintf("{filename:%Q,received:%d,written:%d,"
            "success:%B}", data->filename, conn->post->received,
            data->b_written, data->state == UPSTATE_DONE);
    free(data);

    ehttpd_start_response(conn, 200);
    ehttpd_header(conn, "Cache-Control",
            "no-store, must-revalidate, no-cache, max-age=0");
    ehttpd_header(conn, "Content-Type", "application/json; charset=utf-8");
    ehttpd_end_headers(conn);
    ehttpd_enqueue(conn, json, -1);
    free(json);

    return EHTTPD_STATUS_DONE;
}
