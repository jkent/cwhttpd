/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* Copyright 2017 Jeroen Domburg <git@j0h.nl> */
/* Copyright 2017 Chris Morgan <chmorgan@gmail.com> */
/* Copyright 2021 Jeff Kent <jeff@jkent.net> */

#include "cb.h"
#include "log.h"
#include "cwhttpd/httpd.h"
#include "cwhttpd/port.h"

#if defined(ESP_PLATFORM)
# include <freertos/FreeRTOS.h>
# include <freertos/task.h>
#endif /* defined(ESP_PLATFORM) */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(ESP_PLATFORM)
# include <lwip/sockets.h>
#endif /* defined(ESP_PLATFORM) */

#if defined(CONFIG_CWHTTPD_MBEDTLS)
# include <mbedtls/platform.h>
# include <mbedtls/entropy.h>
# include <mbedtls/ctr_drbg.h>
# include <mbedtls/certs.h>
# include <mbedtls/x509.h>
# include <mbedtls/ssl.h>
# include <mbedtls/net_sockets.h>
# include <mbedtls/error.h>
#endif

#pragma GCC diagnostic ignored "-Wunused-label"

#ifndef CONFIG_CWHTTPD_LISTENER_STACK_SIZE
# define CONFIG_CWHTTPD_LISTENER_STACK_SIZE 1024
#endif

#ifndef CONFIG_CWHTTPD_LISTENER_PRIORITY
# define CONFIG_CWHTTPD_LISTENER_PRIORITY 1
#endif

#ifndef CONFIG_CWHTTPD_LISTENER_AFFINITY
# define CONFIG_CWHTTPD_LISTENER_AFFINITY 0
#endif

#ifndef CONFIG_CWHTTPD_WORKER_STACK_SIZE
# define CONFIG_CWHTTPD_WORKER_STACK_SIZE 1024
#endif

#ifndef CONFIG_CWHTTPD_WORKER_PRIORITY
# define CONFIG_CWHTTPD_WORKER_PRIORITY 1
#endif

#ifndef CONFIG_CWHTTPD_WORKER_AFFINITY
# define CONFIG_CWHTTPD_WORKER_AFFINITY 0
#endif

#ifndef CONFIG_CWHTTPD_WORKER_COUNT
# define CONFIG_CWHTTPD_WORKER_COUNT 8
#endif

#ifndef CONFIG_CWHTTPD_LISTENER_BACKLOG
# define CONFIG_CWHTTPD_LISTENER_BACKLOG 2
#endif

#define inst_to_pinst(container) container_of(container, posix_inst_t, inst)
#define conn_to_pconn(container) container_of(container, posix_conn_t, conn)

typedef struct posix_conn_t posix_conn_t;
typedef struct posix_inst_t posix_inst_t;
#if defined(CONFIG_CWHTTPD_MBEDTLS)
typedef struct SSL_CTX SSL_CTX;

struct SSL_CTX {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cert;
    mbedtls_pk_context pkey;
};
#endif /* defined(CONFIG_CWHTTPD_MBEDTLS) */

typedef struct conn_data_t {
    int fd;
    struct sockaddr_in addr;
} conn_data_t;

struct posix_conn_t {
    cwhttpd_conn_t conn;
    cwhttpd_thread_t *thread;
    conn_data_t conn_data;
    bool error;
#if defined(CONFIG_CWHTTPD_MBEDTLS)
    mbedtls_ssl_context ssl;
#endif /* defined(CONFIG_CWHTTPD_MBEDTLS) */
};

struct posix_inst_t {
    cwhttpd_inst_t inst;
    cwhttpd_flags_t flags;

    cwhttpd_thread_t *thread;

    struct sockaddr_in listen_addr;
    int listen_fd;

    conn_data_t conn_data;
    int num_connections;
    cwhttpd_semaphore_t *conn_empty;
    cwhttpd_semaphore_t *conn_full;

    cwhttpd_semaphore_t *shutdown;

#if defined(CONFIG_CWHTTPD_MBEDTLS)
    SSL_CTX *ssl;
#endif /* defined(CONFIG_CWHTTPD_MBEDTLS) */
    posix_conn_t pconn[CONFIG_CWHTTPD_WORKER_COUNT];
};

/* Forward declarations */
static void listener_task(void *arg);
static void worker_task(void *arg);


/*******************************
 * \section Instance Functions
 *******************************/

void cwhttpd_destroy(cwhttpd_inst_t *inst)
{
    posix_inst_t *pinst = inst_to_pinst(inst);

    int num_workers = 0;
    for (int i = 0; i < CONFIG_CWHTTPD_WORKER_COUNT; i++) {
        if (pinst->pconn[i].conn.inst != 0) {
            num_workers++;
        }
    }

    pinst->shutdown = cwhttpd_semaphore_create(UINT32_MAX,
            CONFIG_CWHTTPD_WORKER_COUNT - num_workers);
    for (int i = 0; i < CONFIG_CWHTTPD_WORKER_COUNT; i++) {
        cwhttpd_semaphore_take(pinst->shutdown, UINT32_MAX);
    }

#if defined(CONFIG_CWHTTPD_MBEDTLS)
    if (pinst->flags & CWHTTPD_FLAG_TLS) {
        free(pinst->ssl);
    }
#endif /* defined(CONFIG_CWHTTPD_MBEDTLS) */

    while (pinst->inst.route_head) {
        cwhttpd_route_remove(&pinst->inst, 0);
    }

    cwhttpd_semaphore_delete(pinst->conn_empty);
    cwhttpd_semaphore_delete(pinst->conn_full);

    cwhttpd_semaphore_delete(pinst->shutdown);
    cwhttpd_thread_t *thread = pinst->thread;
    free(pinst);
    cwhttpd_thread_delete(thread);
}

cwhttpd_inst_t *cwhttpd_init(const char *addr, cwhttpd_flags_t flags)
{
    posix_inst_t *pinst =
            (posix_inst_t *) calloc(1, sizeof(posix_inst_t));
    if (pinst == NULL) {
        LOGE(__func__, "calloc");
        return NULL;
    }

    pinst->flags = flags;

#if !defined(CONFIG_CWHTTPD_MBEDTLS)
    if (pinst->flags & CWHTTPD_FLAG_TLS) {
        LOGW(__func__, "TLS support not enabled in");
        pinst->flags &= ~CWHTTPD_FLAG_TLS;
    }
#endif /* !defined(CONFIG_CWHTTPD_MBEDTLS) */

    pinst->listen_fd = -1;

    if (addr == NULL) {
        addr = (pinst->flags & CWHTTPD_FLAG_TLS) ? "0.0.0.0:443" :
                "0.0.0.0:80";
    }

    char *s = strdup(addr);
    char *p = strrchr(s, ':');
    if (p) {
        *p = '\0';
        pinst->listen_addr.sin_port = htons(strtol(p + 1, NULL, 10));
    }
    pinst->listen_addr.sin_family = AF_INET;
    inet_pton(AF_INET, s, &pinst->listen_addr.sin_addr);
    free(s);

#if defined(CONFIG_CWHTTPD_MBEDTLS)
    if (pinst->flags & CWHTTPD_FLAG_TLS) {
        int ret;
        pinst->ssl = malloc(sizeof(SSL_CTX));
        if (pinst->ssl == NULL) {
            LOGE(__func__, "malloc");
            goto cleanup;
        }
        mbedtls_ssl_config_init(&pinst->ssl->conf);
        mbedtls_x509_crt_init(&pinst->ssl->cert);
        mbedtls_pk_init(&pinst->ssl->pkey);
        mbedtls_entropy_init(&pinst->ssl->entropy);
        mbedtls_ctr_drbg_init(&pinst->ssl->ctr_drbg);
        ret = mbedtls_ctr_drbg_seed(&pinst->ssl->ctr_drbg,
                mbedtls_entropy_func, &pinst->ssl->entropy, NULL, 0);
        if (ret != 0) {
            LOGE(__func__, "mbedtls_ctr_drbg_seed %d", ret);
            goto cleanup;
        }
        ret = mbedtls_ssl_config_defaults(&pinst->ssl->conf,
                MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                MBEDTLS_SSL_PRESET_DEFAULT);
        if (ret != 0) {
            LOGE(__func__, "mbedtls_ssl_config_defaults %d", ret);
            goto cleanup;
        }
        mbedtls_ssl_conf_rng(&pinst->ssl->conf, mbedtls_ctr_drbg_random,
                &pinst->ssl->ctr_drbg);
    }
#endif /* defined(CONFIG_CWHTTPD_MBEDTLS) */

    pinst->conn_empty = cwhttpd_semaphore_create(1, 1);
    pinst->conn_full = cwhttpd_semaphore_create(1, 0);

    return &pinst->inst;

cleanup:
    cwhttpd_destroy(&pinst->inst);
    return NULL;
}

bool cwhttpd_start(cwhttpd_inst_t *inst)
{
    posix_inst_t *pinst = inst_to_pinst(inst);

    cwhttpd_thread_attr_t thread_attr = {
        .name = 'httpd_listener",
        .stack_size = CONFIG_CWHTTPD_LISTENER_STACK_SIZE,
        .priority = CONFIG_CWHTTPD_LISTENER_PRIORITY,
        .affinity = CONFIG_CWHTTPD_LISTENER_AFFINITY,
    };
    pinst->thread = cwhttpd_thread_create(listener_task, pinst,
            &thread_attr);
    if (pinst->thread == NULL) {
        LOGE(__func__, "listener thread");
        goto err;
    }

    thread_attr.name = "httpd_worker";
    thread_attr.stack_size = CONFIG_CWHTTPD_WORKER_STACK_SIZE;
    thread_attr.priority = CONFIG_CWHTTPD_WORKER_PRIORITY;
    thread_attr.affinity = CONFIG_CWHTTPD_WORKER_AFFINITY;
    for (int i = 0; i < CONFIG_CWHTTPD_WORKER_COUNT; i++) {
        posix_conn_t *pconn = &pinst->pconn[i];
        pconn->conn.inst = &pinst->inst;
        pconn->thread = cwhttpd_thread_create(worker_task, pconn,
                &thread_attr);
        if (pconn->thread == NULL) {
            LOGE(__func__, "worker thread");
            goto err;
        }
    }

    return true;

err:
    cwhttpd_destroy(inst);
    return false;
}

#if defined(CONFIG_CWHTTPD_MBEDTLS)
void cwhttpd_set_cert_and_key(cwhttpd_inst_t *inst, const void *cert,
        size_t cert_len, const void *priv_key,
        size_t priv_key_len)
{
    posix_inst_t *pinst = inst_to_pinst(inst);

    if (!(pinst->flags & CWHTTPD_FLAG_TLS)) {
        LOGW(__func__, "cannot add cert to non-tls instance");
        return;
    }

    int ret;
    ret = mbedtls_x509_crt_parse(&pinst->ssl->cert,
            (const unsigned char *) cert, cert_len);
    if (ret != 0) {
        LOGE(__func__, "cannot add cert");
        return;
    }

#if MBEDTLS_VERSION_MAJOR < 3
    ret = mbedtls_pk_parse_key(&pinst->ssl->pkey,
            (const unsigned char *) priv_key, priv_key_len, NULL, 0);
#else
    ret = mbedtls_pk_parse_key(&pinst->ssl->pkey,
            (const unsigned char *) priv_key, priv_key_len, NULL, 0,
            mbedtls_ctr_drbg_random, NULL);
#endif
    if (ret != 0) {
        LOGE(__func__, "cannot add private key");
        return;
    }

    ret = mbedtls_ssl_conf_own_cert(&pinst->ssl->conf,
            &pinst->ssl->cert, &pinst->ssl->pkey);
    if (ret != 0) {
        LOGE(__func__, "cannot set cert");
    }
}

void cwhttpd_set_client_validation(cwhttpd_inst_t *inst, bool enable)
{
    posix_inst_t *pinst = inst_to_pinst(inst);

    if (!(pinst->flags & CWHTTPD_FLAG_TLS)) {
        LOGW(__func__, "cannot set authmode on non-tls instance");
        return;
    }

    mbedtls_ssl_conf_authmode(&pinst->ssl->conf,
            enable ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_NONE);
}

void cwhttpd_add_client_cert(cwhttpd_inst_t *inst, const void *cert,
        size_t cert_len)
{
    posix_inst_t *pinst = inst_to_pinst(inst);

    if (!(pinst->flags & CWHTTPD_FLAG_TLS)) {
        LOGW(__func__, "cannot add cert to non-tls instance");
        return;
    }

    int ret;
    ret = mbedtls_x509_crt_parse(&pinst->ssl->cert,
            (const unsigned char *) cert, cert_len);
    if (ret != 0) {
        LOGE(__func__, "cannot add cert");
    }
}
#endif /* defined(CONFIG_CWHTTPD_MBEDTLS) */


/*********************************
 * \section Connection Functions
 *********************************/

bool cwhttpd_plat_is_ssl(cwhttpd_conn_t *conn)
{
    posix_inst_t *pinst = inst_to_pinst(conn->inst);

    return pinst->flags & CWHTTPD_FLAG_TLS;
}

ssize_t cwhttpd_plat_send(cwhttpd_conn_t *conn, const void *buf, size_t len)
{
    ssize_t ret = -1;
    posix_conn_t *pconn = conn_to_pconn(conn);
    posix_inst_t *pinst = inst_to_pinst(conn->inst);

    if (len == 0) {
        return 0;
    }

#if defined(CONFIG_CWHTTPD_MBEDTLS)
    if (pinst->flags & CWHTTPD_FLAG_TLS) {
        ret = mbedtls_ssl_write(&pconn->ssl, buf, len);
        if (ret < 0) {
            pconn->error = true;
            if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
                LOGW(__func__, "connection reset by peer %p", pconn);
            } else if (ret < 0) {
                LOGE(__func__, "mbedtls_ssl_write %d", ret);
            }
        }
    } else
#endif /* defined(CONFIG_CWHTTPD_MBEDTLS) */
    {
        ret = write(pconn->conn_data.fd, buf, len);
        if (ret < 0) {
            pconn->error = true;
            if (errno == ECONNRESET) {
                LOGW(__func__, "connection reset by peer %p", pconn);
                return ret;
            } else if (errno == EPIPE) {
                LOGW(__func__, "broken pipe %p", pconn);
                return ret;
            }
            LOGE(__func__, "write %d", errno);
        }
    }

    return ret;
}

ssize_t cwhttpd_plat_recv(cwhttpd_conn_t *conn, void *buf, size_t len)
{
    posix_conn_t *pconn = conn_to_pconn(conn);
    posix_inst_t *pinst = inst_to_pinst(conn->inst);
    ssize_t ret = -1;

#if defined(CONFIG_CWHTTPD_MBEDTLS)
    if (pinst->flags & CWHTTPD_FLAG_TLS) {
        ret = mbedtls_ssl_read(&pconn->ssl, buf, len);
        if (ret < 0) {
            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                /* do nothing */
            } else if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
                pconn->error = true;
                LOGW(__func__, "connection reset by peer %p", pconn);
            } else {
                pconn->error = true;
                LOGE(__func__, "mbedtls error: %d", ret);
            }
        }
    } else
#endif /* defined(CONFIG_CWHTTPD_MBEDTLS) */
    {
        ret = recv(pconn->conn_data.fd, buf, len, 0);
        if (ret < 0) {
            pconn->error = true;
            if (errno == ECONNRESET) {
                LOGW(__func__, "connection reset by peer %p", pconn);
                return ret;
            }
            LOGE(__func__, "recv error %d", errno);
        }
    }
    return ret;
}


/**************************
 * \section Listener Task
 **************************/

static void listener_task(void *arg)
{
    posix_inst_t *pinst = inst_to_pinst(arg);

    pinst->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (pinst->listen_fd < 0) {
        LOGE(__func__, "failed to create socket");
        goto cleanup;
    }

    int flags = fcntl(pinst->listen_fd, F_GETFL);
    fcntl(pinst->listen_fd, F_SETFL, flags | O_NONBLOCK);

    int enable = 1;
    setsockopt(pinst->listen_fd, SOL_SOCKET, SO_REUSEADDR, &enable,
            sizeof(int));

    char buf[16];
    inet_ntop(AF_INET, &pinst->listen_addr.sin_addr, buf, sizeof(buf));

    if (bind(pinst->listen_fd,
            (struct sockaddr *) &pinst->listen_addr,
            sizeof(pinst->listen_addr)) < 0) {
        LOGE(__func__, "unable to bind to TCP %s:%d", buf,
                ntohs(pinst->listen_addr.sin_port));
        goto cleanup;
    }

    if (listen(pinst->listen_fd, CONFIG_CWHTTPD_LISTENER_BACKLOG) < 0) {
        LOGE(__func__, "unable to listen on TCP %s:%d", buf,
                ntohs(pinst->listen_addr.sin_port));
        goto cleanup;
    }

    LOGI(__func__, "esphttpd listening on TCP %s:%d%s", buf,
            ntohs(pinst->listen_addr.sin_port),
            (pinst->flags & CWHTTPD_FLAG_TLS) ? " TLS" : "");

    while (!pinst->shutdown) {
        fd_set read_set;
        struct timeval timeout = {
            .tv_usec = 250000,
        };

        FD_ZERO(&read_set);
        FD_SET(pinst->listen_fd, &read_set);
        if (select(pinst->listen_fd + 1, &read_set, NULL, NULL,
                &timeout) <= 0) {
            continue;
        }

        while (!pinst->shutdown) {
            if (cwhttpd_semaphore_take(pinst->conn_empty, 250)) {
                break;
            }
        }
        if (pinst->shutdown) {
            cwhttpd_semaphore_give(pinst->conn_empty);
            break;
        }
        socklen_t len = sizeof(pinst->conn_data.addr);
        pinst->conn_data.fd = accept(pinst->listen_fd,
                (struct sockaddr *) &pinst->conn_data.addr, &len);
        if (pinst->conn_data.fd < 0) {
            cwhttpd_semaphore_give(pinst->conn_empty);
            LOGE(__func__, "accept failed");
            continue;
        }
        cwhttpd_semaphore_give(pinst->conn_full);
    }

cleanup:
    close(pinst->listen_fd);

#if defined(CONFIG_CWHTTPD_MBEDTLS)
    if (pinst->flags & CWHTTPD_FLAG_TLS && pinst->ssl) {
        mbedtls_x509_crt_free(&pinst->ssl->cert);
        mbedtls_pk_free(&pinst->ssl->pkey);
        mbedtls_ssl_config_free(&pinst->ssl->conf);
        mbedtls_ctr_drbg_free(&pinst->ssl->ctr_drbg);
        mbedtls_entropy_free(&pinst->ssl->entropy);
        free(pinst->ssl);
    }
#endif /* defined(CONFIG_CWHTTPD_MBEDTLS) */

    cwhttpd_thread_t *thread = pinst->thread;
    cwhttpd_destroy(&pinst->inst);
    cwhttpd_thread_delete(thread);
}


/************************
 * \section Worker Task
 ************************/

static void worker_task(void *arg)
{
    posix_conn_t *pconn = conn_to_pconn(arg);
    posix_inst_t *pinst = inst_to_pinst(pconn->conn.inst);

    while (true) {
        while (!pinst->shutdown) {
            if (cwhttpd_semaphore_take(pinst->conn_full, 250)) {
                break;
            }

        }
        if (pinst->shutdown) {
            cwhttpd_semaphore_give(pinst->conn_full);
            break;
        }
        pinst->num_connections++;
        if (pinst->num_connections == CONFIG_CWHTTPD_WORKER_COUNT) {
            pconn->conn.priv.flags |= HFL_REQUEST_CLOSE;
        }
        memcpy(&pconn->conn_data, &pinst->conn_data, sizeof(pconn->conn_data));
        cwhttpd_semaphore_give(pinst->conn_empty);

        char ipstr[16];
        inet_ntop(AF_INET, &pconn->conn_data.addr.sin_addr, ipstr,
                sizeof(ipstr));
        LOGD(__func__, "new connection from %s:%d%s %p", ipstr,
                ntohs(pconn->conn_data.addr.sin_port),
                pinst->flags & CWHTTPD_FLAG_TLS ? " TLS" : "", pconn);

        int keepAlive = 1;
        int keepIdle = 60;
        int keepInterval = 5;
        int keepCount = 3;
        int nodelay = 0;
#if defined(CONFIG_CWHTTPD_TCP_NODELAY)
        nodelay = 1; // enable TCP_NODELAY to speed-up transfers of small
                     // files. See Nagle's Algorithm.
#endif /* defined(CONFIG_CWHTTPD_TCP_NODELAY) */

        setsockopt(pconn->conn_data.fd, SOL_SOCKET, SO_KEEPALIVE,
                (void *) &keepAlive, sizeof(keepAlive));
        setsockopt(pconn->conn_data.fd, IPPROTO_TCP, TCP_KEEPIDLE,
                (void *) &keepIdle, sizeof(keepIdle));
        setsockopt(pconn->conn_data.fd, IPPROTO_TCP, TCP_KEEPINTVL,
                (void *) &keepInterval, sizeof(keepInterval));
        setsockopt(pconn->conn_data.fd, IPPROTO_TCP, TCP_KEEPCNT,
                (void *) &keepCount, sizeof(keepCount));
        setsockopt(pconn->conn_data.fd, IPPROTO_TCP, TCP_NODELAY,
                (void *) &nodelay, sizeof(nodelay));

#if defined(CONFIG_CWHTTPD_MBEDTLS)
        if (pinst->flags & CWHTTPD_FLAG_TLS) {
            mbedtls_ssl_init(&pconn->ssl);

            int ret = mbedtls_ssl_setup(&pconn->ssl,
                    &pinst->ssl->conf);
            if (ret != 0) {
                LOGE(__func__, "mbedtls_ssl_setup %d", ret);
                close(pconn->conn_data.fd);
                continue;
            }

            mbedtls_ssl_set_bio(&pconn->ssl, &pconn->conn_data.fd,
                    mbedtls_net_send, mbedtls_net_recv, NULL);

            while ((ret = mbedtls_ssl_handshake(&pconn->ssl)) != 0) {
                if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
                    LOGD(__func__, "MBEDTLS_ERR_SSL_WANT_READ %p",
                            pconn);
                    continue;
                }
                if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                    LOGD(__func__, "MBEDTLS_ERR_SSL_WANT_WRITE %p",
                            pconn);
                    continue;
                }
                LOGE(__func__, "mbedtls_ssl_handshake %d", ret);
                break;
            }
            if (ret != 0) {
                mbedtls_ssl_free(&pconn->ssl);
                close(pconn->conn_data.fd);
                continue;
            }
        }
#endif /* defined(CONFIG_CWHTTPD_MBEDTLS) */

        cwhttpd_new_conn_cb(&pconn->conn);

        if (!pconn->error) {
#if defined(CONFIG_CWHTTPD_MBEDTLS)
            if (pinst->flags & CWHTTPD_FLAG_TLS) {
                int ret;
                while ((ret = mbedtls_ssl_close_notify(&pconn->ssl)) < 0) {
                    LOGE(__func__, "mbedtls_ssl_close_notify %d", ret);
                    break;
                }
            }
#endif /* defined(CONFIG_CWHTTPD_MBEDTLS) */

            shutdown(pconn->conn_data.fd, SHUT_RDWR);
        }

        close(pconn->conn_data.fd);
#if defined(CONFIG_CWHTTPD_MBEDTLS)
        mbedtls_ssl_free(&pconn->ssl);
#endif /* defined(CONFIG_CWHTTPD_MBEDTLS) */

        LOGD(__func__, "disconnected %p", pconn);

        pinst->num_connections--;

        /* Recycle the conn */
        cwhttpd_thread_t *thread = pconn->thread;
        memset(pconn, 0, sizeof(*pconn));
        pconn->conn.inst = &pinst->inst;
        pconn->thread = thread;
    }

    cwhttpd_semaphore_give(pinst->shutdown);
    cwhttpd_thread_delete(pconn->thread);
}
