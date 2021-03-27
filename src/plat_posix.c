/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* Copyright 2017 Jeroen Domburg <git@j0h.nl> */
/* Copyright 2017 Chris Morgan <chmorgan@gmail.com> */
/* Copyright 2021 Jeff Kent <jeff@jkent.net> */

#include "cb.h"
#include "log.h"
#include "libesphttpd/captdns.h"
#include "libesphttpd/httpd.h"
#include "libesphttpd/port.h"

#if defined(FREERTOS) || defined(CONFIG_IDF_TARGET_ESP8266) || \
    defined(ESP_PLATFORM)
# include <freertos/FreeRTOS.h>
# include <freertos/task.h>
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(CONFIG_IDF_TARGET_ESP8266) || defined(ESP_PLATFORM)
# include <lwip/sockets.h>
#endif

#if defined(CONFIG_EHTTPD_TLS_MBEDTLS)
# include <mbedtls/platform.h>
# include <mbedtls/entropy.h>
# include <mbedtls/ctr_drbg.h>
# include <mbedtls/certs.h>
# include <mbedtls/x509.h>
# include <mbedtls/ssl.h>
# include <mbedtls/net_sockets.h>
# include <mbedtls/error.h>
#elif defined(CONFIG_EHTTPD_TLS_OPENSSL)
# include <openssl/ssl.h>
# if !defined(CONFIG_IDF_TARGET_ESP8266) && !defined(ESP_PLATFORM)
#  include <openssl/err.h>
# endif
#endif

#pragma GCC diagnostic ignored "-Wunused-label"

#ifndef CONFIG_EHTTPD_RECVBUF_SIZE
# define CONFIG_EHTTPD_RECVBUF_SIZE 2048
#endif

#ifndef CONFIG_EHTTPD_LISTEN_BACKLOG
# define CONFIG_EHTTPD_LISTEN_BACKLOG 2
#endif

#define inst_to_posix(container) container_of(container, posix_inst_t, inst)
#define conn_to_posix(container) container_of(container, posix_conn_t, conn)

#if defined(FREERTOS) && defined(UNIX)
# define enter_critical() taskENTER_CRITICAL()
# define exit_critical() taskEXIT_CRITICAL()
#else
# define enter_critical()
# define exit_critical()
#endif

typedef struct ehttpd_captdns_t ehttpd_captdns_t;
typedef struct posix_conn_t posix_conn_t;
typedef struct posix_inst_t posix_inst_t;
#if defined(CONFIG_EHTTPD_TLS_MBEDTLS)
typedef struct SSL_CTX SSL_CTX;

struct SSL_CTX {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cert;
    mbedtls_pk_context pkey;
};
#endif

struct posix_inst_t {
    ehttpd_inst_t inst;

    uint8_t buf[CONFIG_EHTTPD_RECVBUF_SIZE];

    ehttpd_mutex_t *mutex;
    ehttpd_thread_t *thread;

#if defined(CONFIG_EHTTPD_TLS_MBEDTLS) || defined(CONFIG_EHTTPD_TLS_OPENSSL)
    SSL_CTX *ssl;
#endif

    int listen_fd;
    struct sockaddr_in listen_addr;

    int captdns_fd;
    ehttpd_captdns_t *captdns;

#if defined(CONFIG_EHTTPD_USE_SHUTDOWN)
    int shutdown_fd;
    uint16_t shutdown_port;
#endif
    bool shutdown;

    ehttpd_flags_t flags;
    posix_conn_t *conn_buf;
    size_t conn_max;
};

struct posix_conn_t {
    ehttpd_conn_t conn;

    int fd;
    bool need_write;
    bool need_close;
    int port;
    struct sockaddr_in addr;
#if defined(CONFIG_EHTTPD_TLS_MBEDTLS)
    mbedtls_ssl_context ssl;
#elif defined(CONFIG_EHTTPD_TLS_OPENSSL)
    SSL *ssl;
#endif
};

/* Forward declarations */
static void close_connection(ehttpd_conn_t *conn, bool do_shutdown);
static void server_task(void *arg);

void ehttpd_end_request(ehttpd_conn_t *conn);
void ehttpd_captdns_recv(ehttpd_captdns_t *captdns);


/*******************************
 * \section Instance Functions
 *******************************/

static void ehttpd_free(ehttpd_inst_t *inst)
{
    posix_inst_t *posix_inst = inst_to_posix(inst);

    ehttpd_mutex_delete(posix_inst->mutex);

    if (posix_inst->flags & EHTTPD_FLAG_TLS) {
#if defined(CONFIG_EHTTPD_TLS_MBEDTLS)
        free(posix_inst->ssl);
#elif defined(CONFIG_EHTTPD_TLS_OPENSSL)
        SSL_CTX_free(posix_inst->ssl);
#endif
    }

    if (posix_inst->flags & EHTTPD_FLAG_MANAGED_CONN_BUF) {
        free(posix_inst->conn_buf);
    }
    while (posix_inst->inst.route_head) {
        ehttpd_route_remove(&posix_inst->inst, 0);
    }
    free(posix_inst);
}

ehttpd_inst_t *ehttpd_init(const char *addr, void *conn_buf, size_t conn_max,
        ehttpd_flags_t flags)
{
    if (conn_buf == NULL) {
        conn_buf = calloc(1, ehttpd_get_conn_buf_size(conn_max));
        if (conn_buf == NULL) {
            return NULL;
        }
        flags |= EHTTPD_FLAG_MANAGED_CONN_BUF;
    }

    posix_inst_t *posix_inst =
            (posix_inst_t *) calloc(1, sizeof(posix_inst_t));
    if (posix_inst == NULL) {
        EHTTPD_LOGE(__func__, "calloc");
        goto err;
    }

    posix_inst->listen_fd = -1;
    posix_inst->captdns_fd = -1;
#if defined(CONFIG_EHTTPD_USE_SHUTDOWN)
    posix_inst->shutdown_fd = -1;
#endif

    posix_inst->flags = flags;
    posix_inst->conn_buf = conn_buf;
    posix_inst->conn_max = conn_max;

    posix_inst->mutex = ehttpd_mutex_create(true);
    if (posix_inst->mutex == NULL) {
        EHTTPD_LOGE(__func__, "create mutex");
        goto err;
    }

    if (flags & EHTTPD_FLAG_TLS) {
#if defined(CONFIG_EHTTPD_TLS_MBEDTLS)
        int ret;
        posix_inst->ssl = malloc(sizeof(SSL_CTX));
        if (posix_inst->ssl == NULL) {
            EHTTPD_LOGE(__func__, "create ssl context");
            goto err;
        }
        mbedtls_ssl_config_init(&posix_inst->ssl->conf);
        mbedtls_x509_crt_init(&posix_inst->ssl->cert);
        mbedtls_pk_init(&posix_inst->ssl->pkey);
        mbedtls_entropy_init(&posix_inst->ssl->entropy);
        mbedtls_ctr_drbg_init(&posix_inst->ssl->ctr_drbg);
        ret = mbedtls_ctr_drbg_seed(&posix_inst->ssl->ctr_drbg,
                mbedtls_entropy_func, &posix_inst->ssl->entropy, NULL, 0);
        if (ret != 0) {
            EHTTPD_LOGE(__func__, "mbedtls_ctr_drbg_seed %d", ret);
            goto err;
        }
        ret = mbedtls_ssl_config_defaults(&posix_inst->ssl->conf,
                MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                MBEDTLS_SSL_PRESET_DEFAULT);
        if (ret != 0) {
            EHTTPD_LOGE(__func__, "mbedtls_ssl_config_defaults %d", ret);
            goto err;
        }
        mbedtls_ssl_conf_rng(&posix_inst->ssl->conf, mbedtls_ctr_drbg_random,
                &posix_inst->ssl->ctr_drbg);
#elif defined(CONFIG_EHTTPD_TLS_OPENSSL)
        posix_inst->ssl = SSL_CTX_new(TLS_server_method());
        if (posix_inst->ssl == NULL) {
            EHTTPD_LOGE(__func__, "create ssl context");
            goto err;
        }
#endif
    }

    if (addr == NULL) {
        addr = (flags & EHTTPD_FLAG_TLS) ? "0.0.0.0:443" : "0.0.0.0:80";
    }

    char *s = strdup(addr);
    char *p = strrchr(s, ':');
    if (p) {
        *p = '\0';
        posix_inst->listen_addr.sin_port = htons(strtol(p + 1, NULL, 10));
    }
    inet_pton(AF_INET, s, &posix_inst->listen_addr.sin_addr);
    free(s);

    return &posix_inst->inst;

err:
    ehttpd_free(&posix_inst->inst);
    return NULL;
}

size_t ehttpd_get_conn_buf_size(size_t conn_max)
{
    return sizeof(posix_conn_t) * conn_max;
}

bool ehttpd_start(ehttpd_inst_t *inst)
{
    posix_inst_t *posix_inst = inst_to_posix(inst);

    posix_inst->thread = ehttpd_thread_create(server_task, posix_inst, NULL);
    if (posix_inst->thread == NULL) {
        EHTTPD_LOGE(__func__, "thread create");
        ehttpd_free(&posix_inst->inst);
        return false;
    }

    return true;
}

void ehttpd_lock(ehttpd_inst_t *inst)
{
    posix_inst_t *posix_inst = inst_to_posix(inst);

    ehttpd_mutex_lock(posix_inst->mutex);
}

void ehttpd_unlock(ehttpd_inst_t *inst)
{
    posix_inst_t *posix_inst = inst_to_posix(inst);

    ehttpd_mutex_unlock(posix_inst->mutex);
}

#if defined(CONFIG_EHTTPD_USE_SHUTDOWN)
void ehttpd_shutdown(ehttpd_inst_t *inst)
{
    posix_inst_t *posix_inst = inst_to_posix(inst);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd <= 0) {
        EHTTPD_LOGE(__func__, "socket err %d", fd);
        return;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(posix_inst->shutdown_port);

    EHTTPD_LOGI(__func__, "sending shutdown");

    sendto(fd, "shutdown", 8, 0, (struct sockaddr *) &addr, sizeof(addr));
    close(fd);
}
#endif

void ehttpd_captdns_hook(ehttpd_inst_t *inst, ehttpd_captdns_t *captdns,
        int fd)
{
    posix_inst_t *posix_inst = inst_to_posix(inst);

    ehttpd_lock(inst);

    posix_inst->captdns = captdns;
    posix_inst->captdns_fd = fd;

    ehttpd_unlock(inst);
}

#if defined(CONFIG_EHTTPD_TLS_MBEDTLS)
void ehttpd_set_cert_and_key(ehttpd_inst_t *inst, const void *cert,
        size_t cert_len, const void *priv_key,
        size_t priv_key_len)
{
    posix_inst_t *posix_inst = inst_to_posix(inst);

    int ret;
    ret = mbedtls_x509_crt_parse(&posix_inst->ssl->cert,
            (const unsigned char *) cert, cert_len);
    if (ret != 0) {
        EHTTPD_LOGE(__func__, "error adding cert");
        return;
    }

    ret = mbedtls_pk_parse_key(&posix_inst->ssl->pkey,
            (const unsigned char *) priv_key, priv_key_len, NULL, 0);
    if (ret != 0) {
        EHTTPD_LOGE(__func__, "error adding private key");
        return;
    }

    ret = mbedtls_ssl_conf_own_cert(&posix_inst->ssl->conf,
            &posix_inst->ssl->cert, &posix_inst->ssl->pkey);
    if (ret != 0) {
        EHTTPD_LOGE(__func__, "error setting cert");
    }
}

void ehttpd_set_client_validation(ehttpd_inst_t *inst, bool enable)
{
    posix_inst_t *posix_inst = inst_to_posix(inst);

    mbedtls_ssl_conf_authmode(&posix_inst->ssl->conf,
            enable ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_NONE);
}

void ehttpd_add_client_cert(ehttpd_inst_t *inst, const void *cert,
        size_t cert_len)
{
    posix_inst_t *posix_inst = inst_to_posix(inst);

    int ret;
    ret = mbedtls_x509_crt_parse(&posix_inst->ssl->cert,
            (const unsigned char *) cert, cert_len);
    if (ret != 0) {
        EHTTPD_LOGE(__func__, "error adding cert");
    }
}
#elif defined(CONFIG_EHTTPD_TLS_OPENSSL)
static bool set_der_cert_and_key(ehttpd_inst_t *inst,
        const void *cert, size_t cert_len,
        const void *priv_key, size_t priv_key_len)
{
    posix_inst_t *posix_inst = inst_to_posix(inst);
    bool status = true;

    if (!(posix_inst->flags & EHTTPD_FLAG_TLS)) {
        EHTTPD_LOGE(__func__, "not an ssl instance");
        return false;
    }

    int ret = SSL_CTX_use_certificate_ASN1(posix_inst->ssl, cert_len, cert);
    if (ret == 0) {
        EHTTPD_LOGE(__func__, "SSL_CTX_use_certificate_ASN1 failed: %d", ret);
        status = false;
    }

    ret = SSL_CTX_use_RSAPrivateKey_ASN1(posix_inst->ssl, priv_key,
            priv_key_len);
    if (ret == 0) {
        EHTTPD_LOGE(__func__, "SSL_CTX_use_RSAPrivateKey_ASN1 failed: %d",
                ret);
        status = false;
    }

#if !defined(CONFIG_IDF_TARGET_ESP8266) && !defined(ESP_PLATFORM)
    if (status == false) {
        ERR_print_errors_fp(stderr);
    }
#endif

    return status;
}

void ehttpd_set_cert_and_key(ehttpd_inst_t *inst, const void *cert,
        size_t cert_len, const void *priv_key,
        size_t priv_key_len)
{
    posix_inst_t *posix_inst = inst_to_posix(inst);

    if (!(posix_inst->flags & EHTTPD_FLAG_TLS)) {
        EHTTPD_LOGE(__func__, "not an ssl instance");
        return;
    }

    if (!set_der_cert_and_key(inst, cert, cert_len,
            priv_key, priv_key_len)) {
        EHTTPD_LOGE(__func__, "failed");
    }
}

void ehttpd_set_client_validation(ehttpd_inst_t *inst, bool enable)
{
    posix_inst_t *posix_inst = inst_to_posix(inst);
    int flags;

    if (!(posix_inst->flags & EHTTPD_FLAG_TLS)) {
        EHTTPD_LOGE(__func__, "not an ssl instance");
        return;
    }

    if (enable) {
        flags = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    } else {
        flags = SSL_VERIFY_NONE;
    }
    SSL_CTX_set_verify(posix_inst->ssl, flags, NULL);
}

void ehttpd_add_client_cert(ehttpd_inst_t *inst, const void *cert,
        size_t cert_len)
{
    posix_inst_t *posix_inst = inst_to_posix(inst);

    if (!(posix_inst->flags & EHTTPD_FLAG_TLS)) {
        EHTTPD_LOGE(__func__, "not an ssl instance");
        return;
    }

    X509 *client_cacert = d2i_X509(NULL, cert, cert_len);
    int rv = SSL_CTX_add_client_CA(posix_inst->ssl, client_cacert);
    if (rv == 0) {
        EHTTPD_LOGE(__func__, "failed");
    }
}
#endif


/*********************************
 * \section Connection Functions
 *********************************/

bool ehttpd_is_ssl(ehttpd_conn_t *conn)
{
    posix_inst_t *posix_inst = inst_to_posix(conn->inst);

    return posix_inst->flags & EHTTPD_FLAG_TLS;
}

ssize_t ehttpd_send(ehttpd_conn_t *conn, void *buf, size_t len)
{
    ssize_t ret = -1;
    posix_conn_t *posix_conn = conn_to_posix(conn);
    posix_inst_t *posix_inst = inst_to_posix(conn->inst);

    if (len == 0) {
        return 0;
    }

    posix_conn->need_write = true;

    if (posix_inst->flags & EHTTPD_FLAG_TLS) {
#if defined(CONFIG_EHTTPD_TLS_MBEDTLS)
        while ((ret = mbedtls_ssl_write(&posix_conn->ssl, buf, len)) < 0) {
            if ((ret == MBEDTLS_ERR_SSL_WANT_READ) ||
                    (ret == MBEDTLS_ERR_SSL_WANT_WRITE)) {
                continue;
            }
            if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
                EHTTPD_LOGW(__func__, "connection reset by peer");
                close_connection(conn, false);
            } else if (ret < 0) {
                EHTTPD_LOGE(__func__, "mbedtls_ssl_write %d", ret);
                close_connection(conn, false);
            }
            ret = -1;
            break;
        }
#elif defined(CONFIG_EHTTPD_TLS_OPENSSL)
        enter_critical();
        ret = SSL_write(posix_conn->ssl, buf, len);
        exit_critical();
#endif
    } else {
        ret = write(posix_conn->fd, buf, len);
        if (ret < 0) {
            if (errno == ECONNRESET) {
                EHTTPD_LOGW(__func__, "connection reset by peer");
                close_connection(conn, false);
                return -1;
            } else if (errno == EPIPE) {
                EHTTPD_LOGW(__func__, "broken pipe");
                close_connection(conn, false);
                return -1;
            }
            EHTTPD_LOGE(__func__, "write %d", errno);
            close_connection(conn, false);
            return -1;
        }
    }

    return ret;
}

void ehttpd_disconnect(ehttpd_conn_t *conn)
{
    posix_conn_t *posix_conn = conn_to_posix(conn);

    posix_conn->need_close = true;
}

static void close_connection(ehttpd_conn_t *conn, bool do_shutdown)
{
    posix_conn_t *posix_conn = conn_to_posix(conn);
    posix_inst_t *posix_inst = inst_to_posix(conn->inst);

    if (!conn->closed) {
        conn->closed = true;
        ehttpd_recv_cb(conn, NULL, 0);
    }

    if (do_shutdown) {
        if (posix_inst->flags & EHTTPD_FLAG_TLS) {
#if defined(CONFIG_EHTTPD_TLS_MBEDTLS)
            int ret;
            while ((ret = mbedtls_ssl_close_notify(&posix_conn->ssl)) < 0) {
                if ((ret == MBEDTLS_ERR_SSL_WANT_READ) ||
                        (ret == MBEDTLS_ERR_SSL_WANT_WRITE)) {
                    continue;
                }
                EHTTPD_LOGE(__func__, "mbedtls_ssl_close_notify %d", ret);
                break;
            }
#elif defined(CONFIG_EHTTPD_TLS_OPENSSL)
            enter_critical();
            int ret = SSL_shutdown(posix_conn->ssl);
            exit_critical();
            if (ret == 0) {
                return;
            } else if (ret < 0) {
                EHTTPD_LOGE(__func__, "SSL_shutdown %d", ret);
            }
#endif
        }

        shutdown(posix_conn->fd, SHUT_RDWR);
    }

    if (posix_inst->flags & EHTTPD_FLAG_TLS) {
#if defined(CONFIG_EHTTPD_TLS_MBEDTLS)
        mbedtls_ssl_free(&posix_conn->ssl);
#elif defined(CONFIG_EHTTPD_TLS_OPENSSL)
        SSL_free(posix_conn->ssl);
#endif

    }

    close(posix_conn->fd);
    memset(posix_conn, 0, sizeof(*posix_conn));
    posix_conn->conn.inst = &posix_inst->inst;
    posix_conn->fd = -1;

    EHTTPD_LOGD(__func__, "closed %p", conn);
}


/***************************
 * \section Task Functions
 ***************************/

#if defined(CONFIG_EHTTPD_USE_SHUTDOWN)
static void init_shutdown(posix_inst_t *posix_inst);
#endif
static bool init_listen(posix_inst_t *posix_inst);
static void connect_event(posix_conn_t *posix_conn);
static void write_event(posix_conn_t *posix_conn);
static void read_event(posix_conn_t *posix_conn);

static void server_task(void *arg)
{
    posix_inst_t *posix_inst = inst_to_posix(arg);
    fd_set read_set, write_set;
    int max_fd;

    posix_inst->shutdown = false;

    memset(posix_inst->conn_buf, 0,
            sizeof(posix_conn_t) * posix_inst->conn_max);

    for (int i = 0; i < posix_inst->conn_max; i++) {
        posix_inst->conn_buf[i].conn.inst = &posix_inst->inst;
        posix_inst->conn_buf[i].fd = -1;
    }

#if defined(CONFIG_EHTTPD_USE_SHUTDOWN)
    init_shutdown(posix_inst);
#endif

    if (!init_listen(posix_inst)) {
        ehttpd_thread_delete(posix_inst->thread);
    }

    while (!posix_inst->shutdown) {
        posix_conn_t *free_conn = NULL;
        max_fd = 0;

        FD_ZERO(&read_set);
        FD_ZERO(&write_set);

        for (int i = 0; i < posix_inst->conn_max; i++) {
            posix_conn_t *posix_conn = &posix_inst->conn_buf[i];

            if (posix_conn->fd < 0) {
                if (free_conn == NULL) {
                    free_conn = posix_conn;
                }
                continue;
            }

            FD_SET(posix_conn->fd, &read_set);
            if (posix_conn->need_write || posix_conn->need_close) {
                FD_SET(posix_conn->fd, &write_set);
            }

            max_fd = posix_conn->fd > max_fd ? posix_conn->fd : max_fd;
        }

        if (free_conn) {
            FD_SET(posix_inst->listen_fd, &read_set);
            max_fd = posix_inst->listen_fd > max_fd ?
                    posix_inst->listen_fd : max_fd;
        }

        if (posix_inst->captdns_fd >= 0) {
            FD_SET(posix_inst->captdns_fd, &read_set);
            max_fd = posix_inst->captdns_fd > max_fd ?
                    posix_inst->captdns_fd : max_fd;
        }

#if defined(CONFIG_EHTTPD_USE_SHUTDOWN)
        FD_SET(posix_inst->shutdown_fd, &read_set);
        max_fd = posix_inst->shutdown_fd > max_fd ?
                posix_inst->shutdown_fd : max_fd;
#endif

        struct timeval timeout = {
            .tv_sec = 0,
            .tv_usec = 100000,
        };
        if (select(max_fd + 1, &read_set, &write_set, NULL, &timeout) <= 0) {
            continue;
        }

#if defined(CONFIG_EHTTPD_USE_SHUTDOWN)
        if (FD_ISSET(posix_inst->shutdown_fd, &read_set)) {
            posix_inst->shutdown = true;
        }
#endif

        if ((posix_inst->captdns_fd >= 0) && FD_ISSET(posix_inst->captdns_fd,
                &read_set)) {
            ehttpd_captdns_recv(posix_inst->captdns);
        }

        if (FD_ISSET(posix_inst->listen_fd, &read_set)) {
            int i;
            connect_event(free_conn);
            for (i = 0; i < posix_inst->conn_max; i++) {
                posix_conn_t *posix_conn = &posix_inst->conn_buf[i];
                if (posix_conn->fd < 0) {
                    continue;
                }
            }
            if (i == posix_inst->conn_max) {
                ehttpd_set_close(&free_conn->conn, true);
            }
        }

        for (int i = 0; i < posix_inst->conn_max; i++) {
            posix_conn_t *posix_conn = &posix_inst->conn_buf[i];

            if (posix_conn->fd < 0) {
                continue;
            }

            if (FD_ISSET(posix_conn->fd, &read_set)) {
                read_event(posix_conn);
            }

            if (FD_ISSET(posix_conn->fd, &write_set)) {
                write_event(posix_conn);
            }
        }
    }

#if defined(CONFIG_EHTTPD_USE_SHUTDOWN)
    close(posix_inst->shutdown_fd);
#endif
    close(posix_inst->listen_fd);
    ehttpd_captdns_shutdown(posix_inst->captdns);

    for (int i = 0; i < posix_inst->conn_max; i++) {
        posix_conn_t *posix_conn = &posix_inst->conn_buf[i];

        if (posix_conn->fd >= 0) {
            close_connection(&posix_conn->conn, true);
        }
    }

    if (posix_inst->flags & EHTTPD_FLAG_TLS) {
#if defined(CONFIG_EHTTPD_TLS_MBEDTLS)
        mbedtls_x509_crt_free(&posix_inst->ssl->cert);
        mbedtls_pk_free(&posix_inst->ssl->pkey);
        mbedtls_ssl_config_free(&posix_inst->ssl->conf);
        mbedtls_ctr_drbg_free(&posix_inst->ssl->ctr_drbg);
        mbedtls_entropy_free(&posix_inst->ssl->entropy);
        free(posix_inst->ssl);
#elif defined(CONFIG_EHTTPD_TLS_OPENSSL)
        SSL_CTX_free(posix_inst->ssl);
#endif
    }

    ehttpd_thread_delete(posix_inst->thread);
    ehttpd_free(&posix_inst->inst);
}

#if defined(CONFIG_EHTTPD_USE_SHUTDOWN)
static void init_shutdown(posix_inst_t *posix_inst)
{
    char buf[16];
    posix_inst->shutdown_port = 60000;

    struct sockaddr_in shutdown_addr;
    memset(&shutdown_addr, 0, sizeof(shutdown_addr));
    shutdown_addr.sin_family = AF_INET;
    shutdown_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    shutdown_addr.sin_port = htons(posix_inst->shutdown_port);

    inet_ntop(AF_INET, &shutdown_addr.sin_addr, buf, sizeof(buf));

    posix_inst->shutdown_fd = socket(AF_INET, SOCK_DGRAM, 0);
    while (bind(posix_inst->shutdown_fd, (struct sockaddr *) &shutdown_addr,
            sizeof(shutdown_addr)) != 0) {
        posix_inst->shutdown_port++;
        shutdown_addr.sin_port = htons(posix_inst->shutdown_port);
    }

    EHTTPD_LOGI(__func__, "shutdown bound to UDP %s:%d", buf,
            posix_inst->shutdown_port);
}
#endif

static bool init_listen(posix_inst_t *posix_inst)
{
    posix_inst->listen_addr.sin_family = AF_INET;

    posix_inst->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (posix_inst->listen_fd < 0) {
        EHTTPD_LOGE(__func__, "failed to create socket");
        return false;
    }

    int enable = 1;
    setsockopt(posix_inst->listen_fd, SOL_SOCKET, SO_REUSEADDR, &enable,
            sizeof(int));

    char buf[16];
    inet_ntop(AF_INET, &posix_inst->listen_addr.sin_addr, buf, sizeof(buf));

    if (bind(posix_inst->listen_fd,
            (struct sockaddr *) &posix_inst->listen_addr,
            sizeof(posix_inst->listen_addr)) < 0) {
        EHTTPD_LOGE(__func__, "unable to bind to TCP %s:%d", buf,
                ntohs(posix_inst->listen_addr.sin_port));
        close(posix_inst->listen_fd);
        posix_inst->listen_fd = -1;
        return false;
    }

    if (listen(posix_inst->listen_fd, CONFIG_EHTTPD_LISTEN_BACKLOG) < 0) {
        EHTTPD_LOGE(__func__, "unable to listen on TCP %s:%d", buf,
                ntohs(posix_inst->listen_addr.sin_port));
        close(posix_inst->listen_fd);
        posix_inst->listen_fd = -1;
        return false;
    }

    EHTTPD_LOGI(__func__, "esphttpd listening on TCP %s:%d%s", buf,
            ntohs(posix_inst->listen_addr.sin_port),
            (posix_inst->flags & EHTTPD_FLAG_TLS) ? " TLS" : "");
    return true;
}

static void connect_event(posix_conn_t *posix_conn)
{
    posix_inst_t *posix_inst = inst_to_posix(posix_conn->conn.inst);
    socklen_t len = sizeof(posix_conn->addr);

    posix_conn->fd = accept(posix_inst->listen_fd,
            (struct sockaddr *) &posix_conn->addr, (socklen_t *) &len);
    if (posix_conn->fd < 0) {
        EHTTPD_LOGE(__func__, "accept failed");
        return;
    }

    char ipstr[16];
    struct sockaddr_in *sa = (struct sockaddr_in *) &posix_conn->addr;
    inet_ntop(AF_INET, &sa->sin_addr, ipstr, sizeof(ipstr));
    EHTTPD_LOGD(__func__, "new connection from %s:%d%s %p", ipstr,
            ntohs(sa->sin_port), posix_inst->flags & EHTTPD_FLAG_TLS ?
            " TLS" : "", posix_conn);

    int keepAlive = 1;
    int keepIdle = 60;
    int keepInterval = 5;
    int keepCount = 3;
    int nodelay = 0;
#if defined(CONFIG_EHTTPD_TCP_NODELAY)
    nodelay = 1;  // enable TCP_NODELAY to speed-up transfers of small files.
                  // See Nagle's Algorithm.
#endif

    setsockopt(posix_conn->fd, SOL_SOCKET, SO_KEEPALIVE,
            (void *) &keepAlive, sizeof(keepAlive));
    setsockopt(posix_conn->fd, IPPROTO_TCP, TCP_KEEPIDLE,
            (void *) &keepIdle, sizeof(keepIdle));
    setsockopt(posix_conn->fd, IPPROTO_TCP, TCP_KEEPINTVL,
            (void *) &keepInterval, sizeof(keepInterval));
    setsockopt(posix_conn->fd, IPPROTO_TCP, TCP_KEEPCNT,
            (void *) &keepCount, sizeof(keepCount));
    setsockopt(posix_conn->fd, IPPROTO_TCP, TCP_NODELAY,
            (void *) &nodelay, sizeof(nodelay));

    if (posix_inst->flags & EHTTPD_FLAG_TLS) {
#if defined(CONFIG_EHTTPD_TLS_MBEDTLS)
        mbedtls_ssl_init(&posix_conn->ssl);

        int ret = mbedtls_ssl_setup(&posix_conn->ssl, &posix_inst->ssl->conf);
        if (ret != 0) {
            EHTTPD_LOGE(__func__, "mbedtls_ssl_setup %d", ret);
            goto err;
        }

        mbedtls_ssl_set_bio(&posix_conn->ssl, &posix_conn->fd,
                mbedtls_net_send, mbedtls_net_recv, NULL);

        while ((ret = mbedtls_ssl_handshake(&posix_conn->ssl)) != 0) {
            if ((ret != MBEDTLS_ERR_SSL_WANT_READ) &&
                    (ret != MBEDTLS_ERR_SSL_WANT_WRITE)) {
                EHTTPD_LOGE(__func__, "mbedtls_ssl_handshake %d", ret);
                goto err;
            }
        }
#elif defined(CONFIG_EHTTPD_TLS_OPENSSL)
        posix_conn->ssl = SSL_new(posix_inst->ssl);
        if (posix_conn->ssl == NULL) {
            EHTTPD_LOGE(__func__, "SSL_new");
            goto err;
        }

        SSL_set_fd(posix_conn->ssl, posix_conn->fd);

        enter_critical();
        int ret = SSL_accept(posix_conn->ssl);
        exit_critical();
        if (ret <= 0) {
            ret = SSL_get_error(posix_conn->ssl, ret);
            EHTTPD_LOGE(__func__, "SSL_accept %d", ret);
            goto err;
        }
#endif
    }

    posix_conn->conn.inst = &posix_inst->inst;
    posix_conn->conn.priv.flags |= HFL_NEW_CONN;

    return;

err:
    if (posix_conn->fd >= 0) {
        close(posix_conn->fd);
    }
#if defined(CONFIG_EHTTPD_TLS_MBEDTLS)
    mbedtls_ssl_free(&posix_conn->ssl);
#elif defined(CONFIG_EHTTPD_TLS_OPENSSL)
    SSL_free(posix_conn->ssl);
#endif
    posix_conn->fd = -1;
}

static void write_event(posix_conn_t *posix_conn)
{
    if (posix_conn->need_write) {
        posix_conn->need_write = false;
        if (ehttpd_sent_cb(&posix_conn->conn) != EHTTPD_CB_SUCCESS) {
            close_connection(&posix_conn->conn, true);
        }
    }
    if (posix_conn->need_close) {
        close_connection(&posix_conn->conn, true);
    }
}

static void read_event(posix_conn_t *posix_conn)
{
    posix_inst_t *posix_inst = inst_to_posix(posix_conn->conn.inst);
    ssize_t ret = -1;

    if (posix_inst->flags & EHTTPD_FLAG_TLS) {
#if defined(CONFIG_EHTTPD_TLS_MBEDTLS)
        ret = mbedtls_ssl_read(&posix_conn->ssl, posix_inst->buf,
                CONFIG_EHTTPD_RECVBUF_SIZE);
        if (ret <= 0) {
            if (ret == 0) {
                /* do nothing */;
            } else if ((ret == MBEDTLS_ERR_SSL_WANT_READ) ||
                    (ret == MBEDTLS_ERR_SSL_WANT_WRITE)) {
                return;
            } else if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                /* do nothing */
            } else if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
                EHTTPD_LOGW(__func__, "connection reset by peer");
            } else {
                EHTTPD_LOGE(__func__, "mbedtls error: %d", ret);
            }
            close_connection(&posix_conn->conn, false);
            return;
        }
#elif defined(CONFIG_EHTTPD_TLS_OPENSSL)
        // select() does not detect all available data, this
        // re-read approach resolves an issue where data is stuck in
        // TLS internal buffers
        do {
            enter_critical();
            ret = SSL_read(posix_conn->ssl, posix_inst->buf,
                    CONFIG_EHTTPD_RECVBUF_SIZE);
            exit_critical();
            if (ret < 0) {
                int ret = SSL_get_error(posix_conn->ssl, ret);
                EHTTPD_LOGE(__func__, "SSL_read %d", ret);
                close_connection(&posix_conn->conn, false);
                return;
            } else if (ret == 0) {
                close_connection(&posix_conn->conn, false);
                return;
            }

            if (ehttpd_recv_cb(&posix_conn->conn, posix_inst->buf, ret) !=
                    EHTTPD_CB_SUCCESS) {
                close_connection(&posix_conn->conn, true);
            }
        } while (SSL_has_pending(posix_conn->ssl));
        return;
#endif
    } else {
        ret = recv(posix_conn->fd, posix_inst->buf,
                CONFIG_EHTTPD_RECVBUF_SIZE, 0);
        if (ret < 0) {
            if (errno == ECONNRESET) {
                EHTTPD_LOGW(__func__, "connection reset by peer");
                close_connection(&posix_conn->conn, false);
                return;
            }
            EHTTPD_LOGE(__func__, "recv error %d", errno);
            close_connection(&posix_conn->conn, false);
            return;
        } else if (ret == 0) {
            close_connection(&posix_conn->conn, false);
            return;
        }
    }

    if (ehttpd_recv_cb(&posix_conn->conn, posix_inst->buf, ret) !=
            EHTTPD_CB_SUCCESS) {
        close_connection(&posix_conn->conn, true);
    }
}
