/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "httpd_priv.h"

#include <limits.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(CONFIG_IDF_TARGET_ESP8266) || defined(ESP_PLATFORM)
# include <lwip/sockets.h>
#endif


/**
 * Design notes:
 *  - The platform code owns the memory management of connections
 *  - The platform embeds ehttpd_conn_t at the top of its own structure,
 *    allowing ehttpd_conn_t* to be cast to the platform structure.
 */

#define EHTTPD_VERSION "1.0.0"

// Max post buffer len. This is dynamically malloc'd as needed.
#ifndef CONFIG_EHTTPD_MAX_POST_SIZE
# define CONFIG_EHTTPD_MAX_POST_SIZE 2048
#endif

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type, member) );})


/*********************
 * \section Typedefs
 *********************/

typedef struct ehttpd_route_t ehttpd_route_t;
typedef struct ehttpd_inst_t ehttpd_inst_t;
typedef struct ehttpd_request_t ehttpd_request_t;
typedef struct ehttpd_conn_t ehttpd_conn_t;
typedef struct ehttpd_post_t ehttpd_post_t;
typedef struct espfs_fs_t espfs_fs_t;
typedef struct ehttpd_method_entry_t ehttpd_method_entry_t;

typedef enum ehttpd_flags_t ehttpd_flags_t;
typedef enum ehttpd_status_t ehttpd_status_t;
typedef enum ehttpd_method_t ehttpd_method_t;

typedef ehttpd_status_t (*ehttpd_route_handler_t)(ehttpd_conn_t *conn);
typedef ehttpd_status_t (*ehttpd_recv_handler_t)(ehttpd_conn_t *conn,
        void *buf, int len);
typedef void (*ehttpd_thread_func_t)(void *arg);
typedef void (*ehttpd_timer_handler_t)(void *arg);


/*********************
 * \section Instance
 *********************/

enum ehttpd_flags_t {
    EHTTPD_FLAG_NONE                = 0,
    EHTTPD_FLAG_TLS                 = (1 << 0)
};


/**
 * \brief A struct that describes a route
 *
 * This is used to send dispatch URL requests to route handlers.
 */
typedef struct ehttpd_route_t {
    ehttpd_route_t *next; /**< next route entry */
    ehttpd_route_handler_t handler; /**< route handler function */
    const char *path; /**< path expression for this route */
    size_t argc; /**< argument count */
    const void *argv[]; /**< argument list */
} ehttpd_route_t;

/**
 * \brief A struct for httpd instances
 *
 * This struct is shared between all connections.
 */
struct ehttpd_inst_t {
    ehttpd_route_t *route_head; /**< head of route linked list */
    ehttpd_route_t *route_tail; /**< tail of route linked list */
    size_t num_routes; /**< number of routes */
    espfs_fs_t *espfs; /**< \a espfs_fs_t instance */
    void *user; /**< user data */
};


/**
 * \brief Create a httpd instance
 *
 * \return httpd instance or NULL on error
 */
ehttpd_inst_t *ehttpd_init(
    const char *addr, /** [in] bind address:port, or if NULL, 0.0.0.0:80 or
                               0.0.0.0:443 depending on TLS */
    ehttpd_flags_t flags /** [in] configuration flags */
);

/**
 * \brief Insert a route at a given index in the route list
 */
void ehttpd_route_vinsert(
    ehttpd_inst_t *inst, /** [in] httpd instance */
    ssize_t index, /** [in] index of route entry, can be negative */
    const char *path, /** [in] path expression for this route */
    ehttpd_route_handler_t handler, /** [in] route handler function */
    size_t argc, /** [in] argument count */
    va_list args /** [in] arguments */
);

/**
 * \brief Insert a route at a given index in the route list
 */
void ehttpd_route_insert(
    ehttpd_inst_t *inst, /** [in] httpd instance */
    ssize_t index, /** [in] index of route entry, can be negative */
    const char *path, /** [in] path expression for this route */
    ehttpd_route_handler_t handler, /** [in] route handler function */
    size_t argc, /** [in] argument count */
    ... /** [in] arguments */
);

/**
 * \brief Append a route to the end of the route list
 */
void ehttpd_route_append(
    ehttpd_inst_t *inst, /** [in] httpd instance */
    const char *path, /** [in] path expression for this route */
    ehttpd_route_handler_t handler, /** [in] route handler function */
    size_t argc, /** [in] argument count */
    ... /** [in] arguments */
);

/**
 * \brief Return the route at the given index of the route list
 *
 * \returns The route at the given index
 */
ehttpd_route_t *ehttpd_route_get(
    ehttpd_inst_t *inst, /** [in] httpd instance */
    ssize_t index /** [in] index of route entry, can be negative */
);

/**
 * \brief Delete a route at the given index of the route list
 */
void ehttpd_route_remove(
    ehttpd_inst_t *inst, /** [in] httpd instance */
    ssize_t index /** [in] index of route entry, can be negative */
);

#if defined(CONFIG_EHTTPD_TLS_MBEDTLS) || defined(CONFIG_EHTTPD_TLS_OPENSSL)
/**
 * \brief Set the ssl certificate and private key (in DER format)
 *
 * \note
 * \verbatim embed:rst:leading-asterisk
 *
 * This requires **EHTTPD_SSL_MBEDTLS** or **EHTTPD_SSL_OPENSSL**.
 *
 * This should be called before :c:func:`ehttpd_start()`.
 *
 * \endverbatim */
void ehttpd_set_cert_and_key(
    ehttpd_inst_t *inst, /** [in] httpd instance */
    const void *cert, /** [in] certificate data */
    size_t cert_len, /** [in] certificate length */
    const void *priv_key, /** [in] private key data */
    size_t priv_key_len /** [in] private key length */
);

/**
 * \brief Enable or disable client certificate verification
 *
 * \note This requires **EHTTPD_SSL_MBEDTLS** or **EHTTPD_SSL_OPENSSL**.
 *
 * This is disabled by default.
 */
void ehttpd_set_client_validation(
    ehttpd_inst_t *inst, /** [in] httpd instance */
    bool enable /** [in] true or false */
);

/**
 * \brief Add a client certificate (in DER format)
 *
 * \note
 * \verbatim embed:rst:leading-asterisk
 *
 * This requires **EHTTPD_SSL_MBEDTLS** or **EHTTPD_SSL_OPENSSL**.
 *
 * Enable client certificate verification using
 * :c:func:`ehttpd_set_client_validation()`.
 *
 * \endverbatim */
void ehttpd_add_client_cert(
    ehttpd_inst_t *inst, /** [in] httpd instance */
    const void *cert, /** [in] certificate data */
    size_t cert_len /** [in] certificate length */
);
#endif /* CONFIG_EHTTPD_TLS_OPENSSL */

/**
 * \brief Start a httpd instance
 *
 * \return true on success
 */
bool ehttpd_start(
    ehttpd_inst_t *inst /** [in] httpd instance */
);

/**
 * \brief Shutdown and delete httpd instance
 */
void ehttpd_destroy(
    ehttpd_inst_t *inst /** [in] httpd instance */
);


/***********************
 * \section Connection
 ***********************/

enum ehttpd_status_t {
    EHTTPD_STATUS_OK,
    EHTTPD_STATUS_NOTFOUND,
    EHTTPD_STATUS_AUTHENTICATED,
    EHTTPD_STATUS_MORE,
    EHTTPD_STATUS_DONE,
    EHTTPD_STATUS_CLOSE,
    EHTTPD_STATUS_FAIL,
};

/* This enum must be kept in sync with the ehttpd_methods list in httpd.c */
enum ehttpd_method_t {
    EHTTPD_METHOD_GET,
    EHTTPD_METHOD_POST,
    EHTTPD_METHOD_OPTIONS,
    EHTTPD_METHOD_PUT,
    EHTTPD_METHOD_PATCH,
    EHTTPD_METHOD_DELETE,
    EHTTPD_METHOD_UNKNOWN,
};

/**
 * \brief HTTP request data
 */
struct ehttpd_request_t {
    ehttpd_method_t method; /**< request method */
    const char *url; /**< URL without arguments */
    char *args; /**< URL arguments */
    char *headers; /**< the start of the headers */
    const char *hostname; /**< hostname header value */
};

/**
 * \brief HTTP connection data
 */
struct ehttpd_conn_t {
    ehttpd_inst_t *inst; /**< HTTP server instance */
    ehttpd_request_t request; /**< HTTP request data */
    ehttpd_post_t *post; /**< POST/PUT data */
    const ehttpd_route_t *route; /**< the route */
    void *user;  /**< user data */
    ehttpd_conn_priv_t priv; /**< internal data */
};

/**
 * \brief A struct describing the POST received
 */
struct ehttpd_post_t {
    size_t len; /**< Content-Length header value */
    size_t buf_len; /**< bytes in the post buffer */
    size_t received; /**< total bytes received so far */
    char *boundary; /**< start of the multipart boundary in conn->priv.head */
    char buf[CONFIG_EHTTPD_MAX_POST_SIZE]; /**< data buffer */
};

/**
 * \brief Return if connection is SSL or not
 *
 * \return true if SSL, false if not
 */
bool ehttpd_plat_is_ssl(
    ehttpd_conn_t *conn /** [in] connection instance */
);

/**
 * \brief Receive data over connection
 *
 * \return number of bytes that were actually read, or -1 on error
 */
ssize_t ehttpd_plat_recv(
    ehttpd_conn_t *conn, /** [in] connection instance */
    void *buf, /** [out] bytes */
    size_t len /** [in] data length */
);

/**
 * \brief Send data over connection
 *
 * \return number of bytes that were actually written, or -1 on error
 */
ssize_t ehttpd_plat_send(
    ehttpd_conn_t *conn, /** [in] connection instance */
    const void *buf, /** [in] bytes */
    size_t len /** [in] data length */
);

/**
 * \brief Receive data over connection, using req data first if available
 *
 * \return number of bytes that were actually read, or -1 on error
 */
ssize_t ehttpd_recv(
    ehttpd_conn_t *conn, /** [in] connection instance */
    void *buf, /** [in] bytes */
    size_t len /** [in] number of bytes to recv */
);

/**
 * \brief Send data over connection
 *
 * \return number of bytes that were actually written, or -1 on error
 */
ssize_t ehttpd_send(
    ehttpd_conn_t *conn, /** [in] connection instance */
    const void *buf, /** [in] bytes */
    ssize_t len /** [out] number of bytes to send or -1 for strlen */
);

/**
 * \brief Send data over connection using a format string
 *
 * \return number of bytes that were actually written, or -1 on error
 */
ssize_t ehttpd_sendf(
    ehttpd_conn_t *conn, /** [in] connection instance */
    const char *fmt, /** [in] format string */
    ... /** [in] format arguments */
);

/**
 * \brief Get the value of a header in the connection's head buffer
 *
 * \return header value if found, NULL otherwise
 */
const char *ehttpd_get_header(
    ehttpd_conn_t *conn, /** [in] connection instance */
    const char *name /** [in] header name */
);

/**
 * \brief Set chunked HTTP transfer mode
 *
 * \note You should call this before calling ehttpd_response.
 */
void ehttpd_set_chunked(
    ehttpd_conn_t *conn, /** [in] connection instance */
    bool enable /** [in] true for chunked */
);

/**
 * \brief Set connection closed header
 *
 * \note You should call this before ehttpd_response.
 */
void ehttpd_set_close(
    ehttpd_conn_t *conn, /** [in] connection instance */
    bool close /** [in] true to set close */
);

/**
 * \brief Start a http response
 *
 * \return bytes sent or -1 on error
 */
ssize_t ehttpd_response(
    ehttpd_conn_t *conn, /** [in] connection instance */
    int code /** [in] HTTP status code */
);

/**
 * \brief Send a custom HTTP header
 *
 * \return bytes sent or -1 on error
 */
ssize_t ehttpd_send_header(
    ehttpd_conn_t *conn, /** [in] connection instance */
    const char *name, /** [in] header name */
    const char *value /** [in] header value */
);

/**
 * \brief Send a sensible cache control header
 *
 * \return bytes sent or -1 on error
 */
ssize_t ehttpd_send_cache_header(
    ehttpd_conn_t *conn, /** [in] connection instance */
    const char *mime /** [in] mime type */
);

/**
 * \brief Start a chunk with given length
 *
 * \return bytes sent or -1 on error
 */
ssize_t ehttpd_chunk_start(
    ehttpd_conn_t *conn, /** [in] connection instance */
    size_t len /** [in] chunk length in bytes */
);

/**
 * \brief End a chunk
 *
 * \return bytes sent or -1 on error
 */
ssize_t ehttpd_chunk_end(
    ehttpd_conn_t *conn /** [in] connection instance */
);


/********************
 * \section Utility
 ********************/

/**
 * \brief 404 not found handler
 *
 * \note this function is defined \_\_weak\_\_ so you can override it.
 */
ehttpd_status_t ehttpd_route_404(
    ehttpd_conn_t *conn
);

/**
 * \brief Send a redirect response
 */
void ehttpd_redirect(
    ehttpd_conn_t *conn, /** [in] connection instance */
    const char *url /** [in] url to redirect to */
);

/**
 * \brief Decode a percent-encoded value
 *
 * \return actual number of bytes written excluding the NULL terminator
 *
 * \note Output buffer is always NULL terminated
 */
size_t ehttpd_url_decode(
    const char *in, /** [in] input buffer */
    ssize_t in_len, /** [in] input buffer len or -1 for strlen() */
    char *out, /** [out] output buffer or NULL */
    size_t *out_len /* [in,out] output buffer length, returns the total bytes
                                required */
);

/**
 * \brief Find an parameter in GET string or POST data
 *
 * \return actual number of bytes written excluding the NULL terminator, or -1
 *         if not found
 *
 * \note Output buffer is always NULL terminated
 */
ssize_t ehttpd_find_param(
    const char *needle, /** [in] parameter to search for */
    const char *haystack, /** [in] GET or POST data to search */
    char *out, /** [out] urldecoded output buffer or NULL */
    size_t *out_len /** [in,out] output buffer length, returns total bytes
                                  required */
);

/**
 * \brief Return the mimetype for a given URL
 *
 * \return mime type string
 */
const char *ehttpd_get_mimetype(
    const char *url /** [in] URL */
);

/**
 * \brief Custom sprintf implementation
 *
 * \return number of characters written to str or -1 on error
 */
int ehttpd_sprintf(
    char *str, /* [out] output string */
    const char *format, /* [in] format string */
    ... /* [in] args */
);

/**
 * \brief Custom snprintf implementation
 *
 * \return number of characters that could have been written to str. A value
 *         greater-than or equal to size indicates truncation.
 */
int ehttpd_snprintf(
    char *str, /* [out] output string */
    size_t size, /* [in] max length of str buffer */
    const char *format, /* [in] format string */
    ... /* [in] args */
);

/**
 * \brief Custom vsnprintf implementation
 *
 * \return number of characters that could have been written to str. A value
 *         greater-than or equal to size indicates truncation.
 */
int ehttpd_vsnprintf(
    char *str, /* [out] output string */
    size_t size, /* [in] max length of str buffer */
    const char *format, /* [in] format string */
    va_list va /* [in] args */
);


#ifdef __cplusplus
}
#endif
