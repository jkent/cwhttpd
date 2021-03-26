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
typedef struct ehttpd_conn_t ehttpd_conn_t;
typedef struct ehttpd_post_t ehttpd_post_t;
typedef struct espfs_fs_t espfs_fs_t;

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
    EHTTPD_FLAG_TLS                 = (1 << 0),
};

/**
 * \brief A struct that describes a route
 *
 * This is used to send dispatch URL requests to route handlers.
 */
typedef struct ehttpd_route_t {
    ehttpd_route_t *next; /**< next route entry */
    ehttpd_route_handler_t handler; /**< route handler function */
    void *arg; /**< first argument */
    void *arg2; /**< second argument */
    char path[]; /**< path expression for this route */
} ehttpd_route_t;

/**
 * \brief A struct for httpd instances
 *
 * This struct is shared between all connections.
 */
struct ehttpd_inst_t {
    ehttpd_route_t *route_head; /* head of route linked list */
    ehttpd_route_t *route_tail; /* tail of route linked list */
    espfs_fs_t *espfs; /**< \a espfs_fs_t instance */
    void *user; /**< user data */
};

/**
 * \brief Create an esphttpd instance
 *
 * \return httpd instance or NULL on error
 */
ehttpd_inst_t *ehttpd_init(
    const char *addr, /** [in] bind address:port, or if NULL, 0.0.0.0:80 or
                               0.0.0.0:443 depending on TLS */
    void *conn_buf, /** [in] buffer for connection data, or NULL for
                             automatically managed */
    size_t conn_max, /** [in] max number of concurrent connections */
    ehttpd_flags_t flags /** [in] configuration flags */
);

/**
 * \brief Return the size in bytes needed for ``conn_max`` connections
 */
size_t ehttpd_get_conn_buf_size(
    size_t conn_max /** [in] max number of concurrent connections */
);

/**
 * \brief Insert a route at the head of the route list
 *
 * \returns The inserted route
 */
ehttpd_route_t *ehttpd_route_insert_head(
    ehttpd_inst_t *inst, /** [in] httpd instance */
    const char *path /** [in] path expression for this route */
);

/**
 * \brief Append a route to the tail of the route list
 *
 * \returns The inserted route
 */
ehttpd_route_t *ehttpd_route_insert_tail(
    ehttpd_inst_t *inst, /** [in] httpd instance */
    const char *path /** [in] path expression for this route */
);

/**
 * \brief Insert a route to the route list after a given route
 *
 * \returns The inserted route
 */
ehttpd_route_t *ehttpd_route_insert_after(
    ehttpd_inst_t *inst, /** [in] httpd instance */
    ehttpd_route_t *after, /** [in] route entry to insert after */
    const char *path /** [in] path expression for this route */
);

/**
 * \brief Remove a route
 */
void ehttpd_route_remove(
    ehttpd_inst_t *inst, /** [in] httpd instance */
    ehttpd_route_t *route /** [in] route entry to remove */
);

/**
 * \brief Remove a route from head of the route list
 */
void ehttpd_route_remove_head(
    ehttpd_inst_t *inst /** [in] httpd instance */
);

/**
 * \brief Start the httpd server
 *
 * \return **true** on sucess or **false** on error
 */
bool ehttpd_start(
    ehttpd_inst_t *inst /** [in] httpd instance */
);

/**
 * \brief Lock the instance mutex
 */
void ehttpd_lock(
    ehttpd_inst_t *inst /** [in] httpd instance */
);

/**
 * \brief Unlock the instance mutex
 */
void ehttpd_unlock(
    ehttpd_inst_t *inst /** [in] httpd instance */
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
 * This must be called before :c:func:`ehttpd_start()` if ``inst`` has
 * **EHTTPD_FLAG_TLS** set.
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
 * \note
 * \verbatim embed:rst:leading-asterisk
 *
 * This requires **EHTTPD_SSL_MBEDTLS** or **EHTTPD_SSL_OPENSSL**.
 *
 * This is disabled by default.
 *
 * \endverbatim */
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

#ifdef CONFIG_EHTTPD_USE_SHUTDOWN
/**
 * \brief Shutdown httpd instance
 */
void ehttpd_shutdown(
    ehttpd_inst_t *inst /** [in] httpd instance */
);
#endif /* CONFIG_EHTTPD_USE_SHUTDOWN */


/***********************
 * \section Connection
 ***********************/

enum ehttpd_status_t {
    EHTTPD_STATUS_NOTFOUND,
    EHTTPD_STATUS_FOUND,
    EHTTPD_STATUS_MORE,
    EHTTPD_STATUS_DONE,
    EHTTPD_STATUS_AUTHENTICATED,
};

enum ehttpd_method_t {
    EHTTPD_METHOD_UNKNOWN,
    EHTTPD_METHOD_GET,
    EHTTPD_METHOD_POST,
    EHTTPD_METHOD_OPTIONS,
    EHTTPD_METHOD_PUT,
    EHTTPD_METHOD_PATCH,
    EHTTPD_METHOD_DELETE,
};

/**
 * \brief HTTP connection data
 */
struct ehttpd_conn_t {
    ehttpd_inst_t *inst; /**< HTTP server instance */
    ehttpd_method_t method; /**< request method */
    const char *url; /**< the URL request without GET arguments */
    char *args; /**< the URL arguments */
    char *headers; /**< the start of the headers */
    const char *hostname; /**< hostname field */
    ehttpd_post_t *post; /**< POST/PUT data */
    const ehttpd_route_t *route; /**< the route */
    ehttpd_recv_handler_t recv_handler; /**< body recv handler */
    void *user;  /**< user data */
    bool closed; /**< closed indicator for routes */
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
 * You should call this before calling ehttpd_start_response.
 */
void ehttpd_set_chunked_encoding(
    ehttpd_conn_t *conn, /** [in] connection instance */
    bool enable /** [in] true for chunked */
);

/**
 * \brief Set connection closed header
 *
 * You should call this before ehttpd_start_response.
 */
void ehttpd_set_close(
    ehttpd_conn_t *conn, /** [in] connection instance */
    bool close /** [in] true to set close */
);

/**
 * \brief Enqueue the response headers
 */
void ehttpd_start_response(
    ehttpd_conn_t *conn, /** [in] connection instance */
    int code /** [in] HTTP status code */
);

/**
 * \brief Enqueue a custom HTTP header
 */
void ehttpd_header(
    ehttpd_conn_t *conn, /** [in] connection instance */
    const char *name, /** [in] header name */
    const char *value /** [in] header value */
);

/**
 * \brief End the header section and start the message body
 */
void ehttpd_end_headers(
    ehttpd_conn_t *conn /** [in] connection instance */
);

/**
 * \brief Enqueue sensible cache control headers
 */
void ehttpd_add_cache_header(
    ehttpd_conn_t *conn, /** [in] connection instance */
    const char *mime /** [in] mime type */
);

/**
 * \brief Ready the send buffer for data
 *
 * \return free space in buffer or -1 if required lenght not met
 */
ssize_t ehttpd_prepare(
    ehttpd_conn_t *conn, /** [in] connection instance */
    void **buf, /** [out] buffer start */
    size_t len /** [in] required length */
);

/**
 * \brief Add data to send buffer
 *
 * \note If the lengh of the data exceeds the free space in the send buffer,
 * no data is written to the buffer.
 *
 * \return true if sucessful or false if the buffer does not have enough space
 */
bool ehttpd_enqueue(
    ehttpd_conn_t *conn, /** [in] connection instance */
    const void *buf, /** [in] data to add */
    ssize_t len /** [in] data length or -1 for strlen() */
);

/**
 * \brief Add formatted text to send buffer
 *
 * \note If the lengh of the data exceeds the free space in the send buffer,
 * no data is written to the buffer.
 *
 * \return true if sucessful or false if the buffer does not have enough space
 */
bool ehttpd_enqueuef(
    ehttpd_conn_t *conn, /** [in] connection instance */
    const char *fmt, /** [in] format string */
    ... /** [in] args */
);

/**
 * \brief Encode html entities and add to the send buffer
 *
 * \note If the lengh of the data exceeds the free space in the send buffer,
 * no data is written to the buffer.
 *
 * \return true if sucessful or false if the buffer does not have enough space
 */
bool ehttpd_enqueue_html(
    ehttpd_conn_t *conn, /** [in] connection instance */
    const char *buf, /** [in] data to add */
    ssize_t len /** [in] data length or -1 for strlen() */
);

/**
 * \brief Encode javascript and add to the send buffer
 *
 * \note If the lengh of the data exceeds the free space in the send buffer,
 * no data is written to the buffer.
 *
 * \return true if sucessful or false if the buffer does not have enough space
 */
bool ehttpd_enqueue_js(
    ehttpd_conn_t *conn, /** [in] connection instance */
    const char *data, /** [in] data to add */
    ssize_t len /** [in] data length or -1 for strlen() */
);

/**
 * \brief Flush the send buffer
 */
void ehttpd_flush(
    ehttpd_conn_t *conn /** [in] connection instance */
);

/**
 * \brief Return if connection is SSL or not
 *
 * \return true if SSL, false if not
 *
 * \note This function implementation is platform defined
 */
bool ehttpd_is_ssl(
    ehttpd_conn_t *conn /** [in] connection instance */
);

/**
 * \brief Send data over connection
 *
 * \return number of bytes that were actually written, or -1 on error
 *
 * \note This function implementation is platform defined
 */
ssize_t ehttpd_send(
    ehttpd_conn_t *conn, /** [in] connection instance */
    void *buf, /** [in] bytes */
    size_t len /** [in] data length */
);

/**
 * \brief Schedule a connection for close
 *
 * \note This function implementation is platform defined
 */
void ehttpd_disconnect(
    ehttpd_conn_t *conn /** [in] connection instance */
);


/********************
 * \section Utility
 ********************/

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
