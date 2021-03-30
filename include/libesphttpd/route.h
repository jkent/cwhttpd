/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "httpd.h"

#if defined(CONFIG_IDF_TARGET_ESP8266) || defined(ESP_PLATFORM)
# include <esp_event.h>
#endif


/******************************
 * \section Filesystem Routes
 ******************************/

/**
 * \brief Header callback function prototype
 */
typedef void (*ehttpd_header_cb_t)(
    ehttpd_conn_t *conn /** [in] connection instance */
);

/**
 * \brief Template callback function prototype
 */
typedef void (*ehttpd_tpl_cb_t)(
    ehttpd_conn_t *conn, /** [in] connection instance */
    char *token, /** [in] current template token or NULL if end */
    void **user  /** [in,out] user data double pointer, NULL on first token */
);

/**
 * \brief Filesystem GET route handler
 *
 * \par Description
 * \verbatim embed:rst:leading-asterisk
 *
 * This handler reads files and passes them through to the HTTP client.
 * If path is a directory, ``index.html`` is tried in that directory next.
 * Failing that, it falls through to the next route handler.
 *
 * There are a few different ways of specifying routes, which all provide
 * slightly different results:
 *
 *   1. ::
 *
 *       EHTTPD_ROUTE_FS("*", NULL),
 *
 *     The request **GET** ``/index.html`` would map to the filesystem path
 *     ``/index.html``.
 *
 *   2. ::
 *
 *         EHTTPD_ROUTE_FS("*", "/test"),
 *
 *      The request **GET** ``/index.html`` would map to the filesystem path
 *      ``/test/index.html``.
 *
 *   3. ::
 *
 *         EHTTPD_ROUTE_FS("*", "/test/index.html"),
 *
 *      The request **GET** ``/anything.html`` would map to the filesystem
 *      path ``/test/index.html``.
 *
 *   4. ::
 *
 *         ehttpd_route_fs_t arg = {
 *             .basepath = '/test',
 *         };
 *
 *      ::
 *
 *         EHTTPD_ROUTE_FS_EX("*", &arg),
 *
 *      The request **GET** ``/index.html`` would map to the filesystem
 *      path ``/test/index.html``.
 *
 *   5. ::
 *
 *         ehttpd_route_fs_t arg = {
 *             .basepath = '/test/index.html',
 *         };
 *
 *      ::
 *
 *         EHTTPD_ROUTE_FS_EX("*", &arg),
 *
 *      The request **GET** ``/anything.html`` would map to the filesystem
 *      path ``/test/index.html``.
 *
 * \endverbatim */
ehttpd_status_t ehttpd_route_fs_get(ehttpd_conn_t *conn);

/**
 * \brief Filesystem template route handler
 *
 * \par Description
 * \verbatim embed:rst:leading-asterisk
 *
 * This handler processes files with a user template callback. arg and
 * **basepath** work the same way as :cpp:func:`ehttpd_route_file_get()`,
 * except that in the case of a directory, ``index.tpl`` is tried next.
 *
 * **arg2** or **template_cb** gets called every time it finds a
 * ``%token%`` in the template file, allowing you to emit dynamic content.
 *
 * \endverbatim */
ehttpd_status_t ehttpd_route_fs_tpl(ehttpd_conn_t *conn);

/**
 * \brief POST/PUT handler for uploading files
 *
 * \par Description
 * \verbatim embed:rst:leading-asterisk
 *
 * If http method is not **PUT** or **POST**, this route handler returns
 * **EHTTPD_STATUS_NOTFOUND** so a route handler fallthrough can occur.
 *
 * Specify base directory (with trailing slash) or single file as first arg.
 *
 * Filename can be specified 3 ways, in order of priority lowest to highest:
 *
 *   1. URL Path. PUT ``/file.txt``
 *   2. Inside multipart/form-data (TODO: not supported yet)
 *   3. URL Parameter. **POST** ``/upload.cgi?filename=path%2Fnewfile.txt``
 *
 * Usage:
 * ::
 *
 *   EHTTPD_ROUTE_ARG("*", ehttpd_route_fs_put, "/base/directory/")
 *
 * * Allows creating/replacing files anywhere under "/base/directory/".  Don't
 *   forget to specify trailing slash in arg!
 * * Example: **POST** or **PUT** ``/anydir/anyname.txt``
 *
 * ::
 *
 *   EHTTPD_ROUTE_ARG("/upload.cgi", ehttpd_route_fs_put, "/sdcard/")
 *
 * * Allows creating/replacing files anywhere under "/sdcard/".  Don't
 *   forget to specify trailing slash in arg!
 * * Example: **POST** or **PUT**
 *   ``/filesystem/upload.cgi?filename=newdir%2Fnewfile.txt``
 *
 * ::
 *
 *   EHTTPD_ROUTE_ARG("/file.txt", ehttpd_route_fs_put, "/sdcard/file.txt")
 *
 * * Allows only replacing content of one file at "/sdcard/file.txt".
 * * example: **POST** or **PUT** ``/file.txt``
 * \endverbatim */
ehttpd_status_t ehttpd_route_fs_put(ehttpd_conn_t *conn);

/*************************
 * \section Espfs Routes
 *************************/

/**
 * \brief Espfs GET route handler
 */
ehttpd_status_t ehttpd_route_espfs_get(ehttpd_conn_t *conn);

/**
 * \brief Espfs template route handler
 */
ehttpd_status_t ehttpd_route_espfs_tpl(ehttpd_conn_t *conn);

/**
 * \brief Espfs index route handler
 */
ehttpd_status_t ehttpd_route_espfs_index(ehttpd_conn_t *conn);


/****************************
 * \section Redirect Routes
 ****************************/

/**
 * \brief Redirect one URL to another
 *
 * \par Description
 * \verbatim embed:rst:leading-asterisk
 *
 * The **arg** is expected to be the new path or URL.
 *
 * Example::
 *
 *     EHTTPD_ROUTE_ARG("/", ehttpd_route_redirect, "/index.html"),
 *
 * \endverbatim */
ehttpd_status_t ehttpd_route_redirect(ehttpd_conn_t *conn);

/** \brief URL redirect to a new hostname if not on current hostname
 *
 * \par Description
 * \verbatim embed:rst:leading-asterisk
 *
 * This handler redirects to a fixed URL of **http[s]://[hostname]** if
 * hostname field of request isn't already that hostname. Use this in
 * combination with a DNS server that redirects everything to the ESP in
 * order to load a HTML page as soon as a phone, tablet etc connects to the
 * ESP.
 *
 * It is recommended to place this route handler early or first in your route
 * list so the redirect occurs before other route processing.
 *
 * The **arg** to this route handler is the hostname that the client will be
 * redirected to.
 *
 * If the hostname matches the hostname specified in arg then this route
 * handler will return **EHTTPD_STATUS_NOTFOUND**, causing the libesphttpd
 * server to skip over this route handler and to continue processing with the
 * next route.
 *
 * Example::
 *
 *     EHTTPD_ROUTE_ARG("*", ehttpd_route_redirect_hostname, "esp.nonet"),
 *
 * \endverbatim */
ehttpd_status_t ehttpd_route_redirect_hostname(ehttpd_conn_t *conn);


/************************
 * \section Auth Routes
 ************************/

/**
 * \brief Callback type for user authentication
 *
 * \par Description
 * \verbatim embed:rst:leading-asterisk
 *
 * Used with :cpp:func:`ehttpd_route_auth_basic()`. Function should
 * return username/passwords indexed by **no**.
 *
 * \endverbatim */
typedef int (*ehttpd_auth_account_cb_t)(
    ehttpd_conn_t *conn, /** [in] connection instance */
    int index, /** [in] account index */
    char *user, /** [out] username */
    int user_len, /** [in] user max length */
    char *pass, /** [out] password */
    int pass_len /** [in] pass max length */
);

/**
 * \brief Basic HTTP authentication handler
 *
 * \par Description
 * \verbatim embed:rst:leading-asterisk
 *
 * The **arg** is expected to be a callback function of
 * :cpp:type:`ehttpd_auth_account_cb_t` type.
 *
 * \endverbatim */
ehttpd_status_t ehttpd_route_auth_basic(ehttpd_conn_t *conn);


/*****************************
 * \section Websocket Routes
 *****************************/

ehttpd_status_t ehttpd_route_ws(ehttpd_conn_t *conn);


/************************
 * \section WiFi Routes
 ************************/

#if defined(CONFIG_IDF_TARGET_ESP8266) || defined(ESP_PLATFORM)
esp_err_t ehttpd_wifi_init(void);
void ehttpd_wifi_event_cb(system_event_t *event);
ehttpd_status_t ehttpd_tpl_wlan(ehttpd_conn_t *conn, char *token, void **arg);

ehttpd_status_t ehttpd_route_wifi_scan(ehttpd_conn_t *conn);
ehttpd_status_t ehttpd_route_wifi(ehttpd_conn_t *conn);
ehttpd_status_t ehttpd_route_wifi_connect(ehttpd_conn_t *conn);
ehttpd_status_t ehttpd_route_wifi_set_mode(ehttpd_conn_t *conn);
ehttpd_status_t ehttpd_route_wifi_ap_settings(ehttpd_conn_t *conn);
ehttpd_status_t ehttpd_route_wifi_status(ehttpd_conn_t *conn);
ehttpd_status_t ehttpd_route_wifi_start_wps(ehttpd_conn_t *conn);
#endif


/*************************
 * \section Flash Routes
 *************************/

#if defined(CONFIG_IDF_TARGET_ESP8266) || defined(ESP_PLATFORM)
ehttpd_status_t ehttpd_route_fw_get_next(ehttpd_conn_t *conn);
ehttpd_status_t ehttpd_route_fw_upload(ehttpd_conn_t *conn);
ehttpd_status_t ehttpd_route_fw_reboot(ehttpd_conn_t *conn);
ehttpd_status_t ehttpd_route_fw_set_boot(ehttpd_conn_t *conn);
ehttpd_status_t ehttpd_route_fw_erase_flash(ehttpd_conn_t *conn);
ehttpd_status_t ehttpd_route_fw_get_flash_info(ehttpd_conn_t *conn);
#endif


#ifdef __cplusplus
} /* extern "C" */
#endif
