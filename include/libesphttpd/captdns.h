/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "httpd.h"

#include <netinet/in.h>


/************************
 * \section Captive DNS
 ************************/

/**
 * \brief Opaque captdns instance type
 */
typedef struct ehttpd_captdns_t ehttpd_captdns_t;

/**
 * \brief Start the captdns service
 *
 * \return \li a captdns instance or NULL on error
 *
 * \par Description
 * \verbatim embed:rst:leading-asterisk
 *
 * This starts listening for DNS queries on **0.0.0.0:53**.
 *
 * See :cpp:func:`ehttpd_captdns_start_ex()` for more details.
 *
 * \endverbatim */
ehttpd_captdns_t *ehttpd_captdns_start(
    ehttpd_inst_t *inst /** [in] initialized httpd instance */
);

/**
 * \brief Start the captdns service with custom bind
 *
 * \return \li a captdns instance or NULL on error
 *
 * \par Description
 * \verbatim embed:rst:leading-asterisk
 *
 * This starts listening for DNS queries on the address and port in sockaddr.
 * DNS queries handled include:
 *
 * **A**
 *
 *     If **addr.sin_addr** is not **0.0.0.0**, it is returned. Otherwise, on
 *     CONFIG_IDF_TARGET_ESP8266 or ESP_PLATFORM the netif ip address of the
 *     matching netif will be returned. Else, it will return the from address
 *     masked with **255.255.255.0** and the last octet set to **1**.
 *
 * **NS**
 *
 *     **ns.** will be returned.
 *
 * **URI**
 *
 *     **http://esp.nonet** will be returned.
 *
 * \endverbatim */
ehttpd_captdns_t *ehttpd_captdns_start_ex(
    ehttpd_inst_t *inst, /** [in] initialized httpd instance */
    struct sockaddr *addr /** [in] address/port to bind */
);

/**
 * \brief Shutdown the captdns service
 *
 * \par Description
 * \verbatim embed:rst:leading-asterisk
 *
 * This will be called automatically if **CONFIG_EHTTPD_USE_SHUTDOWN** is
 * enabled and a shutdown event occurs.
 *
 * \endverbatim */
void ehttpd_captdns_shutdown(
    ehttpd_captdns_t *captdns /** [in] captdns instance */
);


#ifdef __cplusplus
} /* extern "C" */
#endif
