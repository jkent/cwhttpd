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
typedef struct cwhttpd_captdns_t cwhttpd_captdns_t;

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
 *     ESP_PLATFORM the netif ip address of the matching netif will be
 *     returned. Else, it will return the from address masked with
 *     **255.255.255.0** and the last octet set to **1**.
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
cwhttpd_captdns_t *cwhttpd_captdns_start(
    const char *addr /** [in] address:port to bind */
);

/**
 * \brief Shutdown the captdns service
 *
 * \par Description
 * \verbatim embed:rst:leading-asterisk
 *
 * This will be called automatically if **CONFIG_CWHTTPD_USE_SHUTDOWN** is
 * enabled and a shutdown event occurs.
 *
 * \endverbatim */
void cwhttpd_captdns_shutdown(
    cwhttpd_captdns_t *captdns /** [in] captdns instance */
);


#ifdef __cplusplus
} /* extern "C" */
#endif
