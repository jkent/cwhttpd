/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "log.h"
#include "libesphttpd/route.h"
#include "libesphttpd/httpd.h"

#if defined(CONFIG_IDF_TARGET_ESP8266) || defined(ESP_PLATFORM)
# include <esp_netif.h>
#endif

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


ehttpd_status_t ehttpd_route_redirect(ehttpd_conn_t *conn)
{
    if (conn->closed) {
        return EHTTPD_STATUS_DONE;
    }

    ehttpd_redirect(conn, (char *) conn->route->arg);
    return EHTTPD_STATUS_DONE;
}

ehttpd_status_t ehttpd_route_redirect_hostname(ehttpd_conn_t *conn)
{
    const char *new_hostname = (char *) conn->route->arg;
    char *buf;

    if (conn->closed) {
        return EHTTPD_STATUS_DONE;
    }

    if (conn->hostname == NULL) {
        return EHTTPD_STATUS_NOTFOUND;
    }

    /* Test hostname, pass on if it is the same... Not ignoring the case
     * because looks are everything!
     */
    if (strcmp(conn->hostname, new_hostname) == 0) {
        return EHTTPD_STATUS_NOTFOUND;
    }

#if 0
#if defined(CONFIG_IDF_TARGET_ESP8266) || defined(ESP_PLATFORM)
    /* If we're not on the AP network, don't redirect the hostname
     */
    uint32_t remote;
    memcpy(&remote, frconn_of_conn(conn)->ip, 4);

    tcpip_adapter_ip_info_t ap_info;
    tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_AP, &ap_info);

    uint32_t netmask = ap_info.netmask.addr;
    if ((remote & netmask) != (ap_info.ip.addr & netmask)) {
        return EHTTPD_STATUS_NOTFOUND;
    }
#endif
#endif

    const char *uri_fmt;
    if (ehttpd_is_ssl(conn)) {
        uri_fmt = "https://%s";
    } else {
        uri_fmt = "http://%s";
    }

    /* Tests failed.  Redirect to real hostname.
     */
    buf = malloc(strlen(new_hostname) + strlen(uri_fmt) - 1);
    if (buf == NULL) {
        EHTTPD_LOGE(__func__, "malloc failed");
        return EHTTPD_STATUS_DONE;
    }

    sprintf(buf, uri_fmt, new_hostname);
    EHTTPD_LOGD(__func__, "redirecting to hostname url %s", buf);
    ehttpd_redirect(conn, buf);
    free(buf);
    return EHTTPD_STATUS_DONE;
}
