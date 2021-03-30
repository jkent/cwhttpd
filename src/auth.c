/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "base64.h"
#include "libesphttpd/route.h"
#include "libesphttpd/httpd.h"

#include <string.h>


#ifndef HTTP_AUTH_REALM
#define HTTP_AUTH_REALM "Protected"
#endif

#define MAX_USER 32
#define MAX_PASS 32

ehttpd_status_t ehttpd_route_auth_basic(ehttpd_conn_t *conn)
{
    char userpass[MAX_USER + MAX_PASS + 2];
    char user[MAX_USER];
    char pass[MAX_PASS];

    const char *header = ehttpd_get_header(conn, "Authorization");
    if (header && strncmp(header, "Basic", 5) == 0) {
        int len = base64_decode(strlen(header) - 6, header + 6,
                sizeof(userpass), (unsigned char *) userpass);
        if (len < 0) {
            len = 0;
        }
        userpass[len] = '\0';

        ehttpd_auth_account_cb_t get_account =
                (ehttpd_auth_account_cb_t) conn->route->argv[0];
        int i = 0;
        while (get_account(conn, i, user, MAX_USER, pass, MAX_PASS)) {
            if (strlen(userpass) == strlen(user) + strlen(pass) + 1 &&
                    strncmp(userpass, user, strlen(user)) == 0 &&
                    userpass[strlen(user)] == ':' &&
                    strcmp(userpass + strlen(user) + 1, pass) == 0) {
                return EHTTPD_STATUS_AUTHENTICATED;
            }
            i++;
        }
    }

    ehttpd_response(conn, 401);
    ehttpd_send_header(conn, "Content-Type", "text/plain");
    ehttpd_send_header(conn, "WWW-Authenticate",
            "Basic realm=\""HTTP_AUTH_REALM"\"");
    ehttpd_send(conn, "Unauthorized", -1);

    return EHTTPD_STATUS_DONE;
}
