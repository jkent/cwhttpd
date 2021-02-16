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

#define EHTTPD_AUTH_SINGLE 0
#define EHTTPD_AUTH_CALLBACK 1

#define AUTH_MAX_USER_LEN 32
#define AUTH_MAX_PASS_LEN 32

ehttpd_status_t ehttpd_route_auth_basic(ehttpd_conn_t *conn)
{
    const char *unauthorized = "401 Unauthorized.";
    const char *auth;
    char userpass[AUTH_MAX_USER_LEN + AUTH_MAX_PASS_LEN + 2];
    char user[AUTH_MAX_USER_LEN];
    char pass[AUTH_MAX_PASS_LEN];

    if (conn->closed) {
        // Connection closed. Clean up.
        return EHTTPD_STATUS_DONE;
    }

    auth = ehttpd_get_header(conn, "Authorization");
    if (auth) {
        if (strncmp(auth, "Basic", 5) == 0) {
            int len = base64_decode(strlen(auth) - 6, auth + 6,
                    sizeof(userpass), (unsigned char *) userpass);
            if (len < 0) {
                len = 0; // just clean out string on decode error
            }
            userpass[len] = '\0'; // zero-terminate user:pass string

            ehttpd_auth_account_cb_t get_account =
                    (ehttpd_auth_account_cb_t) conn->route->arg;
            int i = 0;
            while (get_account(conn, i, user, AUTH_MAX_USER_LEN, pass,
                    AUTH_MAX_PASS_LEN)) {
                // Check user/pass against auth header
                if (strlen(userpass) == strlen(user) + strlen(pass) + 1 &&
                        strncmp(userpass, user, strlen(user)) == 0 &&
                        userpass[strlen(user)] == ':' &&
                        strcmp(userpass + strlen(user) + 1, pass) == 0) {
                    // Authenticated. Yay!
                    return EHTTPD_STATUS_AUTHENTICATED;
                }
                i++; // Not authenticated with this account. Check next
            }
        }
    }

    // Not authenticated. Go bug user with login screen.
    ehttpd_start_response(conn, 401);
    ehttpd_header(conn, "Content-Type", "text/plain");
    ehttpd_header(conn, "WWW-Authenticate", "Basic realm=\""HTTP_AUTH_REALM"\"");
    ehttpd_end_headers(conn);
    ehttpd_enqueue(conn, unauthorized, -1);

    // Okay, all done.
    return EHTTPD_STATUS_DONE;
}
