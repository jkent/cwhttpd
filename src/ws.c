/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "base64.h"
#include "log.h"
#include "sha1.h"
#include "libesphttpd/route.h"
#include "libesphttpd/httpd.h"
#include "libesphttpd/ws.h"

#include <endian.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#if defined(UNIX)
# include <bsd/string.h>
#endif


#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/* from IEEE RFC6455 sec 5.2
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-------+-+-------------+-------------------------------+
     |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
     |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
     |N|V|V|V|       |S|             |   (if payload len==126/127)   |
     | |1|2|3|       |K|             |                               |
     +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
     |     Extended payload length continued, if payload len == 127  |
     + - - - - - - - - - - - - - - - +-------------------------------+
     |                               |Masking-key, if MASK set to 1  |
     +-------------------------------+-------------------------------+
     | Masking-key (continued)       |          Payload Data         |
     +-------------------------------- - - - - - - - - - - - - - - - +
     :                     Payload Data continued ...                :
     + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
     |                     Payload Data continued ...                |
     +---------------------------------------------------------------+
*/


enum {
    /* non-control frames */
    OPCODE_CONTINUE = 0,
    OPCODE_TEXT,
    OPCODE_BINARY,
    /* control frames */
    OPCODE_CLOSE    = 8,
    OPCODE_PING,
    OPCODE_PONG,
};

#define FLAGS_MASK ((uint8_t)0xF0)
#define OPCODE_MASK ((uint8_t)0x0F)
#define FLAG_FIN ((uint8_t)1<<7)
#define IS_MASKED ((uint8_t)(1<<7))
#define PAYLOAD_MASK ((uint8_t)0x7F)


static ehttpd_ws_t *ws_head = NULL;


static int send_frame_head(ehttpd_ws_t *ws, uint8_t opcode, size_t len)
{
    uint8_t buf[14];
    int i = 0;
    buf[i++] = opcode;
    if (len > 65535) {
        buf[i++] = 127;
        buf[i++] = 0;
        buf[i++] = 0;
        buf[i++] = 0;
        buf[i++] = 0;
        buf[i++] = len >> 24;
        buf[i++] = len >> 16;
        buf[i++] = len >> 8;
        buf[i++] = len;
    } else if (len > 125) {
        buf[i++] = 126;
        buf[i++] = len >> 8;
        buf[i++] = len;
    } else {
        buf[i++] = len;
    }
    EHTTPD_LOGV(__func__, "payload of %d bytes", len);
    return ehttpd_plat_send(ws->conn, buf, i);
}

static void unmask(const uint8_t *mask, uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i += 4) {
        buf[i] ^= mask[0];
        if (i < len - 3) {
            buf[i] ^= mask[1];
            buf[i] ^= mask[2];
            buf[i] ^= mask[3];
        } else if (i < len - 2) {
            buf[i] ^= mask[1];
            buf[i] ^= mask[2];
        } else if (i < len - 1) {
            buf[i] ^= mask[1];
        }
    }
}

ssize_t ehttpd_ws_recv(ehttpd_ws_t *ws, void *buf, size_t len)
{
    size_t outlen = 0;

    while (outlen < len) {
        if (ws->priv.frame.len) {
            size_t recvlen = (ws->priv.frame.len < len) ?
                    ws->priv.frame.len : len;
            ssize_t ret = ehttpd_recv(ws->conn, buf, recvlen);
            if (ret < 0) {
                return -1;
            }
            if (ws->priv.frame.len8 & IS_MASKED) {
                unmask(ws->priv.frame.mask, buf, ret);
            }
            buf += ret;
            ws->priv.frame.len -= ret;
            outlen += ret;

            if (ws->priv.frame.len == 0) {
                ws->flags |= EHTTPD_WS_FLAG_DONE;
                return outlen;
            } else if (!(ws->priv.frame.flags & FLAG_FIN)) {
                ws->flags |= EHTTPD_WS_FLAG_MORE;
            }
        } else {
            ws->flags = EHTTPD_WS_FLAG_NONE;
            ssize_t ret = ehttpd_recv(ws->conn, &ws->priv.frame, 2);
            if (ret != 2) {
                return -1;
            }
            ws->priv.frame.len = (ws->priv.frame.len8 & PAYLOAD_MASK);
            if (ws->priv.frame.len == 126) {
                uint16_t len16;
                ret = ehttpd_recv(ws->conn, &len16, 2);
                if (ret != 2) {
                    return -1;
                }
                ws->priv.frame.len = ntohs(len16);
            } else if (ws->priv.frame.len == 127) {
                ret = ehttpd_recv(ws->conn, &ws->priv.frame.len, 8);
                if (ret != 8) {
                    return -1;
                }
                ws->priv.frame.len = be64toh(ws->priv.frame.len);
            }
            if (ws->priv.frame.len8 & IS_MASKED) {
                ret = ehttpd_recv(ws->conn, ws->priv.frame.mask, 4);
                if (ret != 4) {
                    return -1;
                }
            }
            switch (ws->priv.frame.flags & OPCODE_MASK) {
                case OPCODE_CONTINUE:
                    ws->flags |= EHTTPD_WS_FLAG_CONT;
                    break;

                case OPCODE_BINARY:
                    ws->flags |= EHTTPD_WS_FLAG_BIN;
                    /* fallthrough */

                case OPCODE_TEXT:
                    break;

                case OPCODE_CLOSE: {
                    uint16_t reason = htons(1000);
                    if (ws->priv.frame.len >= 2) {
                        ret = ehttpd_recv(ws->conn, &reason, 2);
                        if (ret != 2) {
                            return -1;
                        }
                    }
                    ehttpd_ws_close(ws, reason);
                    return 0;
                }

                case OPCODE_PING: {
                    char buf[125];
                    if (ws->priv.frame.len > sizeof(buf)) {
                        return -1;
                    }
                    ret = ehttpd_recv(ws->conn, buf, ws->priv.frame.len);
                    if (ret != ws->priv.frame.len) {
                        return -1;
                    }
                    send_frame_head(ws, OPCODE_PONG | FLAG_FIN,
                            ws->priv.frame.len);
                    ehttpd_plat_send(ws->conn, buf, ret);
                    break;
                }

                case OPCODE_PONG:
                    /* do nothing */
                    break;

                default:
                    EHTTPD_LOGE(__func__, "unhandled opcode");
                    /* error */
                    return -1;

            }
        }
    }

    return outlen;
}

ssize_t ehttpd_ws_send(ehttpd_ws_t *ws, const void *buf, size_t len,
        ehttpd_ws_flags_t flags)
{
    int fl = 0;

    // Continuation frame has opcode 0
    if ((flags & EHTTPD_WS_FLAG_CONT) == 0) {
        if (flags & EHTTPD_WS_FLAG_BIN) {
            fl = OPCODE_BINARY;
        } else {
            fl = OPCODE_TEXT;
        }
    }
    // add FIN to last frame
    if ((flags & EHTTPD_WS_FLAG_MORE) == 0) {
        fl |= FLAG_FIN;
    }

    send_frame_head(ws, fl, len);
    return ehttpd_plat_send(ws->conn, buf, len);
}

void ehttpd_ws_close(ehttpd_ws_t *ws, int reason)
{
    uint8_t rs[2] = {reason >> 8, reason & 0xff};
    send_frame_head(ws, FLAG_FIN | OPCODE_CLOSE, 2);
    ehttpd_plat_send(ws->conn, rs, 2);
}

// Broadcast data to all WebSockets at a specific url. Returns the number of
// connections sent to.
int ehttpd_ws_broadcast(ehttpd_inst_t *inst, const char *resource,
        const void *buf, int len, int flags)
{
    ehttpd_ws_t *lw = ws_head;
    int ret = 0;

    while (lw != NULL) {
        if (lw->conn && (lw->conn->inst == inst) &&
                (strcmp(lw->conn->request.url, resource) == 0)) {
            if (ehttpd_ws_send(lw, buf, len, flags) >= 0) {
                ret++;
            }
        }
        lw = lw->priv.next;
    }

    return ret;
}

// WebSocket route handler
ehttpd_status_t ehttpd_route_ws(ehttpd_conn_t *conn)
{
    char buf[1024];
    ehttpd_ws_t ws = { };
    sha1nfo s;

    const char *header = ehttpd_get_header(conn, "Upgrade");
    if (header == NULL || strstr(header, "websocket") == NULL) {
        ehttpd_response(conn, 500);
        return EHTTPD_STATUS_CLOSE;
    }

    header = ehttpd_get_header(conn, "Sec-WebSocket-Key");
    if (header == NULL) {
        ehttpd_response(conn, 500);
        return EHTTPD_STATUS_CLOSE;
    }

    ws.conn = conn;

    // Reply with the right headers.
    strlcpy(buf, header, sizeof(buf));
    strlcat(buf, WS_GUID, sizeof(buf));
    sha1_init(&s);
    sha1_write(&s, buf, strlen(buf));
    ehttpd_set_chunked(conn, false);
    ehttpd_response(conn, 101);
    ehttpd_send_header(conn, "Upgrade", "websocket");
    ehttpd_send_header(conn, "Connection", "upgrade");
    base64_encode(20, sha1_result(&s), sizeof(buf), buf);
    ehttpd_send_header(conn, "Sec-WebSocket-Accept", buf);
    ehttpd_send(conn, NULL, 0); /* send end of header */

    // Insert ws into linked list
    if (ws_head == NULL) {
        ws_head = &ws;
    } else {
        ehttpd_ws_t *lw = ws_head;
        while (lw->priv.next) {
            lw = lw->priv.next;
        }
        lw->priv.next = &ws;
    }

    // Call the handler
    ehttpd_ws_handler_t ws_handler = conn->route->argv[0];
    ws_handler(&ws);

    // Clean up linked list
    if (ws_head == &ws) {
        ws_head = ws.priv.next;
    } else if (ws_head) {
        ehttpd_ws_t *lws = ws_head;
        // Find ws that links to this one.
        while (lws != NULL && lws->priv.next != &ws) {
            lws = lws->priv.next;
        }
        if (lws != NULL) {
            lws->priv.next = ws.priv.next;
        }
    }

    return EHTTPD_STATUS_CLOSE;
}
