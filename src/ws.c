/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
Websocket support for esphttpd. Inspired by https://github.com/dangrie158/ESP-8266-WebSocket
*/

#include "base64.h"
#include "log.h"
#include "sha1.h"
#include "libesphttpd/route.h"
#include "libesphttpd/httpd.h"
#include "libesphttpd/ws.h"

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

#define FLAG_FIN (1 << 7)

#define OPCODE_CONTINUE 0x0
#define OPCODE_TEXT 0x1
#define OPCODE_BINARY 0x2
#define OPCODE_CLOSE 0x8
#define OPCODE_PING 0x9
#define OPCODE_PONG 0xA

#define FLAGS_MASK ((uint8_t)0xF0)
#define OPCODE_MASK ((uint8_t)0x0F)
#define IS_MASKED ((uint8_t)(1<<7))
#define PAYLOAD_MASK ((uint8_t)0x7F)

typedef struct WebsockFrame WebsockFrame;

#define ST_FLAGS 0
#define ST_LEN0 1
#define ST_LEN1 2
#define ST_LEN2 3
//...
#define ST_LEN8 9
#define ST_MASK1 10
#define ST_MASK4 13
#define ST_PAYLOAD 14


static ehttpd_ws_t *ws_head = NULL;


static int send_frame_head(ehttpd_ws_t *ws, int opcode, int len)
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
    //EHTTPD_LOGD(__func__, "payload of %d bytes", len);
    return ehttpd_enqueue(ws->conn, buf, i);
}

int ehttpd_ws_send(ehttpd_ws_t *ws, const void *buf, int len, ehttpd_ws_flags_t flags)
{
    int r = 0;
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

    if (ws->conn->closed) {
        EHTTPD_LOGE(__func__, "Websocket closed, cannot send");
        return -1;
    }

    ehttpd_lock(ws->conn->inst);
    send_frame_head(ws, fl, len);
    if (len != 0) {
        r = ehttpd_enqueue(ws->conn, buf, len);
    }
    ehttpd_flush(ws->conn);
    ehttpd_unlock(ws->conn->inst);
    return r;
}

//Broadcast data to all websockets at a specific url. Returns the amount of connections sent to.
int ehttpd_ws_broadcast(ehttpd_inst_t *inst, const char *resource, const void *buf, int len, int flags)
{
    ehttpd_ws_t *lw = ws_head;
    int ret = 0;
    while (lw != NULL) {
        if (lw->conn->inst == inst && strcmp(lw->conn->url, resource) == 0) {
            ehttpd_ws_send(lw, buf, len, flags);
            ret++;
        }
        lw = lw->priv.next;
    }
    return ret;
}

void ehttpd_ws_close(ehttpd_ws_t *ws, int reason)
{
    uint8_t rs[2] = {reason >> 8, reason & 0xff};
    ehttpd_lock(ws->conn->inst);
    send_frame_head(ws, FLAG_FIN | OPCODE_CLOSE, 2);
    ehttpd_enqueue(ws->conn, rs, 2);
    ws->priv.closed = 1;
    ehttpd_flush(ws->conn);
    ehttpd_unlock(ws->conn->inst);
}

static void ws_free(ehttpd_ws_t *ws) {
    if (ws->close_cb) {
        ws->close_cb(ws);
    }
    //Clean up linked list
    if (ws_head == ws) {
        ws_head = ws->priv.next;
    } else if (ws_head) {
        ehttpd_ws_t *lws = ws_head;
        //Find ws that links to this one.
        while (lws != NULL && lws->priv.next != ws) {
            lws = lws->priv.next;
        }
        if (lws != NULL) {
            lws->priv.next = ws->priv.next;
        }
    }
    free(ws);
}

ehttpd_status_t ehttpd_ws_recv(ehttpd_conn_t *conn, void *buf, int len)
{
    int i, j, sl;
    int r = EHTTPD_STATUS_MORE;
    int wasHeaderByte;
    uint8_t *p = buf;

    ehttpd_ws_t *ws = (ehttpd_ws_t *) conn->user;
    for (i = 0; i < len; i++) {
//        httpd_printf("Ws: State %d byte 0x%02X\n", ws->priv.status, p[i]);
        wasHeaderByte = 1;
        if (ws->priv.status == ST_FLAGS) {
            ws->priv.mask_ctr = 0;
            ws->priv.frame_cont = 0;
            ws->priv.fr.flags = p[i];
            ws->priv.status = ST_LEN0;
        } else if (ws->priv.status == ST_LEN0) {
            ws->priv.fr.len8 = p[i];
            if ((ws->priv.fr.len8 & 127) >= 126) {
                ws->priv.fr.len = 0;
                ws->priv.status = ST_LEN1;
            } else {
                ws->priv.fr.len = ws->priv.fr.len8 & 127;
                ws->priv.status = (ws->priv.fr.len8 & IS_MASKED) ? ST_MASK1 : ST_PAYLOAD;
            }
        } else if (ws->priv.status <= ST_LEN8) {
            ws->priv.fr.len = (ws->priv.fr.len << 8) | p[i];
            if (((ws->priv.fr.len8 & 127) == 126 && ws->priv.status == ST_LEN2) || ws->priv.status == ST_LEN8) {
                ws->priv.status = (ws->priv.fr.len8 & IS_MASKED) ? ST_MASK1 : ST_PAYLOAD;
            } else {
                ws->priv.status++;
            }
        } else if (ws->priv.status <= ST_MASK4) {
            ws->priv.fr.mask[ws->priv.status - ST_MASK1] = p[i];
            ws->priv.status++;
        } else {
            //Was a payload byte.
            wasHeaderByte = 0;
        }

        if (ws->priv.status == ST_PAYLOAD && wasHeaderByte) {
            //We finished parsing the header, but i still is on the last header byte. Move one forward so
            //the payload code works as usual.
            i++;
        }
        //Also finish parsing frame if we haven't received any payload bytes yet, but the length of the frame
        //is zero.
        if (ws->priv.status == ST_PAYLOAD) {
            //Okay, header is in; this is a data byte. We're going to process all the data bytes we have
            //received here at the same time; no more byte iterations till the end of this frame.
            //First, unmask the data
            sl = len - i;
            //EHTTPD_LOGD(__func__, "Frame payload. wasHeaderByte %d fr.len %d sl %d cmd 0x%x", wasHeaderByte, (int)ws->priv.fr.len, (int)sl, ws->priv.fr.flags);
            if (sl > ws->priv.fr.len) {
                sl = ws->priv.fr.len;
            }
            for (j = 0; j < sl; j++) {
                p[i + j] ^= (ws->priv.fr.mask[(ws->priv.mask_ctr++) & 3]);
            }

//            httpd_printf("Unmasked: ");
//            for (j=0; j<sl; j++) httpd_printf("%02X ", p[i+j]&0xff);
//            httpd_printf("\n");

            //Inspect the header to see what we need to do.
            if ((ws->priv.fr.flags & OPCODE_MASK) == OPCODE_PING) {
                if (ws->priv.fr.len > 125) {
                    if (ws->priv.frame_cont == 0) {
                        ehttpd_ws_close(ws, 1002);
                    }
                    r = EHTTPD_STATUS_DONE;
                    break;
                } else {
                    if (ws->priv.frame_cont == 0) {
                        send_frame_head(ws, OPCODE_PONG | FLAG_FIN, ws->priv.fr.len);
                    }
                    if (sl>0) {
                        ehttpd_enqueue(ws->conn, p + i, sl);
                    }
                }
            } else if ((ws->priv.fr.flags & OPCODE_MASK) == OPCODE_TEXT ||
                        (ws->priv.fr.flags & OPCODE_MASK) == OPCODE_BINARY ||
                        (ws->priv.fr.flags & OPCODE_MASK) == OPCODE_CONTINUE) {
                if (sl > ws->priv.fr.len) {
                    sl = ws->priv.fr.len;
                }
                if ((ws->priv.fr.len8 & IS_MASKED) == 0) {
                    //We're a server; client should send us masked packets.
                    ehttpd_ws_close(ws, 1002);
                    r = EHTTPD_STATUS_DONE;
                    break;
                } else {
                    ehttpd_ws_flags_t flags = EHTTPD_WS_FLAG_NONE;
                    if ((ws->priv.fr.flags & OPCODE_MASK) == OPCODE_BINARY) {
                        flags |= EHTTPD_WS_FLAG_BIN;
                    }
                    if ((ws->priv.fr.flags & FLAG_FIN) == 0) {
                        flags |= EHTTPD_WS_FLAG_MORE;
                    }
                    if (ws->recv_cb) {
                        ws->recv_cb(ws, p + i, sl, flags);
                    }
                }
            } else if ((ws->priv.fr.flags & OPCODE_MASK) == OPCODE_CLOSE) {
                EHTTPD_LOGD(__func__, "Got close frame");
                if (!ws->priv.closed) {
                    EHTTPD_LOGD(__func__, "Sending response close frame");
                    ehttpd_ws_close(ws, ((p[i] << 8) & 0xff00) + (p[i + 1] & 0xff));
                }
                r = EHTTPD_STATUS_DONE;
                break;
            } else {
                if (ws->priv.frame_cont == 0) {
                    EHTTPD_LOGE(__func__, "Unknown opcode 0x%X", ws->priv.fr.flags & OPCODE_MASK);
                }
            }
            i += sl - 1;
            ws->priv.fr.len -= sl;
            if (ws->priv.fr.len == 0) {
                ws->priv.status = ST_FLAGS; //go receive next frame
            } else {
                ws->priv.frame_cont = 1; //next payload is continuation of this frame.
            }
        }
    }
    if (r == EHTTPD_STATUS_DONE) {
        ws_free(ws);
    }
    return r;
}

// Websocket route implementation
ehttpd_status_t ehttpd_route_websocket(ehttpd_conn_t *conn) {
    char buf[256];
    sha1nfo s;
    if (conn->closed) {
        //Connection aborted. Clean up.
        EHTTPD_LOGD(__func__, "cleanup");
        if (conn->user) {
            ehttpd_ws_t *ws=(ehttpd_ws_t *) conn->user;
            ws_free(ws);
        }
        return EHTTPD_STATUS_DONE;
    }

    if (conn->user == NULL) {
        const char *header = ehttpd_get_header(conn, "Upgrade");
        if (header == NULL || strstr(header, "websocket") == NULL) {
            ehttpd_start_response(conn, 500);
            return EHTTPD_STATUS_DONE;
        }

        header = ehttpd_get_header(conn, "Sec-WebSocket-Key");
        if (header == NULL) {
            ehttpd_start_response(conn, 500);
            return EHTTPD_STATUS_DONE;
        }

        // Seems like a WebSocket connection.
        EHTTPD_LOGD(__func__, "upgrade %p", conn);
        ehttpd_ws_t *ws = (ehttpd_ws_t *) malloc(sizeof(ehttpd_ws_t));
        if (ws == NULL) {
            EHTTPD_LOGE(__func__, "Can't allocate mem for websocket");
            return EHTTPD_STATUS_DONE;
        }
        memset(ws, 0, sizeof(*ws));
        conn->user = ws;
        ws->conn = conn;
        //Reply with the right headers.
        strlcpy(buf, header, sizeof(buf));
        strlcat(buf, WS_GUID, sizeof(buf));
        sha1_init(&s);
        sha1_write(&s, buf, strlen(buf));
        ehttpd_set_chunked_encoding(conn, false);
        ehttpd_start_response(conn, 101);
        ehttpd_header(conn, "Upgrade", "websocket");
        ehttpd_header(conn, "Connection", "upgrade");
        base64_encode(20, sha1_result(&s), sizeof(buf), buf);
        ehttpd_header(conn, "Sec-WebSocket-Accept", buf);
        ehttpd_end_headers(conn);
        //Set data receive handler
        conn->recv_handler = ehttpd_ws_recv;
        //Inform route handler we have a connection
        ehttpd_ws_connected_cb_t connCb = conn->route->argv[0];
        connCb(ws);
        //Insert ws into linked list
        if (ws_head == NULL) {
            ws_head = ws;
        } else {
            ehttpd_ws_t *lw = ws_head;
            while (lw->priv.next) {
                lw = lw->priv.next;
            }
            lw->priv.next = ws;
        }
        return EHTTPD_STATUS_MORE;
    }

    //Sending is done. Call the sent callback if we have one.
    ehttpd_ws_t *ws = (ehttpd_ws_t *) conn->user;
    if (ws && ws->sent_cb) {
        ws->sent_cb(ws);
    }

    return EHTTPD_STATUS_MORE;
}
