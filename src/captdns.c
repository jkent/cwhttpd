/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/** This is a 'captive portal' DNS server: it basically replies with a fixed IP
 * (in this case: the one of the SoftAP interface of this ESP module) for any
 * and all A record DNS queries. This can be used to send mobile phones,
 * tablets etc which connect to the ESP in AP mode directly to the internal
 * webserver.
 */

#include "log.h"
#include "cwhttpd/captdns.h"
#include "cwhttpd/httpd.h"
#include "cwhttpd/port.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#if defined(CONFIG_IDF_TARGET_ESP8266)
# include <tcpip_adapter.h>
#elif defined (ESP_PLATFORM)
# include <esp_netif.h>
#endif


#define DNS_LEN 512

struct cwhttpd_captdns_t {
    cwhttpd_thread_t *thread;
    cwhttpd_semaphore_t *shutdown;
    cwhttpd_inst_t* inst;
    struct sockaddr_in addr;
    int fd;
    uint8_t buf[DNS_LEN];
};

typedef struct dns_header_t dns_header_t;
typedef struct dns_label_t dns_label_t;
typedef struct dns_question_footer_t dns_question_footer_t;
typedef struct dns_resource_footer_t dns_resource_footer_t;
typedef struct dns_uri_header_t dns_uri_header_t;

struct dns_header_t {
    uint16_t id;
    uint8_t flags;
    uint8_t rcode;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__ ((packed));

struct dns_label_t {
    uint8_t len;
    uint8_t data;
} __attribute__ ((packed));

struct dns_question_footer_t {
    //before: name
    uint16_t type;
    uint16_t class;
} __attribute__ ((packed));

struct dns_resource_footer_t {
    //before: name
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    //after: rdata
} __attribute__ ((packed));

struct dns_uri_header_t {
    uint16_t prio;
    uint16_t weight;
} __attribute__ ((packed));

#define FLAG_QR (1<<7)
#define FLAG_AA (1<<2)
#define FLAG_TC (1<<1)
#define FLAG_RD (1<<0)

#define QTYPE_A  1
#define QTYPE_NS 2
#define QTYPE_CNAME 5
#define QTYPE_SOA 6
#define QTYPE_WKS 11
#define QTYPE_PTR 12
#define QTYPE_HINFO 13
#define QTYPE_MINFO 14
#define QTYPE_MX 15
#define QTYPE_TXT 16
#define QTYPE_URI 256

#define QCLASS_IN 1
#define QCLASS_ANY 255
#define QCLASS_URI 256


void cwhttpd_captdns_hook(cwhttpd_inst_t *inst, cwhttpd_captdns_t *captdns,
        int fd);

/** This function writes a 16-bit value to an unaligned pointer *p in network
 *  endian and advances the pointer.
 */
static void write_u16(uint8_t **p, uint16_t n)
{
    *(*p)++ = (n >> 8) & 0xFF;
    *(*p)++ = n & 0xFF;
}

/** This function writes a 32-bit value to an unaligned pointer *p in network
 *  endian and advances the pointer.
 */
static void write_u32(uint8_t **p, uint32_t n)
{
    *(*p)++ = (n >> 24) & 0xFF;
    *(*p)++ = (n >> 16) & 0xFF;
    *(*p)++ = (n >> 8) & 0xFF;
    *(*p)++ = n & 0xFF;
}

/** This function reads a DNS name into string s of max length len. p is
 *  advanced and length is updated with the actual length read. pkt and
 *  pkt_len are used for bounds checking and pointer access to dns names.
 */
static void read_name(uint8_t **p, char *s, size_t *len, uint8_t *pkt,
        size_t pkt_len)
{
    uint8_t *label = *p;
    uint8_t *end = NULL;
    char *start = s;
    size_t n;

    do {
        if ((*label & 0xC0) == 0) {
            n = *label++;
            if (start != s) {
                *s++ = '.';
            }
            if (label + n > pkt + pkt_len || (len && n > *len)) {
                break;
            }
            if (s) {
                memcpy(s, label, n);
                s += n;
            }
            label += n;
        } else if ((*label & 0xC0) == 0xC0) {
            end = label + 2;
            n = ntohs(*((uint16_t *) label)) & 0x3FFF;
            if (n > pkt_len) {
                break;
            }
            label = &pkt[n];
        } else {
            break;
        }
    } while(*label);
    if (s) {
        *s = '\0';
    }
    *p = end ? end : label + 1;
    if (s && len) {
        *len = s - start;
    }
}

/** This function writes the dns string as a name to the buffer *p with max
 *  length len. p is advanced, and len is updated with the actual written
 *  size.
 */
static void write_name(uint8_t **p, char *s, size_t *len)
{
    void *start = *p;
    uint8_t *bytes = (*p)++;

    while (true) {
        if ((void *)  *p - start >= *len) {
            break;
        }
        if (*s == '.' || *s == 0 || *p - bytes > 63) {
            *bytes = *p - bytes - 1;
            bytes = (*p)++;
            if (*s == 0) {
                break;
            }
            s++;
        } else {
            *(char *) (*p)++ = *s++;
        }
    }
    *bytes = 0;
    *len = (void *) *p - start;
}

void cwhttpd_captdns_thread(void *arg)
{
    cwhttpd_captdns_t *captdns = arg;

    while (!captdns->shutdown) {
        fd_set read_set;
        struct timeval timeout = {
            .tv_usec = 250000,
        };
        FD_ZERO(&read_set);
        FD_SET(captdns->fd, &read_set);
        if (select(captdns->fd + 1, &read_set, NULL, NULL,
                &timeout) <= 0) {
            continue;
        }

        struct sockaddr_in from;
        int len = sizeof(from);
        int msglen = recvfrom(captdns->fd, captdns->buf, sizeof(captdns->buf), 0,
                (struct sockaddr *) &from, (socklen_t *) &len);

        if (msglen <= 0) {
            return;
        }

        uint8_t *pi = captdns->buf;
        uint8_t *po = &captdns->buf[msglen];
        dns_header_t *hdr = (dns_header_t *) pi;
        pi += sizeof(dns_header_t);

        if (msglen > DNS_LEN || msglen < sizeof(dns_header_t)) {
            LOGD(__func__, "invalid packet length");
            return;
        }

        if (hdr->ancount || hdr->nscount) {
            LOGD(__func__, "ignoring reply");
            return;
        }

        if (hdr->flags & FLAG_TC) {
            LOGD(__func__, "message truncated");
            return;
        }

        hdr->flags |= FLAG_QR; /* mark header as a response */

        for (int i = 0; i < ntohs(hdr->qdcount); i++) {
            size_t name_ptr = pi - captdns->buf;
            read_name(&pi, NULL, NULL, captdns->buf, msglen);
            dns_question_footer_t *qf = (dns_question_footer_t *) pi;
            pi += sizeof(dns_question_footer_t);

            if (ntohs(qf->type) == QTYPE_A) {
                write_u16(&po, 0xC000 | name_ptr);
                write_u16(&po, QTYPE_A); /* type */
                write_u16(&po, QCLASS_IN); /* class */
                write_u32(&po, 0); /* ttl */
                write_u16(&po, 4); /* rdlength, IPv4 is 4 bytes */
                uint32_t ip = captdns->addr.sin_addr.s_addr;
                if (ip == 0) {
    #if defined(CONFIG_IDF_TARGET_ESP8266)
                    /* Detect which tcpip_if this came in on, and return its ip */
                    tcpip_adapter_ip_info_t ip_info;
                    ip = from.sin_addr.s_addr;
                    for (tcpip_adapter_if_t tcpip_if = 0; tcpip_if < TCPIP_ADAPTER_IF_MAX; tcpip_if++) {
                        tcpip_adapter_get_ip_info(tcpip_if, &ip_info);
                        if ((ip & ip_info.netmask.addr) == (ip_info.ip.addr & ip_info.netmask.addr)) {
                            ip = ip_info.ip.addr;
                            break;
                        }
                    }
    #elif defined(ESP_PLATFORM)
                    /* Detect which netif this came in on, and return its ip */
                    esp_netif_ip_info_t ip_info;
                    esp_netif_t *netif = NULL;
                    ip = from.sin_addr.s_addr;
                    while ((netif = esp_netif_next(netif)) != NULL) {
                        esp_netif_get_ip_info(netif, &ip_info);
                        if ((ip & ip_info.netmask.addr) == (ip_info.ip.addr & ip_info.netmask.addr)) {
                            ip = ip_info.ip.addr;
                            break;
                        }
                    }
    #else
                    /* Apply netmask of 255.255.255.0 and set last octet to 1 */
                    ip = from.sin_addr.s_addr & 0x00FFFFFF | 0x01000000;
    #endif
                }
                memcpy(po, &ip, 4);
                po += 4;
                hdr->ancount = htons(ntohs(hdr->ancount) + 1);

            } else if (ntohs(qf->type) == QTYPE_NS) {
                write_u16(&po, 0xC000 | name_ptr);
                write_u16(&po, QTYPE_NS); /* type */
                write_u16(&po, QCLASS_IN); /* class */
                write_u32(&po, 0); /* ttl */
                size_t len = 4;
                write_u16(&po, len); /* rdlength */
                write_name(&po, "ns", &len);
                hdr->ancount = htons(ntohs(hdr->ancount) + 1);

            } else if (ntohs(qf->type) == QTYPE_URI) {
                write_u16(&po, 0xC000 | name_ptr);
                write_u16(&po, QTYPE_URI); /* type */
                write_u16(&po, QCLASS_URI); /* class */
                write_u32(&po, 0); /* ttl */
                size_t len = 16;
                write_u16(&po, 4 + len); /* rdlength */
                write_u16(&po, 10); /* prio */
                write_u16(&po, 1); /* weight */
                memcpy(po, "http://esp.nonet", len);
                po += len;
                hdr->ancount = htons(ntohs(hdr->ancount) + 1);
            }
        }

        /* Send the response */
        sendto(captdns->fd, captdns->buf, po - captdns->buf, 0,
                (struct sockaddr *) &from, sizeof(struct sockaddr_in));
    }

    cwhttpd_semaphore_give(captdns->shutdown);
    cwhttpd_thread_delete(captdns->thread);
}

cwhttpd_captdns_t *cwhttpd_captdns_start(const char *addr)
{
    cwhttpd_captdns_t *captdns = calloc(1, sizeof(cwhttpd_captdns_t));
    if (captdns == NULL) {
        LOGE(__func__, "calloc");
        return NULL;
    }

    if ((captdns->fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        LOGE(__func__, "failed to create sock");
        goto err;
    }

    captdns->addr.sin_family = AF_INET;
    captdns->addr.sin_port = htons(53);
    if (addr == NULL) {
        addr = "0.0.0.0:53";
    }

    char *s = strdup(addr);
    char *p = strrchr(s, ':');
    if (p) {
        *p = '\0';
        captdns->addr.sin_port = htons(strtol(p + 1, NULL, 10));
    }
    inet_pton(AF_INET, s, &captdns->addr.sin_addr);
    free(s);

    if (bind(captdns->fd, (struct sockaddr *) &captdns->addr,
            sizeof(captdns->addr)) < 0) {
        LOGE(__func__, "unable to bind to UDP %s", addr);
        goto err;
        return NULL;
    }
    LOGI(__func__, "bound to UDP %s", addr);

    captdns->thread = cwhttpd_thread_create(cwhttpd_captdns_thread, captdns,
            NULL);
    if (captdns->thread == NULL) {
        LOGE(__func__, "thread");
        goto err;
    }

    return captdns;

err:
    if (captdns->fd >= 0) {
        close(captdns->fd);
    }
    free(captdns);
    return NULL;
}

void cwhttpd_captdns_shutdown(cwhttpd_captdns_t *captdns)
{
    captdns->shutdown = cwhttpd_semaphore_create(1, 0);
    cwhttpd_semaphore_take(captdns->shutdown, UINT32_MAX);
    cwhttpd_semaphore_delete(captdns->shutdown);
    free(captdns);
}
