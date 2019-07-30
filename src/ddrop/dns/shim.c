#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <sys/queue.h>

#include <event2/event.h>

#include "ddrop/common.h"
#include "ddrop/core/log.h"
#include "ddrop/sock/socket.h"
#include "ddrop/dns/json.h"
#include "ddrop/dns/shim.h"

struct ddrop_dns_shim {
    struct event_base * _evbase;
    struct event      * _event;
    evutil_socket_t     _sock;
    ddrop_dns_shim_cb   _callback;
    void              * _arg;
};

#define DNSHM_GETFN(NAME, TYPE)                                  \
    TYPE ddrop_dns_shim_get ## NAME(struct ddrop_dns_shim * s) { \
        return s->NAME;                                          \
    }

DNSHM_GETFN(_evbase, struct event_base *);
DNSHM_GETFN(_event, struct event *);
DNSHM_GETFN(_sock, evutil_socket_t);

static void
dns__shim_readcb_(int sock, short which, void * arg)
{
    lz_json               * json_packet = NULL;
    ldns_pkt              * dns_packet  = NULL;
    char                  * errstr      = NULL;
    struct ddrop_dns_shim * shim;
    struct sockaddr_storage sk_s;
    socklen_t               sk_len;
    ssize_t                 recv_len;
    char                    packet_buf[LDNS_MAX_PACKETLEN];


    log_debug("events: %s%s",
              which & EV_READ ? "READ " : "",
              which & EV_WRITE ? "WRITE " : "");

    shim   = (struct ddrop_dns_shim *)arg;
    assert(shim != NULL);

    sk_len = sizeof(sk_s);

    if ((recv_len = recvfrom(shim->_sock, packet_buf,
                             LDNS_MAX_PACKETLEN, 0,
                             (struct sockaddr *)&sk_s, &sk_len)) == -1) {
        if (errno != EAGAIN) {
            log_error("recvfrom");
        }

        return;
    }

    if (shim->_callback == NULL) {
        return;
    }

    do {
        if (ldns_wire2pkt(&dns_packet, packet_buf, (size_t)recv_len) != LDNS_STATUS_OK) {
            errstr = "wire2packet";
            break;
        }

        if ((json_packet = ddrop_dns_to_json(dns_packet)) == NULL) {
            errstr = "dns_to_json";
            break;
        }

        if ((shim->_callback)(shim, json_packet, &sk_s, shim->_arg) == -1) {
            errstr = "shimcb";
            break;
        }
    } while (0);

    if (errstr != NULL) {
        log_error("%s", errstr);

        lz_json_free(json_packet);
    }

    return ldns_pkt_free(dns_packet);
} /* dns__shim_readcb_ */

void
ddrop_dns_shim_free(struct ddrop_dns_shim * shim)
{
    if (shim == NULL) {
        return;
    }

    event_del(shim->_event);
    event_free(shim->_event);
    evutil_closesocket(shim->_sock);

    free(shim);
}

int
ddrop_dns_shim_set_callback(struct ddrop_dns_shim * shim, ddrop_dns_shim_cb cb, void * arg)
{
    if (shim == NULL) {
        return -1;
    }

    shim->_callback = cb;
    shim->_arg      = arg;

    return 0;
}

int
ddrop_dns_shim_start(struct ddrop_dns_shim * shim)
{
    log_debug("enter");

    if (shim == NULL) {
        return -1;
    }

    if (shim->_event == NULL) {
        return -1;
    }

    return event_add(shim->_event, NULL);
}

struct ddrop_dns_shim *
ddrop_dns_shim_new(struct event_base         * evbase,
                   struct ddrop_dns_shim_cfg * config)
{
    struct ddrop_dns_shim * shim   = NULL;
    const char            * errstr = NULL;

    if (evbase == NULL || config == NULL) {
        return NULL;
    }

    if ((shim = calloc(1, sizeof(*shim))) == NULL) {
        log_error("alloc");

        return NULL;
    }

    do {
        int ev_flags_ = EV_READ | EV_PERSIST;

        shim->_sock = ddrop_socket_bind(
            config->bind_addr,
            config->bind_port,
            config->sock_type);

        if (shim->_sock == -1) {
            errstr = "ddrop_socket_bind";
            break;
        }

        shim->_event = event_new(evbase,
                                 shim->_sock, ev_flags_,
                                 dns__shim_readcb_, shim);

        if (shim->_event == NULL) {
            errstr = "event_new";
            break;
        }
    } while (0);

    if (errstr != NULL) {
        log_error("%s", errstr);
        ddrop_dns_shim_free(shim);

        return NULL;
    }

    shim->_evbase = evbase;

    return shim;
}     /* ddrop_dns_shim_new */
