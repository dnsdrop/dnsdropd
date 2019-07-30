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
#include "ddrop/dns/dnsd.h"

#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)        \
    for ((var) = TAILQ_FIRST((head));                     \
         (var) && ((tvar) = TAILQ_NEXT((var), field), 1); \
         (var) = (tvar))
#endif


struct ddrop_dnsd_request {
    struct ddrop_dnsd_listener * _listener;
    struct sockaddr_storage   _addr;
    evutil_socket_t           _sock;
    ev_socklen_t              _addrlen;
    ldns_pkt                * _pkt_req;
    ldns_pkt                * _pkt_res;
    uint8_t                   _wire_req[LDNS_MAX_PACKETLEN];
    uint8_t                 * _wire_res;
    size_t                    _wire_req_sz;
    size_t                    _wire_res_sz;

    TAILQ_ENTRY(ddrop_dnsd_request) _pending_next;
};

struct ddrop_dnsd_listener {
    struct event_base * _evbase;
    struct event      * _event;
    evutil_socket_t     _sock;

    ddrop_dnsd_requestcb _callback;
    void            * _usrargs;

    TAILQ_HEAD(, ddrop_dnsd_request) _pending;
};


static void listener__callback_(evutil_socket_t sock, short events, void * arg);

ldns_pkt *
ddrop_dnsd_request_get_query(struct ddrop_dnsd_request * r)
{
    ddrop_assert(r != NULL);

    return r->_pkt_req;
}

static void
listener__free_(struct ddrop_dnsd_listener * listener)
{
    if (listener == NULL) {
        return;
    }

    if (listener->_sock != -1) {
        evutil_closesocket(listener->_sock);
    }

    if (listener->_event != NULL) {
        event_free(listener->_event);
    }

    free(listener);
}

static void
request__free_(struct ddrop_dnsd_request * req)
{
    if (req == NULL) {
        return;
    }

    ldns_pkt_free(req->_pkt_req);
    ldns_pkt_free(req->_pkt_res);

    /*free(req->_wire_req); */
    free(req->_wire_res);
    free(req);
}

static int
request__default_callback_(struct ddrop_dnsd_request * req, void * args)
{
    ldns_pkt      * packet;
    ldns_rr_list  * question;
    ldns_pkt_opcode opcode;

    if ((packet = ldns_pkt_new()) == NULL) {
        return -1;
    }

    if ((question = ldns_rr_list_clone(ldns_pkt_question(req->_pkt_req))) == NULL) {
        return -1;
    }

    opcode = ldns_pkt_get_opcode(req->_pkt_req);


    if (opcode == LDNS_PACKET_QUERY) {
        ldns_pkt_set_cd(packet, ldns_pkt_cd(req->_pkt_req));
        ldns_pkt_set_rd(packet, ldns_pkt_rd(req->_pkt_req));
    }

    ldns_pkt_set_id(packet, ldns_pkt_id(req->_pkt_req));
    ldns_pkt_set_qr(packet, true);
    ldns_pkt_set_opcode(packet, opcode);
    ldns_pkt_set_rcode(packet, LDNS_RCODE_REFUSED);

    ldns_rr_list_deep_free(packet->_question);
    ldns_pkt_set_question(packet, question);
    ldns_pkt_set_qdcount(packet, ldns_rr_list_rr_count(question));

    req->_pkt_res = packet;

    if (ldns_pkt2wire(&req->_wire_res, req->_pkt_res, &req->_wire_res_sz) != LDNS_STATUS_OK) {
        return -1;
    }

    return ddrop_dnsd_request_queue(req);
}

static int
request__process_(struct ddrop_dnsd_request * req)
{
    uint8_t * buffer = req->_wire_req;
    size_t    buflen = req->_wire_req_sz;

    if (req->_pkt_req != NULL) {
        ldns_pkt_free(req->_pkt_req);
        req->_pkt_req = NULL;
    }

    if (ldns_wire2pkt(&req->_pkt_req, buffer, buflen) != LDNS_STATUS_OK) {
        log_error("wire2pkt");
        return -1;
    }

    if (req->_listener->_callback) {
        if ((req->_listener->_callback)(req, req->_listener->_usrargs) == -1) {
            log_error("callback");
            return -1;
        }
    }

    return 0;
}

static int
listener__write_(struct ddrop_dnsd_listener * listener)
{
    struct ddrop_dnsd_request * req;
    struct ddrop_dnsd_request * tmp;

    TAILQ_FOREACH_SAFE(req, &listener->_pending, _pending_next, tmp) {
        ssize_t send_sz;

        send_sz = sendto(listener->_sock, req->_wire_res, req->_wire_res_sz, 0,
                         (struct sockaddr *)&req->_addr, req->_addrlen);

        if (send_sz == -1) {
            if (errno == EAGAIN) {
                /* queue up this function to be called again in
                 * the next event loop.
                 */
                event_active(listener->_event, EV_WRITE, 1);
                return 0;
            }

            log_error("err %s", strerror(errno));
        }

        TAILQ_REMOVE(&listener->_pending, req, _pending_next);

        request__free_(req);
    }

    return 0;
}

static int
listener__read_(struct ddrop_dnsd_listener * listener)
{
    if (listener == NULL) {
        log_error("listener == NULL");
        return -1;
    }

    char                    buf[LDNS_MAX_PACKETLEN];
    struct sockaddr_storage addr;
    ssize_t                 recv_len;
    ev_socklen_t            addrlen = sizeof(addr);

    while (1) {
        struct ddrop_dnsd_request * req;

        recv_len = recvfrom(listener->_sock, buf,
                            LDNS_MAX_PACKETLEN, 0,
                            (struct sockaddr *)&addr,
                            &addrlen);

        if (recv_len == -1) {
            if (errno != EAGAIN) {
                log_error("recvfrom %s", strerror(errno));
            }

            return 0;
        }

        req            = calloc(1, sizeof(*req));
        req->_listener = listener;
        req->_sock     = listener->_sock;
        req->_addrlen  = sizeof(struct sockaddr_storage);

        memcpy(&req->_addr, &addr, addrlen);
        memcpy(&req->_wire_req, buf, recv_len);

        req->_wire_req_sz = (size_t)recv_len;

        if (request__process_(req) == -1) {
            request__free_(req);
            return -1;
        }
    }
} /* listener__read_ */

static void
listener__callback_(evutil_socket_t sock, short events, void * arg)
{
    struct ddrop_dnsd_listener * listener;

    assert(arg != NULL);

    listener = (struct ddrop_dnsd_listener *)arg;

    if (events & EV_READ) {
        listener__read_(listener);
    }

    if (events & EV_WRITE) {
        listener__write_(listener);
    }
}

static int
listener__new_(struct ddrop_dnsd_listener ** out,
               struct event_base        * evbase,
               char                     * host,
               uint16_t                   port,
               const char               * dev)
{
    struct ddrop_dnsd_listener * listener;
    char                    * errstr = NULL;

    assert(out != NULL);

    *out = NULL;

    if (evbase == NULL) {
        log_error("evbase not set");
        return -1;
    }

    if ((listener = calloc(1, sizeof(*listener))) == NULL) {
        return -1;
    }

    listener->_callback = request__default_callback_;
    listener->_sock     = -1;
    listener->_evbase   = evbase;

    TAILQ_INIT(&listener->_pending);

    do {
        int flags = EV_READ | EV_PERSIST;

        if ((listener->_sock = ddrop_socket_bind_dev(host, port, SOCK_DGRAM, dev)) == -1) {
            errstr = "socket_bind";
            break;
        }

        if ((listener->_event = event_new(evbase,
                                          listener->_sock, flags,
                                          listener__callback_, listener)) == NULL) {
            errstr = "event_new";
            break;
        }
    } while (0);

    if (errstr != NULL) {
        log_error("%s", errstr);
        listener__free_(listener);

        return -1;
    }

    *out = listener;
    return 0;
}     /* listener__new_ */

struct ddrop_dnsd_listener *
ddrop_dnsd_listener_new(struct event_base * evbase,
                     char              * host,
                     uint16_t            port,
                     const char        * dev)
{
    struct ddrop_dnsd_listener * listener;

    if (listener__new_(&listener, evbase, host, port, dev) == -1) {
        return NULL;
    }

    return listener;
}

int
ddrop_dnsd_listener_set_callback(struct ddrop_dnsd_listener * listener,
                              ddrop_dnsd_requestcb         callback,
                              void                    * args)
{
    listener->_callback = callback;
    listener->_usrargs  = args;

    return 0;
}

int
ddrop_dnsd_listener_start(struct ddrop_dnsd_listener * listener)
{
    return event_add(listener->_event, NULL);
}

int
ddrop_dnsd_request_queue(struct ddrop_dnsd_request * req)
{
    struct ddrop_dnsd_listener * listener;

    if (req == NULL) {
        return -1;
    }

    if ((listener = req->_listener) == NULL) {
        return -1;
    }

    TAILQ_INSERT_TAIL(&listener->_pending, req, _pending_next);

    return listener__write_(listener);
}

int
ddrop_dnsd_response_queue(struct ddrop_dnsd_request * req,
                       ldns_pkt               * response_pkt)
{
    if (req == NULL || response_pkt == NULL) {
        return -1;
    }

    req->_pkt_res = response_pkt;

    if (ldns_pkt2wire(&req->_wire_res,
                      req->_pkt_res,
                      &req->_wire_res_sz) != LDNS_STATUS_OK) {
        return -1;
    }

    return ddrop_dnsd_request_queue(req);
}
