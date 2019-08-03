#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

#include <event2/event.h>
#include <event2/thread.h>

#include <evhtp/evhtp.h>
#include <evhtp/thread.h>

#include <ldns/ldns.h>

#include "ddrop/common.h"
#include "ddrop/core/log.h"
#include "ddrop/dns/resolver.h"

struct ddrop_resolver_ctx {
    struct event_base * _evbase;
    struct evthr_pool * _thrpool;
    ldns_resolver     * _resolver;
};

struct ddrop_resolver_request {
    struct ddrop_resolver_ctx * _ctx;
    struct event              * _event;
    ldns_pkt                  * _q_packet;
    ldns_pkt                  * _a_packet;
    ldns_status                 _status;
    ddrop_resolver_cb           _callback;
    void                      * _args;
};

#define RES_REQ_FNGEN(TYPE, NAME)                                                \
    TYPE ddrop_resolver_request_get ## NAME(struct ddrop_resolver_request * r) { \
        assert(r);                                                               \
        return r->NAME;                                                          \
    }

RES_REQ_FNGEN(ldns_pkt *, _q_packet);
RES_REQ_FNGEN(ldns_pkt *, _a_packet);
RES_REQ_FNGEN(ldns_status, _status);

#define CS__RES_DEFAULT_NTHREADS sysconf(_SC_NPROCESSORS_ONLN)

static void
resolver__thread_exit_(struct evthr * thread, void * args)
{
    ldns_resolver * resolver;

    /* our thread-specific copy of the ldns_resolver data is set
     * in our thread-specific auxillary argument. We need to free
     * this resource prior to the thread shutting down. This is that.
     */

    if ((resolver = evthr_get_aux(thread)) == NULL) {
        log_error("get_aux");
        return;
    }

    return ldns_resolver_deep_free(resolver);
}

static void
resolver__thread_init_(struct evthr * thread, void * args)
{
    struct ddrop_resolver_ctx * ctx;
    ldns_resolver             * resolver_copy;

    /* since the ldns_resolver held in ddrop_resolver_ctx is not
     * thread-safe, we must make a local copy to each of our
     * threads in the pool.
     *
     * a struct evthr has an `auxillary` argument which can be
     * set or fetched. We make a duplicate version of the
     * resolver, and set the evthr's auxillary argument to it.
     *
     * When this thread is stopped, the function resolver__thread_exit_
     * is called, and this resource is cleaned up.
     */

    if ((ctx = (struct ddrop_resolver_ctx *)args) == NULL) {
        log_error("no context provided");
        abort();
    }

    /* make a brand new copy locally */
    if ((resolver_copy = ldns_resolver_clone(ctx->_resolver)) == NULL) {
        log_error("resolver clone");
        abort();
    }

    ldns_resolver_set_random(resolver_copy, false);
    /* set it as our auxillary argument */
    return evthr_set_aux(thread, resolver_copy);
}

struct ddrop_resolver_ctx *
ddrop_resolver_ctx_new(struct event_base * evbase, const char * resolv_conf)
{
    struct ddrop_resolver_ctx * ctx;

    if (evbase == NULL) {
        return NULL;
    }

    if ((ctx = calloc(1, sizeof(*ctx))) == NULL) {
        return NULL;
    }

    do {
        /* TODO: add configuration variable to set another resolv.conf */
        if (ldns_resolver_new_frm_file(
                &ctx->_resolver, resolv_conf) != LDNS_STATUS_OK) {
            break;
        }

        /* start up our worker threads which will do our actual resolution */
        if ((ctx->_thrpool = evthr_pool_wexit_new(
                 CS__RES_DEFAULT_NTHREADS,        /* TODO: make this configurable */
                 resolver__thread_init_,
                 resolver__thread_exit_, ctx)) == NULL) {
            break;
        }

        ctx->_evbase = evbase;

        return ctx;
    } while (0);

    /* an error occurred with the above allocations */
    ddrop_resolver_ctx_free(ctx);

    return NULL;
}

void
ddrop_resolver_ctx_free(struct ddrop_resolver_ctx * ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->_thrpool != NULL) {
        evthr_pool_free(ctx->_thrpool);
    }

    if (ctx->_resolver != NULL) {
        ldns_resolver_deep_free(ctx->_resolver);
    }

    free(ctx);
}

int
ddrop_resolver_ctx_start(struct ddrop_resolver_ctx * ctx)
{
    if (ctx == NULL) {
        return -1;
    }

    /* TODO: startup other event handlers - like collectors */

    return evthr_pool_start(ctx->_thrpool);
}

static void
request__finalize_(int sock, short events, void * arg)
{
    if (events & EV_READ) {
        /* this was called via event_active(..., EV_READ),
         * meaning the calling thread has marked this request
         * as done. Since we're now back outside of the
         * thread-pool, we can safely call the users request
         * callback.
         */
        struct ddrop_resolver_request * req;

        req = (struct ddrop_resolver_request *)arg;
        assert(req != NULL);

        (req->_callback)(req, req->_args);
    }

    /* TODO: other event type actions here (EV_TIMEOUT?) */
}

struct ddrop_resolver_request *
ddrop_resolver_request_new(struct ddrop_resolver_ctx * ctx)
{
    struct ddrop_resolver_request * req;
    short                           flags = EV_TIMEOUT | EV_READ;

    if (ctx == NULL) {
        return NULL;
    }

    if ((req = calloc(1, sizeof(*req))) == NULL) {
        return NULL;
    }

    req->_ctx   = ctx;

    /* this is an internal event which sits off of the user-supplied
     * event_base. The function `request__finalize_` is only called
     * once one of the threads in the threadpool have marked this
     * request as "processed".
     *
     * Since each thread in our thread-pool uses its own event_base
     * for operations, the event_base in this context must be set to
     * 'notifiable' (via libevent). This allows the transfer of events
     * back from the pool, and into this thread.
     *
     * We never actually add this event to the loop, the specific thread
     * that processed this request will manually call event_activate on
     * this event, thus transferring the control over to finalize_.
     */
    req->_event = event_new(ctx->_evbase, -1, flags,
                            request__finalize_, req);

    if (req->_event == NULL) {
        ddrop_resolver_request_free(req);

        return NULL;
    }

    return req;
}

void
ddrop_resolver_request_free(struct ddrop_resolver_request * req)
{
    if (req == NULL) {
        return;
    }

    if (req->_event) {
        event_free(req->_event);
    }

    ldns_pkt_free(req->_q_packet);
    ldns_pkt_free(req->_a_packet);

    free(req);
}

static void
resolve__in_thread_(struct evthr * thread, void * arg, void * un__)
{
    struct ddrop_resolver_request * request;
    ldns_resolver                 * resolver;
    ldns_status                     status;

    request = (struct ddrop_resolver_request *)arg;
    assert(request != NULL);

    /* as seen in `resolver__thread_init_` function, each thread
     * in our pool is allocated its own copy of the resolver
     * context and placed into the auxillary arguments.
     */
    resolver = (ldns_resolver *)evthr_get_aux(thread);
    assert(resolver != NULL);

    /* use ldns's non-blocking send_pkt to make the request from
     * this thread.
     */
    request->_status = ldns_send(
        &request->_a_packet,
        resolver, request->_q_packet);

    /* now that we have an answer (may be an error, who knows),
     * we call event_active on the requests event. This will then
     * transfer the context over to the thread that owns the event_base
     * on that event.
     */
    return event_active(request->_event, EV_READ, 1);
}

int
ddrop_resolver_send_pkt(struct ddrop_resolver_ctx * ctx,
                        ldns_pkt * packet,
                        ddrop_resolver_cb cb, void * args)
{
    struct ddrop_resolver_request * request;

    if (ctx == NULL) {
        return -1;
    }

    if (packet == NULL) {
        return -1;
    }

    if (cb == NULL) {
        return -1;
    }

    if ((request = ddrop_resolver_request_new(ctx)) == NULL) {
        return -1;
    }

    request->_q_packet = packet;
    request->_callback = cb;
    request->_args     = args;

    /* queue this request up into our thread-pool of resolver
     * workers.
     */
    evthr_res res;

    do {
        res = evthr_pool_defer(ctx->_thrpool,
                               resolve__in_thread_,
                               request);

        if (res == EVTHR_RES_RETRY) {
            log_debug("retry");
            continue;
        }

        if (res != EVTHR_RES_OK) {
            log_error("res = %d", res);
            ddrop_resolver_request_free(request);
            return -1;
        }
    } while (0);

    return 0;
} /* ddrop_resolver_send_pkt */

int
ddrop_resolver_gethostbyname(struct ddrop_resolver_ctx * ctx,
                             const char                * name,
                             int                         type,
                             ddrop_resolver_cb           cb,
                             void                      * args)
{
    ldns_pkt   * packet;
    ldns_rr_type rr_type;

    if (ctx == NULL) {
        return -1;
    }

    if (name == NULL) {
        return -1;
    }

    switch (type) {
        case AF_INET:
            rr_type = LDNS_RR_TYPE_A;
            break;
        case AF_INET6:
            rr_type = LDNS_RR_TYPE_AAAA;
            break;
        default:
            return -1;
    }

    if (ldns_pkt_query_new_frm_str(
            &packet,
            name,
            rr_type,
            LDNS_RR_CLASS_IN,
            LDNS_RD) != LDNS_STATUS_OK) {
        return -1;
    }


    return ddrop_resolver_send_pkt(ctx, packet, cb, args);
} /* ddrop_resolver_gethostbyname */
