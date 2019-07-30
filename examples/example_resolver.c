/*
 * example usage of the libddrop_dnsResolver API.
 *
 * 1. create a resolver context
 * 2. enable notifications on the event_base
 * 3. make a dns request for IN A criticalstack.com.
 * 4. read the response in `resolver_callback_`
 */
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

static int
resolver_callback_(struct ddrop_resolver_request * req, void * args)
{
    ldns_pkt * answer = ddrop_resolver_request_get_a_packet(req);

    log_info("here");

    if (answer == NULL) {
        log_error("get_answer %d",
                  ddrop_resolver_request_get_status(req));
    }

    ldns_pkt_print(stderr, answer);

    ddrop_resolver_request_free(req);

    event_base_loopbreak((struct event_base *)args);

    return 0;
}

int
main(int argc, char ** argv)
{
    struct event_base         * evbase;
    struct ddrop_resolver_ctx * resolver;

    evthread_use_pthreads();

    evbase   = event_base_new();
    resolver = ddrop_resolver_ctx_new(evbase, NULL);

    evthread_make_base_notifiable(evbase);

    ddrop_resolver_ctx_start(resolver);

    /* works much like system gethostbyname, but async-like */
    if (ddrop_resolver_gethostbyname(resolver, "criticalstack.com",
                                  AF_INET, resolver_callback_, evbase) == -1) {
        log_error("gethostbyname");
        exit(EXIT_FAILURE);
    }

    event_base_loop(evbase, EVLOOP_NO_EXIT_ON_EMPTY);

    return 0;
}
