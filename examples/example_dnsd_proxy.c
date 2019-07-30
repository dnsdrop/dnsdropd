#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <getopt.h>

#include <event2/event.h>
#include <event2/thread.h>
#include <evhtp/thread.h>
#include <ldns/ldns.h>

#include "ddrop/common.h"
#include "ddrop/core/log.h"
#include "ddrop/dns/dnsd.h"
#include "ddrop/dns/json.h"
#include "ddrop/dns/resolver.h"

static int
resolver_callback_(struct ddrop_resolver_request * req, void * arg) {
    struct ddrop_dnsd_request * dnsd_req;
    ldns_pkt               * answer_pkt;

    dnsd_req   = (struct ddrop_dnsd_request *)arg;
    ddrop_assert(dnsd_req != NULL);

    answer_pkt = ddrop_resolver_request_get_a_packet(req);
    ddrop_assert(answer_pkt != NULL);

    ddrop_dnsd_response_queue(dnsd_req, ldns_pkt_clone(answer_pkt));

    ddrop_resolver_request_free(req);
    return 0;
}

static int
process_request_(struct ddrop_dnsd_request * req, void * arg) {
    struct ddrop_resolver_ctx * resolver;
    ldns_pkt               * question;
    ldns_pkt               * answer;

    resolver = (struct ddrop_resolver_ctx *)arg;
    ddrop_assert(resolver != NULL);

    question = ddrop_dnsd_request_get_query(req);
    ddrop_assert(question != NULL);

    log_info("{{{{ RAW QUERY TO JSON }}}}");

    {
        lz_json * json_query;
        char      outbuf[4098];
        ssize_t   outlen;

        if ((json_query = ddrop_dns_to_json(question)) == NULL) {
            log_error("dns_to_json");
            exit(EXIT_FAILURE);
        }

        outlen = lz_json_to_buffer(json_query, outbuf, sizeof(outbuf));

        fprintf(stdout, "%.*s\n", (int)outlen, outbuf);

        lz_json_free(json_query);
    }


    return ddrop_resolver_send_pkt(resolver,
                                ldns_pkt_clone(question),
                                resolver_callback_,
                                req);
}

int
main(int argc, char ** argv) {
    struct event_base       * evbase;
    struct ddrop_dnsd_listener * dnsd;
    struct ddrop_resolver_ctx  * resolver;
    int                       res;

    res      = evthread_use_pthreads();
    ddrop_assert(res == 0);

    evbase   = event_base_new();
    ddrop_assert(evbase != NULL);

    res      = evthread_make_base_notifiable(evbase);
    ddrop_assert(res == 0);

    dnsd     = ddrop_dnsd_listener_new(evbase, "127.0.0.6", 53, "lo");
    ddrop_assert(dnsd != NULL);


    resolver = ddrop_resolver_ctx_new(evbase, argv[1]);
    ddrop_assert(resolver != NULL);

    res      = ddrop_dnsd_listener_set_callback(dnsd,
                                             process_request_,
                                             resolver);

    ddrop_assert(res == 0);

    res = ddrop_dnsd_listener_start(dnsd);
    ddrop_assert(res == 0);

    res = ddrop_resolver_ctx_start(resolver);
    ddrop_assert(res == 0);

    event_base_loop(evbase, 0);

    return 0;
}
