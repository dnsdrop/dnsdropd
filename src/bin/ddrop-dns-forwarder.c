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

static char *
mk_strhash_(ldns_rdf * rdf, size_t blen, char buf[blen])
{
    snprintf(buf, blen, "%d:%s", ldns_rdf_get_type(rdf), ldns_rdf2str(rdf));

    return buf;
}

static int
resolver_callback_(struct ddrop_resolver_request * req, void * arg)
{
    struct ddrop_dnsd_request * dnsd_req;
    ldns_pkt               * answer_pkt;

    dnsd_req   = (struct ddrop_dnsd_request *)arg;
    ddrop_assert(dnsd_req != NULL);

    answer_pkt = ddrop_resolver_request_get_a_packet(req);
    ddrop_assert(answer_pkt != NULL);

    {
        lz_json * packet_j;

        if ((packet_j = ddrop_dns_to_json(answer_pkt))) {
            lz_json_fprintf(stderr, packet_j);

            ddrop_safe_free(packet_j, lz_json_free);
        }
    }

    ddrop_dnsd_response_queue(dnsd_req, ldns_pkt_clone(answer_pkt));

    ddrop_resolver_request_free(req);
    return 0;
}

static char     * filter = "";
static lz_kvmap * rrfilter = NULL;

static int
process_request_(struct ddrop_dnsd_request * req, void * arg)
{
    struct ddrop_resolver_ctx * resolver;
    ldns_pkt               * question;
    ldns_pkt               * answer;

    resolver = (struct ddrop_resolver_ctx *)arg;
    ddrop_assert(resolver != NULL);

    question = ddrop_dnsd_request_get_query(req);
    ddrop_assert(question != NULL);

#if 0
    if (rrfilter != NULL) {
        char       buf[1024];
        ldns_rdf * q_rdf = ldns_rr_owner(ldns_rr_list_rr(ldns_pkt_question(question), 0));
        lz_json  * j     = ddrop_dns_rdf_to_json(q_rdf);

        lz_json_fprintf(stdout, j);

        char     * k = mk_strhash_(q_rdf, sizeof(buf), buf);
        void     * e = lz_kvmap_find(rrfilter, k);

        if (e != NULL) {
            ldns_pkt * rec_pkt = (ldns_pkt *)e;
            ldns_pkt * a_pkt = ldns_pkt_new();
        }
    }
#endif

    return ddrop_resolver_send_pkt(resolver,
                                ldns_pkt_clone(question),
                                resolver_callback_,
                                req);
}

int
main(int argc, char ** argv)
{
    struct event_base       * evbase;
    struct ddrop_dnsd_listener * dnsd;
    struct ddrop_resolver_ctx  * resolver;
    int                       res;

    rrfilter = lz_kvmap_new(10);
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
