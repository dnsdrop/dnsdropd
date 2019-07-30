#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <getopt.h>

#include <ldns/ldns.h>
#include <event2/event.h>

#include "ddrop/common.h"
#include "ddrop/core/log.h"
#include "ddrop/dns/json.h"
#include "ddrop/dns/shim.h"

struct shim_ {
    struct ddrop_dns_shim * shim;
    struct event_base     * evbase;
    struct event          * event;
    ldns_resolver         * resolver;
};

struct req_ {
    struct shim_ * shim;
    struct event * event;

    ldns_pkt              * request;
    ldns_pkt              * response;
    evutil_socket_t         client_sock;
    evutil_socket_t         server_sock;
    struct sockaddr_storage ss;
};

static void
dump_json_(lz_json * j)
{
    char   outbuf[4096];
    size_t outlen;

    outlen = lz_json_to_buffer(j, outbuf, sizeof(outbuf));

    fprintf(stdout, "%.*s\n", (int)outlen, outbuf);
    fflush(stdout);
}

static void
wrote__resp_(int sock, short which, void * arg)
{
    struct req_ * r = arg;

/*    event_base_loopbreak(r->shim->evbase); */
}

static void
read__resp_(int sock, short which, void * arg)
{
    struct req_           * r = arg;
    struct sockaddr_storage sk_s;
    socklen_t               sk_len;
    ssize_t                 recv_len;
    char                    buf[LDNS_MAX_PACKETLEN];

    sk_len   = sizeof(sk_s);

    recv_len = recvfrom(sock, buf, sizeof(buf), 0,
                        (struct sockaddr *)&sk_s, &sk_len);


    ldns_wire2pkt(&r->response, buf, recv_len);

    ldns_pkt_print(stderr, r->response);

    {
        uint8_t * a_buf;
        size_t    a_size;

        ldns_pkt2wire(&a_buf, r->response, &a_size);
        log_debug("%d", a_size);

        sendto(r->client_sock, (void *)a_buf, a_size, 0,
               (struct sockaddr *)&r->ss, sizeof(struct sockaddr_storage));
        event_del(r->event);
        event_assign(r->event, r->shim->evbase, sock, EV_WRITE, wrote__resp_, r);
        event_add(r->event, NULL);
    }


    /*event_base_loopbreak(r->shim->evbase); */
}

static int
shim__callback_(struct ddrop_dns_shim * shim_, lz_json * dns_json, struct sockaddr_storage * ss, void * args)
{
    struct event_base * evbase;
    struct shim_      * shim;

    assert(args != NULL);
    assert(shim_ != NULL);
    assert(dns_json != NULL);

    shim   = (struct shim_ *)args;
    evbase = shim->evbase;

    dump_json_(dns_json);
    {
        struct req_             * r        = calloc(1, sizeof(struct req_));
        ldns_rdf               ** ns_array = ldns_resolver_nameservers(shim->resolver);
        struct sockaddr_storage * src      = NULL;
        struct sockaddr_storage * ns       = NULL;
        size_t                    src_len  = 0;
        size_t                    ns_len   = 0;
        ldns_buffer             * lbuf;
        struct timeval            tv       = { 1, 0 };

        lbuf = ldns_buffer_new(512);

        if (ldns_resolver_random(shim->resolver)) {
            ldns_resolver_nameservers_randomize(shim->resolver);
        }

        ns = ldns_rdf2native_sockaddr_storage(
            ns_array[0], ldns_resolver_port(shim->resolver), &ns_len);


        r->shim    = shim;
        r->request = ddrop_json_to_dns(dns_json);

        ldns_pkt2buffer_wire(lbuf, r->request);

        memcpy(&r->ss, ss, sizeof(*ss));
        r->client_sock = ddrop_dns_shim_get_sock(shim_);
        r->server_sock = ldns_udp_bgsend(lbuf, ns, ns_len, tv);
        r->event       = event_new(evbase, r->server_sock, EV_READ, read__resp_, r);
        r->response    = NULL;

        event_add(r->event, &tv);
    }

    lz_json_free(dns_json);

    return 0;
} /* shim__callback_ */

static int
shim__new_(struct shim_ ** out, struct event_base * evbase)
{
    struct shim_ * shim;
    int            error = 1;

    if ((shim = calloc(1, sizeof(*shim))) == NULL) {
        return -1;
    }

    shim->evbase = evbase;

    do {
        struct ddrop_dns_shim_cfg config = {
            .bind_addr = "127.0.0.1",
            .bind_port = 5555,
            .sock_type = SOCK_DGRAM
        };

        if ((shim->shim = ddrop_dns_shim_new(evbase, &config)) == NULL) {
            log_error("shim_new");
            break;
        }

        if (ddrop_dns_shim_set_callback(shim->shim, shim__callback_, shim) == -1) {
            log_error("set_callback");
            break;
        }

        if (ldns_resolver_new_frm_file(&shim->resolver, NULL) != LDNS_STATUS_OK) {
            log_error("new_from_file");
            break;
        }

        error = 0;
    } while (0);

    *out = shim;
}

int
main(int argc, char ** argv)
{
    struct event_base * evbase;
    struct shim_      * shim;

    if ((evbase = event_base_new()) == NULL) {
        log_error("event_base_new");
        exit(EXIT_FAILURE);
    }

    if (shim__new_(&shim, evbase) == -1) {
        log_error("shim_new_");
        exit(EXIT_FAILURE);
    }

    if (ddrop_dns_shim_start(shim->shim) == -1) {
        log_error("shim_start");
        exit(EXIT_FAILURE);
    }

    event_base_loop(evbase, 0);
    event_base_free(evbase);
    ddrop_dns_shim_free(shim->shim);

    return 0;
} /* main */
